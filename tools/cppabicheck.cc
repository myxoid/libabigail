// -*- Mode: C++ -*-
//
// Copyright (C) 2017-2019 Red Hat, Inc.
//
// This file is part of the GNU Application Binary Interface Generic
// Analysis and Instrumentation Library (libabigail).  This library is
// free software; you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3, or (at your option) any
// later version.

// This library is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Lesser Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this program; see the file COPYING-LGPLV3.  If
// not, see <http://www.gnu.org/licenses/>.
//
// Author: Dodji Seketeli

/// @file
///
/// Source code of the cppabicheck tool
///
/// The tool is used as follows:
///
/// cppabicheck <test-binary>
///
/// If the binary contains references to the old C++ ABI, then it
/// emits the message:
///
///       binary 'test-binary' uses the old C++ ABI
///
/// And it exits with an error code.  So this is a possible use of the
/// program on a test binary that contains references to the old C++ ABI:
///
///     $ ./build/tools/cppabicheck prtests/test || echo "Oooops"
///     binary 'prtests/test' uses the old C++ ABI
///     Oooops
///     $
///
///

#include <cstring>
#include <string>
#include <iostream>

#include "abg-config.h"
#include "abg-tools-utils.h"
#include "abg-dwarf-reader.h"
#include "abg-corpus.h"

using std::cout;
using std::cerr;
using std::string;
using std::ostream;
using std::vector;

using abigail::tools_utils::emit_prefix;
using abigail::tools_utils::check_file;
using abigail::tools_utils::file_type;
using abigail::tools_utils::guess_file_type;
using abigail::ir::environment_sptr;
using abigail::ir::environment;
using abigail::ir::elf_symbols;
using abigail::ir::demangle_cplus_mangled_name;
using abigail::corpus;
using abigail::corpus_sptr;
using abigail::dwarf_reader::read_context;
using abigail::dwarf_reader::read_context_sptr;
using abigail::dwarf_reader::read_corpus_from_elf;
using abigail::dwarf_reader::create_read_context;

struct options
{
  bool display_usage;
  bool display_version;
  string file_path;
  string wrong_option;

  options()
    : display_usage(),
      display_version()
  {}
}; // end struct options

/// @param argc the nomber of arguments to parse.
///
/// @param argv the arguments to parse.
///
/// @param opts the options to set as a result of parsing arguments
/// from @p argv.
///
/// @return true if the command line was parsed successfully.
static bool
parse_command_line(int argc, char* argv[], options& opts)
{
  if (argc < 2)
    return false;

  for (int i = 1; i < argc; ++i)
    {
      if (argv[i][0] != '-')
	{
	  if (opts.file_path.empty())
	    opts.file_path = argv[i];
	  else
	    return false;
	}
      else if (!strcmp(argv[i], "--version")
	       || !strcmp(argv[i], "-v"))
	{
	  opts.display_version = true;
	  return true;
	}
      else if (!strcmp(argv[i], "--help")
	       || !strcmp(argv[i], "-h"))
	{
	  opts.display_usage = true;
	  return true;
	}
      else
	{
	  if (strlen(argv[i]) >= 2 && argv[i][0] == '-' && argv[i][1] == '-')
	    opts.wrong_option = argv[i];
	  return false;
	}
    }

  return true;
}

/// Display the usage of the programme.
///
/// @param prog_name the name of the programme that is emitting the display.
///
/// @param out the output stream to emit the usage to.
static void
display_usage(const string& prog_name, ostream& out)
{
  emit_prefix(prog_name, out)
    << "usage: " << prog_name << " [options] [<file-path>\n"
    << " where options can be:\n"
    << " --help|-h     display this message\n"
    << " --version|-v  display program version information and exit\n";
}

/// Detect if a symbol name contains reference to the old or a the new
/// C++ ABI.
///
/// A symbol is considered to have a reference to the old C++ ABI if
/// its demangled name contains the strings std::{basic_string,
/// string, list}.
///
/// A symbol is considered to have a reference to the new C++ ABI if
/// its demangled name contains the strings
/// std::__cxx11::{basic_string, list}.
///
/// @param symbol_name the symbol name to consider.
///
/// @param found_old_abi output parameter.  Is set to true if @p
/// symbol_name contains references to the old C++ ABI.
///
/// @param found_new_abi output parameter.  Is set to true if @p
/// symbol_name contains references to the new (>= c++11) C++ ABI.
///
/// @return true if the detection found references to either the new
/// or the old C++ ABI, false otherwise.
static bool
detect_abi_version_in_symbol_name(const string&	symbol_name,
				  bool&		found_old_abi,
				  bool&		found_new_abi)
{
    string old_abi_pattern1 = "std::basic_string",
      old_abi_pattern2 = "std::string",
      old_abi_pattern3 = "std::list";
    string new_abi_pattern1 = "std::__cxx11::basic_string",
      new_abi_pattern2 = "std::__cxx11::string",
      new_abi_pattern3 = "std::__cxx11::list";

    bool result = false;
    if (symbol_name.find(old_abi_pattern1) != string::npos
	|| symbol_name.find(old_abi_pattern2) != string::npos
	||symbol_name.find(old_abi_pattern3) != string::npos)
      {
	found_old_abi = true;
	result = true;
      }

    if (symbol_name.find(new_abi_pattern1) != string::npos
	|| symbol_name.find(new_abi_pattern2) != string::npos
	|| symbol_name.find(new_abi_pattern3) != string::npos)
      {
	found_new_abi = true;
	result = true;
      }

    return result;
}

/// Check that a given binary does *NOT* contain references to the old
/// C++ ABI.
///
/// This function loads the binary (without the debug info), looks at
/// the defined and undefined public symbols and checks that those
/// contain *NO* references to the old C++ ABI.
static bool
check_cpp_abi_in_binary(const string& prog_name,
			const string& binary_path)
{
  file_type ftype = guess_file_type(binary_path);
  if (ftype != abigail::tools_utils::FILE_TYPE_ELF)
    {
      emit_prefix(prog_name, cerr)
	<< "file '" << binary_path << "' "
	<< " is not an ELF file\n";
      return false;
    }

    environment_sptr env(new environment);
    vector<char**> debug_info_root_paths;
    read_context_sptr ctxt = create_read_context(binary_path,
						 debug_info_root_paths,
						 env.get(),
						 /*load_all_types=*/false,
						 /*linux_kernel_mode=*/false,
						 /*load_debug_info=*/false);

    abigail::dwarf_reader::status read_status =
      abigail::dwarf_reader::STATUS_UNKNOWN;
    corpus_sptr abi = read_corpus_from_elf(*ctxt, read_status);
    if (!(read_status & abigail::dwarf_reader::STATUS_OK))
      {
	emit_prefix(prog_name, cerr)
	  << "could not analyze the file at " << binary_path << "\n";
	return true;
      }
    // Walk the symbol maps, looking for std::{basic_string, list} and
    // for std::__cxx11::{basic_string, list}.
    bool found_old_abi = false;
    bool found_new_abi = false;
    string symbol_name;

    for (abigail::ir::elf_symbols::const_iterator sym =
	   abi->get_sorted_undefined_fun_symbols().begin();
	 sym != abi->get_sorted_undefined_fun_symbols().end();
	 ++sym)
      {

	symbol_name = demangle_cplus_mangled_name((*sym)->get_name());
	if (detect_abi_version_in_symbol_name(symbol_name,
					      found_old_abi,
					      found_new_abi))
	  break;
      }

    for (elf_symbols::const_iterator sym =
	   abi->get_sorted_undefined_var_symbols().begin();
	 sym != abi->get_sorted_undefined_var_symbols().end();
	 ++sym)
      {
	symbol_name = demangle_cplus_mangled_name((*sym)->get_name());
	if (detect_abi_version_in_symbol_name(symbol_name,
					      found_old_abi,
					      found_new_abi))
	  break;
      }

    for (elf_symbols::const_iterator sym =
	   abi->get_sorted_fun_symbols().begin();
	 sym != abi->get_sorted_fun_symbols().end();
	 ++sym)
      {
	symbol_name = demangle_cplus_mangled_name((*sym)->get_name());
	if (detect_abi_version_in_symbol_name(symbol_name,
					      found_old_abi,
					      found_new_abi))
	  break;
      }

    for (elf_symbols::const_iterator sym =
	   abi->get_sorted_var_symbols().begin();
	 sym != abi->get_sorted_var_symbols().end();
	 ++sym)
      {
	symbol_name = demangle_cplus_mangled_name((*sym)->get_name());
	if (detect_abi_version_in_symbol_name(symbol_name,
					      found_old_abi,
					      found_new_abi))
	  break;
      }

    if (found_old_abi)
      {
	cout << "binary '" << binary_path << "' uses the old C++ ABI\n";
	return false;
      }

  return true;
}

int
main(int argc, char* argv[])
{

  options opts;
  if (!parse_command_line(argc, argv, opts))
    {
      if (!opts.wrong_option.empty())
	emit_prefix(argv[0], cerr)
	  << "unrecognized option: "
	  << opts.wrong_option << "\n"
	  << "try the --help option for more information\n";
      else
	display_usage(argv[0], cout);
      return true;
    }

  if (opts.display_usage)
    {
      display_usage(argv[0], cout);
      return 0;
    }

  if (opts.display_version)
    {
      emit_prefix(argv[0], cout)
	<< abigail::tools_utils::get_library_version_string()
	<< "\n";
      return 0;
    }

  if (opts.file_path.empty())
    {
      display_usage(argv[0], cout);
      return true;
    }

  if (!check_cpp_abi_in_binary(argv[0], opts.file_path))
    return true;

  return 0;
}
