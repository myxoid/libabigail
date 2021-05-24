// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2020-2021 Google, Inc.
//
// Author: Maria Teguiani
// Author: Giuliano Procida

#include <getopt.h>
#include <string.h>

#include <iomanip>
#include <iostream>

#include "abg-btf.h"

const int kAbiChange = 4;

int
main(int argc, char* argv[])
{
  bool use_elf_symbols = true;
  static option opts[]{
      {"symbols", required_argument, nullptr, 's'},
      {nullptr, 0, nullptr, 0},
  };
  auto usage = [&]() {
    std::cerr << "usage: " << argv[0] << " [-s|--symbols type] file1 file2\n"
	      << "  where type is elf (the default) or btf\n";
    return 1;
  };
  auto bad_arg = [&](int ix) {
    std::cerr << argv[0] << ": option '--" << opts[ix].name
	      << "' unrecognized argument '" << optarg << "'\n";
    return usage();
  };
  while (true)
    {
      int ix;
      int c = getopt_long(argc, argv, "s:", opts, &ix);
      if (c == -1)
	break;
      switch (c)
	{
	case 's':
	  if (!strcmp(optarg, "btf"))
	    use_elf_symbols = false;
	  else if (!strcmp(optarg, "elf"))
	    use_elf_symbols = true;
	  else
	    return bad_arg(ix);
	  break;
	default:
	  return usage();
	}
    }
  if (optind + 2 != argc)
    return usage();

  const auto structs1 = abigail::btf::ReadFile(argv[optind++]);
  const auto structs2 = abigail::btf::ReadFile(argv[optind++]);
  const auto& map1 = structs1.GetSymbols(use_elf_symbols);
  const auto& map2 = structs2.GetSymbols(use_elf_symbols);
  abigail::btf::Outcomes outcomes;
  auto result = abigail::btf::Type::CompareSymbols(map1, map2, outcomes);
  abigail::btf::NameCache names;
  abigail::btf::Seen seen;
  abigail::btf::Print(result.details_, outcomes, seen, names, std::cout);

  return result.equals_ ? 0 : kAbiChange;
}
