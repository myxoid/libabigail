// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2016-2020 Red Hat, Inc.
//
// Author: Dodji Seketeli

/// @file
///
/// This contains the implementation of the suppression engine of
/// libabigail.

#include <algorithm>

#include "abg-internal.h"
#include <memory>
#include <limits>

// <headers defining libabigail's API go under here>
ABG_BEGIN_EXPORT_DECLARATIONS

#include "abg-ini.h"
#include "abg-comp-filter.h"
#include "abg-suppression.h"
#include "abg-tools-utils.h"

ABG_END_EXPORT_DECLARATIONS
// </headers defining libabigail's API>

#include "abg-suppression-priv.h"

namespace abigail
{

namespace suppr
{

using std::dynamic_pointer_cast;
using regex::regex_t_sptr;

// <parsing stuff>

// Parsing utilities
//
// Suppression specifications parsing can broken down into the
// following pieces.
//
// .ini format parsing - responsibility of ini::config
//
// parsing of strings - done by string_to_foo functions,
// analogously to operator>>; concerns: value format
//
// parsing of (untyped) properties to meaningful types - done in a
// type-driven fashion by (overloaded) read functions; concerns:
// property structure and value format
//
// field look-up within a section - currently done procedurally by the
// read_foo_suppression functions but could be table-driven; concerns:
// field presence / absence, optionality, multiplicity etc.

// string parsing

/// Parse a boolean value.
///
/// @param str the input string representing the value of the
/// boolean.
///
/// @param result the parsed boolean value.
///
/// @return whether the parse was successful.
static bool
string_to_boolean(const std::string& str, bool& result)
{
  if (str == "yes" || str == "true")
  {
    result = true;
    return true;
  }
  if (str == "no" || str == "false")
  {
    result = false;
    return true;
  }
  // TODO: maybe emit bad boolean 'str' error message
  return false;
}

// property parsing

/// Read a string from a property.
///
/// The property should be a simple property.
///
/// @param prop the input property.
///
/// @param result the output string to assign to.
///
/// @return whether parsing was successful.
static bool
read(const ini::property_sptr& prop, std::string& result)
{
  ini::simple_property_sptr simple = is_simple_property(prop);
  if (!simple)
    {
      // TODO: maybe emit property is not a simple string message
      return false;
    }
  result = simple->get_value()->as_string();
  return true;
}

/// Read and compile a regex from a property.
///
/// The property should be a simple property.
///
/// @param prop the input property.
///
/// @param result the output compiled regex.
///
/// @return whether parsing and compiling were successful.
static bool
read(const ini::property_sptr& prop, regex_t_sptr& result)
{
  std::string str;
  if (!read(prop, str))
    return false;
  regex_t_sptr regex = regex::compile(str);
  if (!regex)
    {
      // TODO: maybe emit bad regex 'str' error message
      return false;
    }
  result = regex;
  return true;
}

/// Read a boolean value from a property.
///
/// The property should be a simple property.
///
/// @param prop the input property.
///
/// @param result the output boolean.
///
/// @return whether the parse was successful.
static bool
read(const ini::property_sptr& prop, bool& result)
{
  std::string str;
  return read(prop, str) && string_to_boolean(str, result);
}

// section parsing

/// Check if a section has at least one of the given properties.
///
/// @param names pointer to the start of an array of names.
///
/// @param count number of names in the array.
///
/// @return whether at least of one the properties was found.
bool
check_sufficient_props(const char *const * names, size_t count,
		       const ini::config::section& section)
{
  for (const char *const * name = names; name < names + count; ++name)
    if (section.find_property(*name))
      return true;
  // TODO: Possibly give reason for failure in a message here.
  return false;
}

// </parsing stuff>

// <suppression_base stuff>

/// Default constructor for @ref suppression_base
suppression_base::suppression_base()
  : priv_(new priv())
{}

/// Tests if the current suppression specification is to avoid adding
/// the matched ABI artifact to the internal representation or not.
///
/// @return true iff the current suppression specification is to avoid
/// adding the matched ABI artifact to the internal representation.
bool
suppression_base::get_drops_artifact_from_ir() const
{return priv_->drops_artifact_;}

/// Set the flag that says whether the current suppression
/// specification is to avoid adding the matched ABI artifact to the
/// internal representation or not.
///
/// @param f the flag to set to true iff the current suppression
/// specification is to avoid adding the matched ABI artifact to the
/// internal representation.
void
suppression_base::set_drops_artifact_from_ir(bool f)
{priv_->drops_artifact_ = f;}

/// Test is the suppression specification is artificial.
///
/// Artificial means that the suppression was automatically generated
/// by libabigail, rather than being constructed from a suppression
/// file provided by the user.
///
/// @return TRUE iff the suppression specification is artificial.
bool
suppression_base::get_is_artificial() const
{return priv_->is_artificial_;}

/// Set a flag saying if the suppression specification is artificial
/// or not.
///
/// Artificial means that the suppression was automatically generated
/// by libabigail, rather than being constructed from a suppression
/// file provided by the user.
void
suppression_base::set_is_artificial(bool f)
{priv_->is_artificial_ = f;}

/// Getter for the label associated to this suppression specification.
///
/// @return the label.
const string
suppression_base::get_label() const
{return priv_->label_;}

/// Setter for the label associated to this suppression specification.
///
/// @param label the new label.  This is intended to be an informative
/// text string that the evalution code might use to designate this
/// function suppression specification in error messages.  This
/// parameter might be empty, in which case it's ignored at evaluation
/// time.
void
suppression_base::set_label(const string& label)
{priv_->label_ = label;}

/// Setter for the "file_name_regex" property of the current instance
/// of @ref suppression_base.
///
/// The "file_name_regex" property is a regular expression that
/// identifies files containing ABI artifacts that this suppression
/// should apply to.
///
/// @param regexp the new regular expression that denotes the file
/// names to match, or a null pointer to unset this.
void
suppression_base::set_file_name_regex(const regex_t_sptr& regexp)
{priv_->file_name_regex_ = regexp;}

/// Getter for the "file_name_regex" property of the current instance
/// of @ref suppression_base.
///
/// The "file_name_regex" property is a regular expression that
/// identifies files containing ABI artifacts that this suppression
/// should apply to.
///
/// @return the regular expression, or a null pointer if unset.
const regex_t_sptr&
suppression_base::get_file_name_regex() const
{return priv_->file_name_regex_;}

/// Setter for the "file_name_not_regex" property of the current
/// instance of @ref suppression_base.
///
/// The "file_name_not_regex" property is a regular expression that
/// identifies files containing ABI artifacts that this suppression
/// should *NOT* apply to.
///
/// @param regexp the new regular expression that denotes the file
/// names to *NOT* match, or a null pointer to unset this.
void
suppression_base::set_file_name_not_regex(const regex_t_sptr& regexp)
{priv_->file_name_not_regex_ = regexp;}

/// Getter for the "file_name_not_regex" property of the current
/// instance of @ref suppression_base.
///
/// The "file_name_not_regex" property is a regular expression that
/// identifies files containing ABI artifacts that this suppression
/// should *NOT* apply to, or a null pointer if unset.
///
/// @return the regular expression, or a null pointer if unset.
const regex_t_sptr&
suppression_base::get_file_name_not_regex() const
{return priv_->file_name_not_regex_;}

/// Test if the current suppression has a property related to file
/// name.
///
/// @return true iff the current suppression has either a
/// file_name_regex or a file_name_not_regex property.
bool
suppression_base::has_file_name_related_property() const
{
  return get_file_name_regex() || get_file_name_not_regex();
}

/// Setter of the "soname_regex" property of the current instance
/// of @ref suppression_base.
///
/// The "soname_regex" is a regular expression that designates the
/// soname of the shared library that contains the ABI artifacts this
/// suppression should apply to.
///
/// @param regexp the new regular expression, or a null pointer to
/// unset this.
void
suppression_base::set_soname_regex(const regex_t_sptr& regexp)
{priv_->soname_regex_ = regexp;}

/// Getter of the "soname_regex" property of the current instance
/// of @ref suppression_base.
///
/// The "soname_regex" is a regular expression that designates the
/// soname of the shared library that contains the ABI artifacts this
/// suppression should apply to.
///
/// @return the regular expression, or a null pointer if unset.
const regex_t_sptr&
suppression_base::get_soname_regex() const
{return priv_->soname_regex_;}

/// Setter of the "soname_not_regex" property of the current
/// instance of @ref suppression_base.
///
/// The current suppression specification should apply to ABI
/// artifacts of a shared library which SONAME does *NOT* match the
/// regular expression designated by the "soname_not_regex" property.
///
/// @param regexp the new regular expression, or a null pointer to
/// unset this.
void
suppression_base::set_soname_not_regex(const regex_t_sptr& regexp)
{priv_->soname_not_regex_ = regexp;}

/// Getter of the "soname_not_regex" property of the current
/// instance of @ref suppression_base.
///
/// The current suppression specification should apply to ABI
/// artifacts of a shared library which SONAME does *NOT* match the
/// regular expression designated by the "soname_not_regex" property,
/// or a null pointer if unset.
///
/// @return the regular expression, or a null pointer if unset.
const regex_t_sptr&
suppression_base::get_soname_not_regex() const
{return priv_->soname_not_regex_;}

/// Test if the current suppression has a property related to SONAMEs.
///
/// @return true iff the current suppression has either a soname_regex
/// or a soname_not_regex property.
bool
suppression_base::has_soname_related_property() const
{
  return get_soname_regex() || get_soname_not_regex();
}

/// Test if the current suppression matches a given SONAME.
///
/// @param soname the SONAME to consider.
///
/// @return true iff the suppression matches the SONAME denoted by
/// @p soname.
///
/// Note that if the suppression contains no property that is
/// related to SONAMEs, the function returns false.
bool
suppression_base::matches_soname(const std::string& soname) const
{
  bool has_regexp = false;
  if (regex_t_sptr regexp = get_soname_regex())
    {
      has_regexp = true;
      if (!regex::match(regexp, soname))
	return false;
    }

  if (regex_t_sptr regexp = get_soname_not_regex())
    {
      has_regexp = true;
      if (regex::match(regexp, soname))
	return false;
    }

  if (!has_regexp)
    return false;

  return true;
}

/// Test if the current suppression matches the full file path to a
/// given binary.
///
/// @param binary_name the full path to the binary.
///
/// @return true iff the suppression matches the path denoted by @p
/// binary_name.
///
/// Note that if the suppression contains no property that is
/// related to file name, the function returns false.
bool
suppression_base::matches_binary_name(const std::string& binary_name) const
{
  bool has_regexp = false;

  if (regex_t_sptr regexp = get_file_name_regex())
    {
      has_regexp = true;
      if (!regex::match(regexp, binary_name))
	return false;
    }

  if (regex_t_sptr regexp = get_file_name_not_regex())
    {
      has_regexp = true;
      if (regex::match(regexp, binary_name))
	return false;
    }

  if (!has_regexp)
    return false;

  return true;
}

/// Check if the SONAMEs of the two binaries being compared match the
/// content of the properties "soname_regexp" and "soname_not_regexp"
/// of the current suppression specification.
///
/// @param suppr the suppression specification
///
/// @param ctxt the context of the comparison.
///
/// @return false if the regular expression contained in the property
/// soname_regexp or in the property "soname_not_regexp" does *NOT*
/// match at least one of the SONAMEs of the two binaries being
/// compared.  Return true otherwise.
static bool
sonames_of_binaries_match(const suppression_base& suppr,
			  const diff_context& ctxt)
{
  // Check if the sonames of the binaries match
  string first_soname = ctxt.get_corpus_diff()->first_corpus()->get_soname(),
    second_soname = ctxt.get_corpus_diff()->second_corpus()->get_soname();

  if (!suppr.has_soname_related_property())
    return false;

  if (!suppression_matches_soname(first_soname, suppr)
      && !suppression_matches_soname(second_soname, suppr))
    return false;

  return true;
}

/// Check if the names of the two binaries being compared match the
/// content of the properties "file_name_regexp" and
/// "file_name_not_regexp".
///
/// @param suppr the current suppression specification.
///
/// @param ctxt the context of the comparison.
///
/// @return false if the regular expression contained in the property
/// file_name_regexp or in the property "file_name_not_regexp" does
/// *NOT* match at least one of the names of the two binaries being
/// compared.  Return true otherwise.
static bool
names_of_binaries_match(const suppression_base& suppr,
			const diff_context &ctxt)
{
   // Check if the file names of the binaries match
  string first_binary_path = ctxt.get_corpus_diff()->first_corpus()->get_path(),
    second_binary_path = ctxt.get_corpus_diff()->second_corpus()->get_path();

  if (!suppr.has_file_name_related_property())
    return false;

  if (!suppr.matches_binary_name(first_binary_path)
      && !suppr.matches_binary_name(second_binary_path))
    return false;

  return true;
}

suppression_base::~suppression_base()
{}

static bool
read_type_suppression(const ini::config::section& section,
		      suppression_sptr& suppr);

static bool
read_function_suppression(const ini::config::section& section,
			  suppression_sptr& suppr);

static bool
read_variable_suppression(const ini::config::section& section,
			  suppression_sptr& suppr);

static bool
read_file_suppression(const ini::config::section& section,
		      suppression_sptr& suppr);

/// Read a vector of suppression specifications from the sections of
/// an ini::config.
///
/// Note that this function needs to be updated each time a new kind
/// of suppression specification is added.
///
/// @param config the config to read from.
///
/// @param suppressions out parameter.  The vector of suppressions to
/// append the newly read suppressions to.
///
/// @return whether the parse was successful.
static bool
read_suppressions(const ini::config& config, suppressions_type& suppressions)
{
  bool success = true;
  for (ini::config::sections_type::const_iterator i =
	 config.get_sections().begin();
       i != config.get_sections().end();
       ++i)
    {
      const ini::config::section_sptr& section = *i;
      const std::string& name = section->get_name();
      bool section_success;
      suppression_sptr s;
      if (name == "suppress_type")
	section_success = read_type_suppression(*section, s);
      else if (name == "suppress_function")
	section_success = read_function_suppression(*section, s);
      else if (name == "suppress_variable")
	section_success = read_variable_suppression(*section, s);
      else if (name == "suppress_file")
	section_success = read_file_suppression(*section, s);
      else
	{
	  // TODO: maybe emit unknown section name error
	  success = false;
	  continue;
	}
      if (section_success)
	suppressions.push_back(s);
      else
	{
	  // TODO: maybe emit section parse failure message
	  success = false;
	}
    }
  return success;
}

/// Read suppressions specifications from an input stream.
///
/// @param input the input stream to read from.
///
/// @param suppressions the vector of suppressions to append the newly
/// read suppressions to.
///
/// @return whether the parse was successful
bool
read_suppressions(std::istream& input,
		  suppressions_type& suppressions)
{
  ini::config_sptr config = ini::read_config(input);
  if (!config)
    {
      // TODO: maybe report ini configuration parse failure
      return false;
    }
  return read_suppressions(*config, suppressions);
}

/// Read suppressions specifications from an input file on disk.
///
/// @param input the path to the input file to read from.
///
/// @param suppressions the vector of suppressions to append the newly
/// read suppressions to.
///
/// @return whether the parse was successful
bool
read_suppressions(const string& file_path,
		  suppressions_type& suppressions)
{
  ini::config_sptr config = ini::read_config(file_path);
  if (!config)
    {
      // TODO: maybe report ini configuration file_path parse failure
      return false;
    }
  return read_suppressions(*config, suppressions);
}
// </suppression_base stuff>

// <type_suppression stuff>

/// Default constructor for @ref type_suppression.
type_suppression::type_suppression()
  : suppression_base(), priv_(new priv)
{}

type_suppression::~type_suppression()
{}

/// Setter for the "type_name_regex" property of the type suppression
/// specification.
///
/// This sets a regular expression that specifies the family of types
/// about which diff reports should be suppressed.
///
/// @param name_regex the new regular expression to set, or a null
/// pointer to unset this.
void
type_suppression::set_type_name_regex(const regex_t_sptr& name_regex)
{priv_->type_name_regex_ = name_regex;}

/// Getter for the "type_name_regex" property of the type suppression
/// specification.
///
/// This returns a regular expression that specifies the family
/// of types about which diff reports should be suppressed.
///
/// @return the regular expression or a null pointer if unset.
const regex_t_sptr&
type_suppression::get_type_name_regex() const
{return priv_->type_name_regex_;}

/// Setter for the "type_name_not_regex" property of the type
/// suppression specification.
///
/// This sets a regular expression that specifies the family
/// of types that should be kept after suppression.
///
/// @param r the new regular expression, or a null pointer to unset
/// this.
void
type_suppression::set_type_name_not_regex(const regex_t_sptr& r)
{priv_->type_name_not_regex_ = r;}

/// Getter for the "type_name_not_regex" property of the type
/// suppression specification.
///
/// This returns a regular expression that specifies the family
/// of types that should be kept after suppression.
///
/// @return the new regular expression, or a null pointer if unset.
const regex_t_sptr&
type_suppression::get_type_name_not_regex() const
{return priv_->type_name_not_regex_;}

/// Setter for the name of the type about which diff reports should be
/// suppressed.
///
/// @param name the new type name.
void
type_suppression::set_type_name(const string& name)
{priv_->type_name_ = name;}

/// Getter for the name of the type about which diff reports should be
/// suppressed.
///
/// @param return the type name.
const string&
type_suppression::get_type_name() const
{return priv_->type_name_;}

/// Getter of the property that says whether to consider the kind of
/// type this suppression is about.
///
/// @return the boolean value of the property.
bool
type_suppression::get_consider_type_kind() const
{return priv_->consider_type_kind_;}

/// Setter of the property that says whether to consider the kind of
/// type this suppression is about.
///
/// @param f the new boolean value of the property.
void
type_suppression::set_consider_type_kind(bool f)
{priv_->consider_type_kind_ = f;}

/// Setter of the kind of type this suppression is about.
///
/// Note that this will be considered during evaluation of the
/// suppression only if type_suppression::get_consider_type_kind()
/// returns true.
///
/// @param k the new kind of type this suppression is about.
void
type_suppression::set_type_kind(type_kind k)
{priv_->type_kind_ = k;}

/// Getter of the kind of type this suppression is about.
///
/// Note that this will be considered during evaluation of the
/// suppression only if type_suppression::get_consider_type_kind()
/// returns true.
///
/// @return the kind of type this suppression is about.
type_suppression::type_kind
type_suppression::get_type_kind() const
{return priv_->type_kind_;}

/// Test if the current type suppression specification
/// suggests to consider how the matching diff node is reached.
///
/// @return true if the current type suppression specification
/// suggests to consider how the matching diff node is reached.
bool
type_suppression::get_consider_reach_kind() const
{return priv_->consider_reach_kind_;}

/// Set a flag saying if the current type suppression specification
/// suggests to consider how the matching diff node is reached.
///
/// @param f the new value of the flag.  It's true iff the current
/// type suppression specification suggests to consider how the
/// matching diff node is reached.
void
type_suppression::set_consider_reach_kind(bool f)
{priv_->consider_reach_kind_ = f;}

/// Getter of the way the diff node matching the current suppression
/// specification is to be reached.
///
/// @return the way the diff node matching the current suppression
/// specification is to be reached.
type_suppression::reach_kind
type_suppression::get_reach_kind() const
{return priv_->reach_kind_;}

/// Setter of the way the diff node matching the current suppression
/// specification is to be reached.
///
/// @param p the way the diff node matching the current suppression
/// specification is to be reached.
void
type_suppression::set_reach_kind(reach_kind k)
{priv_->reach_kind_ = k;}

/// Setter for the vector of data member insertion ranges that
/// specifies where a data member is inserted as far as this
/// suppression specification is concerned.
///
/// @param r the new insertion range vector.
void
type_suppression::set_data_member_insertion_ranges(const offset_ranges& r)
{priv_->insertion_ranges_ = r;}

/// Getter for the vector of data member insertion range that
/// specifiers where a data member is inserted as far as this
/// suppression specification is concerned.
///
/// @return the vector of insertion ranges.
const type_suppression::offset_ranges&
type_suppression::get_data_member_insertion_ranges() const
{return priv_->insertion_ranges_;}

/// Getter for the vector of data member insertion range that
/// specifiers where a data member is inserted as far as this
/// suppression specification is concerned.
///
/// @return the vector of insertion ranges.
type_suppression::offset_ranges&
type_suppression::get_data_member_insertion_ranges()
{return priv_->insertion_ranges_;}

/// Getter for the array of source location paths of types that should
/// *NOT* be suppressed.
///
/// @return the set of source locations of types that should *NOT* be
/// supressed.
const unordered_set<string>&
type_suppression::get_source_locations_to_keep() const
{return priv_->source_locations_to_keep_;}

/// Getter for the array of source location paths of types that should
/// *NOT* be suppressed.
///
/// @return the array of source locations of types that should *NOT*
/// be supressed.
unordered_set<string>&
type_suppression::get_source_locations_to_keep()
{return priv_->source_locations_to_keep_;}

/// Setter for the array of source location paths of types that should
/// *NOT* be suppressed.
///
/// @param l the new array.
void
type_suppression::set_source_locations_to_keep
(const unordered_set<string>& l)
{priv_->source_locations_to_keep_ = l;}

/// Getter of the regular expression that designates the source
/// location paths of types that should not be suppressed.
///
/// @return the regular expression, or a null pointer if unset.
const regex_t_sptr&
type_suppression::get_source_location_to_keep_regex() const
{return priv_->source_location_to_keep_regex_;}

/// Setter of the regular expression that designates the source
/// location paths of types that should not be suppressed.
///
/// @param r the new regular expression.
void
type_suppression::set_source_location_to_keep_regex(const regex_t_sptr& r)
{priv_->source_location_to_keep_regex_ = r;}

/// Getter of the vector of the changed enumerators that are supposed
/// to be suppressed.  Note that this will be "valid" only if the type
/// suppression has the 'type_kind = enum' property.
///
/// @return the vector of the changed enumerators that are supposed to
/// be suppressed.
const vector<string>&
type_suppression::get_changed_enumerator_names() const
{return priv_->changed_enumerator_names_;}

/// Setter of the vector of changed enumerators that are supposed to
/// be suppressed.  Note that this will be "valid" only if the type
/// suppression has the 'type_kind = enum' property.
///
/// @param n the vector of the changed enumerators that are supposed
/// to be suppressed.
void
type_suppression::set_changed_enumerator_names(const vector<string>& n)
{priv_->changed_enumerator_names_ = n;}

/// Evaluate this suppression specification on a given diff node and
/// say if the diff node should be suppressed or not.
///
/// @param diff the diff node to evaluate this suppression
/// specification against.
///
/// @return true if @p diff should be suppressed.
bool
type_suppression::suppresses_diff(const diff* diff) const
{
  const type_diff_base* d = is_type_diff(diff);
  if (!d)
    {
      // So the diff we are looking at is not a type diff.  However,
      // there are cases where a type suppression can suppress changes
      // on functions.

      // Typically, if a virtual member function's virtual index (its
      // index in the vtable of a class) changes and if the current
      // type suppression is meant to suppress change reports about
      // the enclosing class of the virtual member function, then this
      // type suppression should suppress reports about that function
      // change.
      const function_decl_diff* d = is_function_decl_diff(diff);
      if (d)
	{
	  // Let's see if 'd' carries a virtual member function
	  // change.
	  if (comparison::filtering::has_virtual_mem_fn_change(d))
	    {
	      function_decl_sptr f = d->first_function_decl();
	      class_decl_sptr fc =
		is_class_type(is_method_type(f->get_type())->get_class_type());
	      ABG_ASSERT(fc);
	      if (suppresses_type(fc, diff->context()))
		return true;
	    }
	}
      return false;
    }

  // If the suppression should consider the way the diff node has been
  // reached, then do it now.
  if (get_consider_reach_kind())
    {
      if (get_reach_kind() == POINTER_REACH_KIND)
	{
	  if (const pointer_diff* ptr_diff = is_pointer_diff(diff))
	    {
	      d = is_type_diff(ptr_diff->underlying_type_diff().get());
	      if (!d)
		// This might be of, e.g, distinct_diff type.
		return false;
	      d = is_type_diff(peel_qualified_diff(d));
	    }
	  else
	    return false;
	}
      else if (get_reach_kind() == REFERENCE_REACH_KIND)
	{
	  if (const reference_diff* ref_diff = is_reference_diff(diff))
	    {
	      d = is_type_diff(ref_diff->underlying_type_diff().get());
	      if (!d)
		// This might be of, e.g, distinct_diff type.
		return false;
	      d = is_type_diff(peel_qualified_diff(d));
	    }
	  else
	    return false;
	}
      else if (get_reach_kind() == REFERENCE_OR_POINTER_REACH_KIND)
	{
	  if (const pointer_diff* ptr_diff = is_pointer_diff(diff))
	    {
	      d = is_type_diff(ptr_diff->underlying_type_diff().get());
	      ABG_ASSERT(d);
	      d = is_type_diff(peel_qualified_diff(d));
	    }
	  else if (const reference_diff* ref_diff = is_reference_diff(diff))
	    {
	      d = is_type_diff(ref_diff->underlying_type_diff().get());
	      ABG_ASSERT(d);
	      d = is_type_diff(peel_qualified_diff(d));
	    }
	  else
	    return false;
	}
    }

  type_base_sptr ft, st;
  ft = is_type(d->first_subject());
  st = is_type(d->second_subject());
  ABG_ASSERT(ft && st);

  if (!suppresses_type(ft, d->context())
      && !suppresses_type(st, d->context()))
    {
      // A private type suppression specification considers that a
      // type can be private and yet some typedefs of that type can be
      // public -- depending on, e.g, if the typedef is defined in a
      // public header or not.  So if we are in the context of a
      // private type suppression let's *NOT* peel typedefs away.
      if (!is_private_type_suppr_spec(*this))
	{
	  ft = peel_typedef_type(ft);
	  st = peel_typedef_type(st);
	}

      if (!suppresses_type(ft, d->context())
	  && !suppresses_type(st, d->context()))
	return false;

      d = is_type_diff(get_typedef_diff_underlying_type_diff(d));
    }

  // Now let's consider class diffs in the context of a suppr spec
  // that contains properties like "has_data_member_inserted_*".

  const class_diff* klass_diff = dynamic_cast<const class_diff*>(d);
  if (klass_diff)
    {
      // We are looking at a class diff ...
      if (!get_data_member_insertion_ranges().empty())
	{
	  // ... and the suppr spec contains a
	  // "has_data_member_inserted_*" clause ...
	  if (klass_diff->deleted_data_members().empty()
	      && (klass_diff->first_class_decl()->get_size_in_bits()
		  <= klass_diff->second_class_decl()->get_size_in_bits()))
	    {
	      // That "has_data_member_inserted_*" clause doesn't hold
	      // if the class has deleted data members or shrunk.

	      const class_decl_sptr& first_type_decl =
		klass_diff->first_class_decl();

	      for (string_decl_base_sptr_map::const_iterator m =
		     klass_diff->inserted_data_members().begin();
		   m != klass_diff->inserted_data_members().end();
		   ++m)
		{
		  decl_base_sptr member = m->second;
		  size_t dm_offset = get_data_member_offset(member);
		  bool matched = false;

		  for (offset_ranges::const_iterator i =
			 get_data_member_insertion_ranges().begin();
		       i != get_data_member_insertion_ranges().end();
		       ++i)
		    {
		      type_suppression::offset_range_sptr range = *i;
		      uint64_t range_begin_val = 0, range_end_val = 0;
		      if (!range->begin()->eval(first_type_decl, range_begin_val))
			break;
		      if (!range->end()->eval(first_type_decl, range_end_val))
			break;

		      uint64_t range_begin = range_begin_val;
		      uint64_t range_end = range_end_val;

		      if (insertion_range::boundary_value_is_end(range_begin)
			  && insertion_range::boundary_value_is_end(range_end))
			{
			  // This idiom represents the predicate
			  // "has_data_member_inserted_at = end"
			  if (dm_offset >
			      get_data_member_offset(get_last_data_member
						     (first_type_decl)))
			    {
			      // So the data member was added after
			      // last data member of the klass.  That
			      // matches the suppr spec
			      // "has_data_member_inserted_at = end".
			      matched = true;
			      continue;
			    }
			}

			if (range_begin > range_end)
			  // Wrong suppr spec.  Ignore it.
			  continue;

		      if (dm_offset < range_begin || dm_offset > range_end)
			// The offset of the added data member doesn't
			// match the insertion range specified.  So
			// the diff object won't be suppressed.
			continue;

		      // If we reached this point, then all the
		      // insertion range constraints have been
		      // satisfied.  So
		      matched = true;
		    }
		  if (!matched)
		    return false;
		}
	    }
	  else
	    return false;
	}
    }

  const enum_diff* enum_dif = dynamic_cast<const enum_diff*>(d);
  if (// We are looking at an enum diff node which ...
      enum_dif
      //... carries no deleted enumerator ... "
      && enum_dif->deleted_enumerators().empty()
      // ... carries no size change ...
      && (enum_dif->first_enum()->get_size_in_bits()
	  == enum_dif->second_enum()->get_size_in_bits())
      // ... and yet carries some changed enumerators!
      && !enum_dif->changed_enumerators().empty())
    {
      // Make sure that all changed enumerators are listed in the
      // vector of enumerator names returned by the
      // get_changed_enumerator_names() member function.
      bool matched = true;
      for (string_changed_enumerator_map::const_iterator i =
	     enum_dif->changed_enumerators().begin();
	   i != enum_dif->changed_enumerators().end();
	   ++i)
	{
	  matched &= true;
	  if (std::find(get_changed_enumerator_names().begin(),
			get_changed_enumerator_names().end(),
			i->first) == get_changed_enumerator_names().end())
	    {
	      matched &= false;
	      break;
	    }
	}
      if (!matched)
	return false;
    }

  return true;
}

/// Test if the current instance of @ref type_suppression suppresses a
/// change reports about a given type.
///
/// @param type the type to consider.
///
/// @param ctxt the context of comparison we are involved with.
///
/// @return true iff the suppression specification suppresses type @p
/// type.
bool
type_suppression::suppresses_type(const type_base_sptr& type,
				  const diff_context_sptr& ctxt) const
{
  if (ctxt)
    {
      // Check if the names of the binaries match the suppression
      if (!names_of_binaries_match(*this, *ctxt))
	if (has_file_name_related_property())
	  return false;

      // Check if the sonames of the binaries match the suppression
      if (!sonames_of_binaries_match(*this, *ctxt))
	if (has_soname_related_property())
	  return false;
    }

  return suppresses_type(type);
}

/// Test if an instance of @ref type_suppression matches a given type.
///
/// This function does not take the name of the type into account
/// while testing if the type matches the type_suppression.
///
/// @param s the suppression to evaluate.
///
/// @param type the type to consider.
///
/// @return true iff the suppression specification matches type @p
/// type without taking its name into account.
static bool
suppression_matches_type_no_name(const type_suppression&	 s,
				 const type_base_sptr		&type)
{
  // If the suppression should consider type kind then, well, check
  // for that.
  if (s.get_consider_type_kind())
    {
      type_suppression::type_kind tk = s.get_type_kind();
      bool matches = true;
      switch (tk)
	{
	case type_suppression::UNKNOWN_TYPE_KIND:
	case type_suppression::CLASS_TYPE_KIND:
	  if (!is_class_type(type))
	    matches = false;
	  break;
	case type_suppression::STRUCT_TYPE_KIND:
	  {
	    class_decl_sptr klass = is_class_type(type);
	    if (!klass || !klass->is_struct())
	      matches = false;
	  }
	  break;
	case type_suppression::UNION_TYPE_KIND:
	  if (!is_union_type(type))
	    matches = false;
	  break;
	case type_suppression::ENUM_TYPE_KIND:
	  if (!is_enum_type(type))
	    matches = false;
	  break;
	case type_suppression::ARRAY_TYPE_KIND:
	  if (!is_array_type(type))
	    matches = false;
	  break;
	case type_suppression::TYPEDEF_TYPE_KIND:
	  if (!is_typedef(type))
	    matches = false;
	  break;
	case type_suppression::BUILTIN_TYPE_KIND:
	  if (!is_type_decl(type))
	    matches = false;
	  break;
	}

      if (!matches)
	return false;
    }

  // Check if there is a source location related match.
  if (!suppression_matches_type_location(s, type))
    return false;

  return true;
}

/// Test if a type suppression specification matches a type name.
///
/// @param s the type suppression to consider.
///
/// @param type_name the type name to consider.
///
/// @return true iff the type designated by its name @p type_name is
/// matched by the type suppression specification @p s.
bool
suppression_matches_type_name(const type_suppression&	s,
			      const string&		type_name)
{
  if (!s.get_type_name().empty()
      || s.get_type_name_regex()
      || s.get_type_name_not_regex())
    {
      // Check if there is an exact type name match.
      if (!s.get_type_name().empty())
	{
	  if (s.get_type_name() != type_name)
	    return false;
	}
      else
	{
	  // Now check if there is a regular expression match.
	  //
	  // If the qualified name of the considered type doesn't match
	  // the regular expression of the type name, then this
	  // suppression doesn't apply.
	  if (const regex_t_sptr& type_name_regex = s.get_type_name_regex())
	    {
	      if (!regex::match(type_name_regex, type_name))
		return false;
	    }

	  if (const regex_t_sptr& type_name_not_regex =
		s.get_type_name_not_regex())
	    {
	      if (regex::match(type_name_not_regex, type_name))
		return false;
	    }
	}
    }

  return true;
}

/// Test if a type suppression matches a type in a particular scope.
///
/// @param s the type suppression to consider.
///
/// @param type_scope the scope of the type to consider.
///
/// @param type the type to consider.
///
/// @return true iff the supression @p s matches type @p type in scope
/// @p type_scope.
bool
suppression_matches_type_name(const suppr::type_suppression&	s,
			      const scope_decl*		type_scope,
			      const type_base_sptr&		type)
{
  string type_name = build_qualified_name(type_scope, type);
  return suppression_matches_type_name(s, type_name);
}

/// Test if a type suppression matches a source location.
///
/// @param s the type suppression to consider.
///
/// @param loc the location to consider.
///
/// @return true iff the suppression @p s matches location @p loc.
bool
suppression_matches_type_location(const type_suppression&	s,
				  const location&		loc)
{
  if (loc)
    {
      // Check if there is a source location related match.
      string loc_path, loc_path_base;
      unsigned loc_line = 0, loc_column = 0;
      loc.expand(loc_path, loc_line, loc_column);

      if (const regex_t_sptr& regexp = s.get_source_location_to_keep_regex())
	if (regex::match(regexp, loc_path))
	  return false;

      tools_utils::base_name(loc_path, loc_path_base);
      if (s.get_source_locations_to_keep().find(loc_path_base)
	  != s.get_source_locations_to_keep().end())
	return false;
      if (s.get_source_locations_to_keep().find(loc_path)
	  != s.get_source_locations_to_keep().end())
	return false;
    }
  else
    {
      if (!s.get_source_locations_to_keep().empty()
	  || s.get_source_location_to_keep_regex())
	// The user provided a "source_location_not_regexp" or
	// a "source_location_not_in" property that was not
	// triggered.  This means the current type suppression
	// doesn't suppress the type given.
	return false;
    }

  return true;
}

/// Test if a type suppression matches a type.
///
/// @param s the type suppression to consider.
///
/// @param type the type to consider.
///
/// @return true iff the suppression @p s matches type @p type.
bool
suppression_matches_type_location(const type_suppression&	s,
				  const type_base_sptr&	type)
{
  location loc = get_location(type);
  if (loc)
    return suppression_matches_type_location(s, loc);
  else
    {
      // The type had no source location.
      //
      // In the case where this type suppression was automatically
      // generated to suppress types not defined in public
      // headers, then this might mean that the type is not
      // defined in the public headers.  Otherwise, why does it
      // not have a source location?
      if (s.get_is_artificial())
	{
	  if (class_decl_sptr cl = is_class_type(type))
	    {
	      if (cl->get_is_declaration_only())
		// We tried hard above to get the definition of
		// the declaration.  If we reach this place, it
		// means the class has no definition at this point.
		ABG_ASSERT(!cl->get_definition_of_declaration());
	      if (s.get_label() == get_private_types_suppr_spec_label())
		// So this looks like what really amounts to an
		// opaque type.  So it's not defined in the public
		// headers.  So we want to filter it out.
		return true;
	    }
	}
      if (!s.get_source_locations_to_keep().empty()
	  || s.get_source_location_to_keep_regex())
	// The user provided a "source_location_not_regexp" or
	// a "source_location_not_in" property that was not
	// triggered.  This means the current type suppression
	// doesn't suppress the type given.
	return false;
    }

  return true;
}

/// Test if a type suppression matches a type name and location.
///
/// @param s the type suppression to consider.
///
/// @param type_name the name of the type to consider.
///
/// @param type_location the location of the type to consider.
///
/// @return true iff suppression @p s matches a type named @p
/// type_name with a location @p type_location.
bool
suppression_matches_type_name_or_location(const type_suppression& s,
					  const string& type_name,
					  const location& type_location)
{
  if (!suppression_matches_type_name(s, type_name))
    return false;
  if (!suppression_matches_type_location(s, type_location))
    return false;
  return true;
}

/// Test if the current instance of @ref type_suppression matches a
/// given type.
///
/// @param type the type to consider.
///
/// @return true iff the suppression specification suppresses type @p
/// type.
bool
type_suppression::suppresses_type(const type_base_sptr& type) const
{
  if (!suppression_matches_type_no_name(*this, type))
    return false;

  if (!suppression_matches_type_name(*this, get_name(type)))
    return false;

  return true;
}

/// Test if the current instance of @ref type_suppression matches a
/// given type in a given scope.
///
/// @param type the type to consider.
///
/// @param type_scope the scope of type @p type.
///
/// @return true iff the suppression specification suppresses type @p
/// type from scope @p type_scope.
bool
type_suppression::suppresses_type(const type_base_sptr& type,
				  const scope_decl* type_scope) const
{
  if (!suppression_matches_type_no_name(*this, type))
    return false;

  if (!suppression_matches_type_name(*this, type_scope, type))
    return false;

  return true;
}

/// The private data of type_suppression::offset_range
struct type_suppression::offset_range::priv
{
  offset_sptr begin_;
  offset_sptr end_;

  priv()
  {}

  priv(offset_sptr begin, offset_sptr end)
    : begin_(begin), end_(end)
  {}
}; // end struct type_suppression::offset_range::priv

/// Default Constructor of @ref type_suppression::offset_range.
type_suppression::offset_range::offset_range()
  : priv_(new priv)
{}

/// Constructor of @ref type_suppression::offset_range.
///
/// @param begin the start of the range.  An offset that is an
/// instance of @ref integer_offset with a negative value means the
/// maximum possible value.
///
/// @param end the end of the range.  An offset that is an instance of
/// @ref integer_offset with a negative value means the maximum
/// possible value.
type_suppression::offset_range::offset_range(offset_sptr begin, offset_sptr end)
  : priv_(new priv(begin, end))
{}

/// Getter for the beginning of the range.
///
/// @return the beginning of the range.  An offset that is an instance
/// of @ref integer_offset with a negative value means the maximum
/// possible value.
type_suppression::offset_sptr
type_suppression::offset_range::begin() const
{return priv_->begin_;}

/// Getter for the end of the range.
///
/// @return the end of the range.  An offset that is an instance of
/// @ref integer_offset with a negative value means the maximum
/// possible value.
type_suppression::offset_sptr
type_suppression::offset_range::end() const
{return priv_->end_;}

/// Create an integer offset.
///
/// The return value of this function is to be used as a boundary for
/// an instance of @ref type_suppression::offset_range.  The offset
/// evaluates to an integer value.
///
/// @param value the value of the integer offset.
///
/// @return the resulting integer offset.
type_suppression::offset_sptr
type_suppression::offset::create_integer_offset(int value)
{return offset_sptr(new integer_offset(value));}

/// Destructor of @ref type_suppression::offset.
type_suppression::offset::~offset()
{}

/// Private data type for @ref
/// type_suppression::offset::integer_offset.
struct type_suppression::offset::integer_offset::priv
{
  uint64_t value_;

  priv()
    : value_()
  {}

  priv(uint64_t value)
    : value_(value)
  {}
}; // end type_suppression::offset::integer_offset::priv

/// Explicit constructor of type_suppression::offset::integer_offset.
///
/// @param value the integer value of the newly created integer offset.
type_suppression::offset::integer_offset::integer_offset(uint64_t value)
  : priv_(new priv(value))
{}

/// Destructor of @ref type_suppression::offset::integer_offset.
type_suppression::offset::integer_offset::~integer_offset()
{}

/// Create a function call expression offset.
///
/// The return value of this function is to be used as a boundary for
/// an instance of @ref type_suppression::offset_range.  The value
/// of the offset is actually a function call expression that itself
/// evalutates to an integer value, in the context of a @ref
/// class_decl.
///
/// @param expr the function call expression to create the offset from.
///
/// @return the resulting function call expression offset.
type_suppression::offset_sptr
type_suppression::offset::create_fn_call_expr_offset(ini::function_call_expr_sptr expr)
{return offset_sptr(new fn_call_expr_offset(expr));}

/// Create a function call expression offset.
///
/// The return value of this function is to be used as a boundary for
/// an instance of @ref type_suppression::offset_range.  The value
/// of the offset is actually a function call expression that
/// itself evalutates to an integer value, in the context of a @ref
/// class_decl.
///
/// @param s a string representing the expression the function call
/// expression to create the offset from.
///
/// @return the resulting function call expression offset.
type_suppression::offset_sptr
type_suppression::offset::create_fn_call_expr_offset(const string& s)
{
  offset_sptr result;
  ini::function_call_expr_sptr expr;
  if (ini::read_function_call_expr(s, expr) && expr)
    result.reset(new fn_call_expr_offset(expr));
  return result;
}

/// Evaluate an offset to get a resulting integer value.
///
/// @param context the context of evaluation.  It's a @ref class_decl
/// to take into account during the evaluation, if there is a need for
/// it.
///
/// @return true iff the evaluation was successful and @p value
/// contains the resulting value.
bool
type_suppression::offset::integer_offset::eval(
  class_decl_sptr, uint64_t& value) const
{
  value = priv_->value_;
  return true;
}

/// Private data type of type @ref
/// type_suppression::offset::fn_call_expr_offset.
struct type_suppression::offset::fn_call_expr_offset::priv
{
  ini::function_call_expr_sptr expr_;

  priv()
  {}

  priv(ini::function_call_expr_sptr expr)
    : expr_(expr)
  {}
}; // end struct type_suppression::offset::fn_call_expr_offset::priv

/// Explicit constructor for @ref
/// type_suppression::offset::fn_call_expr_offset.
///
/// @param expr the function call expression to build this offset
/// from.
type_suppression::offset::fn_call_expr_offset::fn_call_expr_offset(
  ini::function_call_expr_sptr expr)
  : priv_(new priv(expr))
{}

/// Destructor of @ref
/// type_suppression::offset::fn_call_expr_offset.
type_suppression::offset::fn_call_expr_offset::~fn_call_expr_offset()
{}

/// Evaluate an offset to get a resulting integer value.
///
/// @param context the context of evaluation.  It's a @ref class_decl
/// to take into account during the evaluation, if there is a need for
/// it.
///
/// @return true iff the evaluation was successful and @p value
/// contains the resulting value.
bool
type_suppression::offset::fn_call_expr_offset::eval(
  class_decl_sptr context, uint64_t& value) const
{
  ini::function_call_expr_sptr fn_call = priv_->expr_;
  if ((fn_call->get_name() == "offset_of"
       || fn_call->get_name() == "offset_after")
      && fn_call->get_arguments().size() == 1)
    {
      string member_name = fn_call->get_arguments()[0];
      for (class_decl::data_members::const_iterator it =
	     context->get_data_members().begin();
	   it != context->get_data_members().end();
	   ++it)
	{
	  if (!get_data_member_is_laid_out(**it))
	    continue;
	  if ((*it)->get_name() == member_name)
	    {
	      if (fn_call->get_name() == "offset_of")
		value = get_data_member_offset(*it);
	      else if (fn_call->get_name() == "offset_after")
		{
		  if (!get_next_data_member_offset(context, *it, value))
		    {
		      value = get_data_member_offset(*it) +
		      (*it)->get_type()->get_size_in_bits();
		    }
		}
	      else
		// We should not reach this point.
		abort();
	      return true;
	    }
	}
    }
  return false;
}

/// Test if a given value supposed to be inside an insertion range
/// represents the end of the range.
///
/// @param value the value to test for.
///
/// @return true iff @p value represents the end of the insertion
/// range.
bool
type_suppression::offset_range::boundary_value_is_end(uint64_t value)
{
  return value == std::numeric_limits<uint64_t>::max();
}

/// Test if an instance of @ref suppression is an instance of @ref
/// type_suppression.
///
/// @param suppr the instance of @ref suppression to test for.
///
/// @return if @p suppr is an instance of @ref type_suppression, then
/// return the sub-object of the @p suppr of type @ref
/// type_suppression, otherwise return a nil pointer.
type_suppression_sptr
is_type_suppression(suppression_sptr suppr)
{return dynamic_pointer_cast<type_suppression>(suppr);}

// </type_suppression stuff>

/// Parse the value of the "type_kind" property in the "suppress_type"
/// section.
///
/// @param input the input string representing the value of the
/// "type_kind" property.
///
/// @return the @ref type_kind enumerator parsed.
static type_suppression::type_kind
read_type_kind_string(const string& input)
{
  if (input == "class")
    return type_suppression::CLASS_TYPE_KIND;
  else if (input == "struct")
    return type_suppression::STRUCT_TYPE_KIND;
  else if (input == "union")
    return type_suppression::UNION_TYPE_KIND;
  else if (input == "enum")
    return type_suppression::ENUM_TYPE_KIND;
  else if (input == "array")
    return type_suppression::ARRAY_TYPE_KIND;
  else if (input == "typedef")
    return type_suppression::TYPEDEF_TYPE_KIND;
  else if (input == "builtin")
    return type_suppression::BUILTIN_TYPE_KIND;
  else
    return type_suppression::UNKNOWN_TYPE_KIND;
}

/// Parse the value of the "accessed_through" property in the
/// "suppress_type" section.
///
/// @param input the input string representing the value of the
/// "accessed_through" property.
///
/// @return the @ref type_suppression::reach_kind enumerator parsed.
static type_suppression::reach_kind
read_suppression_reach_kind(const string& input)
{
  if (input == "direct")
    return type_suppression::DIRECT_REACH_KIND;
  else if (input == "pointer")
    return type_suppression::POINTER_REACH_KIND;
  else if (input == "reference")
    return type_suppression::REFERENCE_REACH_KIND;
  else if (input == "reference-or-pointer")
    return type_suppression::REFERENCE_OR_POINTER_REACH_KIND;
  else
    return type_suppression::DIRECT_REACH_KIND;
}

/// Read a type suppression from an instance of ini::config::section
/// and build a @ref type_suppression as a result.
///
/// @param section the section of the ini config to read.
///
/// @param suppr the @ref suppression to assign to.
///
/// @return whether the parse was successful.
static bool
read_type_suppression(const ini::config::section& section,
		      suppression_sptr& suppr)
{
  static const char *const sufficient_props[] = {
    "file_name_regexp",
    "file_name_not_regexp",
    "soname_regexp",
    "soname_not_regexp",
    "name",
    "name_regexp",
    "name_not_regexp",
    "type_kind",
    "source_location_not_in",
    "source_location_not_regexp",
  };
  if (!check_sufficient_props(sufficient_props,
			      sizeof(sufficient_props)/sizeof(char*),
			      section))
    return false;

  ini::property_sptr srcloc_not_in_prop =
    section.find_property("source_location_not_in");
  unordered_set<string> srcloc_not_in;
  if (srcloc_not_in_prop)
    {
      if (ini::simple_property_sptr p = is_simple_property(srcloc_not_in_prop))
	srcloc_not_in.insert(p->get_value()->as_string());
      else
	{
	  ini::list_property_sptr list_property =
	    is_list_property(srcloc_not_in_prop);
	  if (list_property)
	    {
	      vector<string>::const_iterator i;
	      for (i = list_property->get_value()->get_content().begin();
		   i != list_property->get_value()->get_content().end();
		   ++i)
		srcloc_not_in.insert(*i);
	    }
	}
    }

  // Support has_data_member_inserted_at
  vector<type_suppression::offset_range_sptr> insert_ranges;
  if (ini::simple_property_sptr prop =
      is_simple_property(section.find_property("has_data_member_inserted_at")))
    {
      // So this property has the form:
      //   has_data_member_inserted_at = <one-string-property-value>
      string ins_point = prop->get_value()->as_string();
      type_suppression::offset_sptr begin, end;
      if (ins_point == "end")
	begin = type_suppression::offset::create_integer_offset(-1);
      else if (isdigit(ins_point[0]))
	begin = type_suppression::offset::create_integer_offset
	  (atoi(ins_point.c_str()));
      else if (type_suppression::offset_sptr expr =
	       type_suppression::offset::create_fn_call_expr_offset(ini::read_function_call_expr(ins_point)))
	begin = expr;
      else
	return false;

      end = type_suppression::offset::create_integer_offset(-1);
      type_suppression::offset_range_sptr insert_range
	(new type_suppression::offset_range(begin, end));
	  insert_ranges.push_back(insert_range);
    }

  // Support has_data_member_inserted_between
  if (ini::tuple_property_sptr prop =
      is_tuple_property(section.find_property
			("has_data_member_inserted_between")))
    {
      // ensures that this has the form:
      //  has_data_member_inserted_between = {0 , end};
      // and not (for instance):
      //  has_data_member_inserted_between = {{0 , end}, {1, foo}}
      //
      //  This means that the tuple_property_value contains just one
      //  value, which is a list_property that itself contains 2
      //  values.
      type_suppression::offset_sptr begin, end;
      ini::tuple_property_value_sptr v = prop->get_value();
      if (v
	  && v->get_value_items().size() == 1
	  && is_list_property_value(v->get_value_items()[0])
	  && is_list_property_value(v->get_value_items()[0])->get_content().size() == 2)
	{
	  ini::list_property_value_sptr val =
	    is_list_property_value(v->get_value_items()[0]);
	  ABG_ASSERT(val);
	  string str = val->get_content()[0];
	  if (str == "end")
	    begin =
	      type_suppression::offset::create_integer_offset(-1);
	  else if (isdigit(str[0]))
	    begin = type_suppression::offset::create_integer_offset
	      (atoi(str.c_str()));
	  else if (type_suppression::offset_sptr expr =
		   type_suppression::offset::create_fn_call_expr_offset(ini::read_function_call_expr(str)))
	    begin = expr;
	  else
	    return false;

	  str = val->get_content()[1];
	  if (str == "end")
	    end =
	      type_suppression::offset::create_integer_offset(-1);
	  else if (isdigit(str[0]))
	    end = type_suppression::offset::create_integer_offset
	      (atoi(str.c_str()));
	  else if (type_suppression::offset_sptr expr =
		   type_suppression::offset::create_fn_call_expr_offset(ini::read_function_call_expr(str)))
	    end = expr;
	  else
	    return false;

	  type_suppression::offset_range_sptr insert_range
	    (new type_suppression::offset_range(begin, end));
	  insert_ranges.push_back(insert_range);
	}
      else
	// the 'has_data_member_inserted_between' property has a wrong
	// value type, so let's discard the endire [suppress_type]
	// section.
	return false;
    }

  // Support has_data_members_inserted_between
  // The syntax looks like:
  //
  //    has_data_members_inserted_between = {{8, 24}, {32, 64}, {128, end}}
  //
  // So we expect a tuple property, with potentially several pairs (as
  // part of the value); each pair designating a range.  Note that
  // each pair (range) is a list property value.
  if (ini::tuple_property_sptr prop =
      is_tuple_property(section.find_property
			("has_data_members_inserted_between")))
    {
      for (vector<ini::property_value_sptr>::const_iterator i =
	     prop->get_value()->get_value_items().begin();
	   i != prop->get_value()->get_value_items().end();
	   ++i)
	{
	  ini::tuple_property_value_sptr tuple_value =
	    is_tuple_property_value(*i);
	  if (!tuple_value
	      || tuple_value->get_value_items().size() != 1
	      || !is_list_property_value(tuple_value->get_value_items()[0]))
	    return false;
	  ini::list_property_value_sptr list_value =
	    is_list_property_value(tuple_value->get_value_items()[0]);
	  if (list_value->get_content().size() != 2)
	    return false;

	  type_suppression::offset_sptr begin, end;
	  string str = list_value->get_content()[0];
	  if (str == "end")
	    begin =
	      type_suppression::offset::create_integer_offset(-1);
	  else if (isdigit(str[0]))
	    begin =
	      type_suppression::offset::create_integer_offset
	      (atoi(str.c_str()));
	  else if (type_suppression::offset_sptr expr =
		   type_suppression::offset::create_fn_call_expr_offset(ini::read_function_call_expr(str)))
	    begin = expr;
	  else
	    return false;

	  str = list_value->get_content()[1];
	  if (str == "end")
	    end =
	      type_suppression::offset::create_integer_offset(-1);
	  else if (isdigit(str[0]))
	    end = type_suppression::offset::create_integer_offset
	      (atoi(str.c_str()));
	  else if (type_suppression::offset_sptr expr =
		   type_suppression::offset::create_fn_call_expr_offset(ini::read_function_call_expr(str)))
	    end = expr;
	  else
	    return false;

	  type_suppression::offset_range_sptr insert_range
	    (new type_suppression::offset_range(begin, end));
	  insert_ranges.push_back(insert_range);
	}
    }

  /// Support 'changed_enumerators = foo, bar, baz'
  ///
  /// Note that this constraint is valid only if we have:
  ///   'type_kind = enum'.
  ///
  /// If the current type is an enum and if it carries changed
  /// enumerators listed in the changed_enumerators property value
  /// then it should be suppressed.

  ini::property_sptr changed_enumerators_prop =
    section.find_property("changed_enumerators");

  vector<string> changed_enumerator_names;
  if (changed_enumerators_prop)
    {
      if (ini::list_property_sptr p =
	  is_list_property(changed_enumerators_prop))
	changed_enumerator_names =
	  p->get_value()->get_content();
      else if (ini::simple_property_sptr p =
	       is_simple_property(changed_enumerators_prop))
	changed_enumerator_names.push_back(p->get_value()->as_string());
    }

  type_suppression result;

  if (ini::property_sptr prop = section.find_property("label"))
    {
      std::string str;
      if (read(prop, str))
	result.set_label(str);
    }

  if (ini::property_sptr prop = section.find_property("name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_type_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_type_name(str);
    }

  if (ini::property_sptr prop = section.find_property("type_kind"))
    {
      std::string str;
      if (read(prop, str))
	{
	  type_suppression::type_kind kind = read_type_kind_string(str);
	  result.set_consider_type_kind(true);
	  result.set_type_kind(kind);
	}
    }

  if (ini::property_sptr prop = section.find_property("accessed_through"))
    {
      std::string str;
      if (read(prop, str))
	{
	  type_suppression::reach_kind kind = read_suppression_reach_kind(str);
	  result.set_consider_reach_kind(true);
	  result.set_reach_kind(kind);
	}
    }

  if (!insert_ranges.empty())
    result.set_data_member_insertion_ranges(insert_ranges);

  if (ini::property_sptr prop = section.find_property("name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_type_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("file_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("file_name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_not_regex(regex);
    }

  if (!srcloc_not_in.empty())
    result.set_source_locations_to_keep(srcloc_not_in);

  if (ini::property_sptr prop = section.find_property("source_location_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_source_location_to_keep_regex(regex);
    }

  ini::property_sptr drop_prop = section.find_property("drop_artifact");
  if (!drop_prop)
    drop_prop = section.find_property("drop");
  if (drop_prop)
    {
      bool b;
      if (read(drop_prop, b))
	result.set_drops_artifact_from_ir(b);
    }

  if (result.get_drops_artifact_from_ir()
      && !result.get_type_name_regex()
      && result.get_type_name().empty()
      && !result.get_source_location_to_keep_regex()
      && result.get_source_locations_to_keep().empty())
    {
      // TODO: maybe emit warning about 'drop' directive being ignored
      result.set_drops_artifact_from_ir(false);
    }

  if (result.get_type_kind() == type_suppression::ENUM_TYPE_KIND
      && !changed_enumerator_names.empty())
    result.set_changed_enumerator_names(changed_enumerator_names);

  suppr.reset(new type_suppression(result));
  return true;
}

// <function_suppression stuff>

/// Constructor for the @ref the function_suppression::parameter_spec
/// type.
///
/// Note that at evaluation time, the parameter @tn_regex is taken
/// into account only if the parameter @p tn is empty.
///
/// @param i the index of the parameter designated by this specification.
///
/// @param tn the type name of the parameter designated by this specification.
///
/// @param tn_regex a regular expression that defines a set of type
/// names for the parameter designated by this specification, or a
/// null pointer to omit this.
function_suppression::parameter_spec::parameter_spec(size_t i,
						     const string& tn,
						     const regex_t_sptr& tn_regex)
  : priv_(new priv(i, tn, tn_regex))
{}

/// Getter for the index of the parameter designated by this
/// specification.
///
/// @return the index of the parameter designated by this
/// specification.
size_t
function_suppression::parameter_spec::get_index() const
{return priv_->index_;}

/// Setter for the index of the parameter designated by this
/// specification.
///
/// @param i the new index to set.
void
function_suppression::parameter_spec::set_index(size_t i)
{priv_->index_ = i;}

/// Getter for the type name of the parameter designated by this specification.
///
/// @return the type name of the parameter.
const string&
function_suppression::parameter_spec::get_parameter_type_name() const
{return priv_->type_name_;}

/// Setter for the type name of the parameter designated by this
/// specification.
///
/// @param tn new parameter type name to set.
void
function_suppression::parameter_spec::set_parameter_type_name(const string& tn)
{priv_->type_name_ = tn;}

/// Getter for the regular expression that defines a set of type names
/// for the parameter designated by this specification.
///
/// Note that at evaluation time, this regular expression is taken in
/// account only if the name of the parameter as returned by
/// function_suppression::parameter_spec::get_parameter_type_name() is
/// empty.
///
/// @return the regular expression, or a null pointer if unset.
const regex_t_sptr&
function_suppression::parameter_spec::get_parameter_type_name_regex() const
{return priv_->type_name_regex_;}

/// Setter for the regular expression that defines a set of type names
/// for the parameter designated by this specification.
///
/// Note that at evaluation time, this regular expression is taken in
/// account only if the name of the parameter as returned by
/// function_suppression::parameter_spec::get_parameter_type_name() is
/// empty.
///
/// @param type_name_regex the new type name regular expression to
/// set, or a null pointer to unset this.
void
function_suppression::parameter_spec::set_parameter_type_name_regex
(const regex_t_sptr& type_name_regex)
{priv_->type_name_regex_ = type_name_regex;}

/// Default constructor for the @ref function_suppression type.
///
/// It defines no suppression for now.  Suppressions have to be
/// specified by using the various accessors of the @ref
/// function_suppression type.
function_suppression::function_suppression()
  : suppression_base(), priv_(new priv)
{}

function_suppression::~function_suppression()
{}

/// Parses a string containing the content of the "change-kind"
/// property and returns the an instance of @ref
/// function_suppression::change_kind as a result.
///
/// @param s the string to parse.
///
/// @return the resulting @ref function_suppression::change_kind.
function_suppression::change_kind
function_suppression::parse_change_kind(const string& s)
{
  if (s == "function-subtype-change")
    return FUNCTION_SUBTYPE_CHANGE_KIND;
  else if (s == "added-function")
    return ADDED_FUNCTION_CHANGE_KIND;
  else if (s == "deleted-function")
    return DELETED_FUNCTION_CHANGE_KIND;
  else if (s == "all")
    return ALL_CHANGE_KIND;
  else
    return UNDEFINED_CHANGE_KIND;
}

/// Getter of the "change-kind" property.
///
/// @param returnthe "change-kind" property.
function_suppression::change_kind
function_suppression::get_change_kind() const
{return priv_->change_kind_;}

/// Setter of the "change-kind" property.
///
/// @param k the new value of the change_kind property.
void
function_suppression::set_change_kind(change_kind k)
{priv_->change_kind_ = k;}

/// Getter for the name of the function the user wants the current
/// specification to designate.  This might be empty, in which case
/// it's ignored at evaluation time.
///
/// @return the name of the function.
const string&
function_suppression::get_name() const
{return priv_->name_;}

/// Setter for the name of the function the user wants the current
/// specification to designate.  This might be empty, in which case
/// it's ignored at evaluation time.
///
/// @param n the new function name to set.
void
function_suppression::set_name(const string& n)
{priv_->name_ = n;}

/// Getter for a regular expression for a family of names of functions
/// the user wants the current specification to designate.
///
/// If the name as returned by function_suppression::get_name() is not
/// empty, then this property is ignored at specification evaluation
/// time.
///
/// @return the regular expression for the possible names of the
/// function(s), or a null pointer if unset.
const regex_t_sptr&
function_suppression::get_name_regex() const
{return priv_->name_regex_;}

/// Setter for a regular expression for a family of names of functions
/// the user wants the current specification to designate.
///
/// If the name as returned by function_suppression::get_name() is not
/// empty, then this property is ignored at specification evaluation
/// time.
///
/// @param r the new the regular expression for the possible names of
/// the function(s).
void
function_suppression::set_name_regex(const regex_t_sptr& r)
{priv_->name_regex_ = r;}

/// Getter for a regular expression of a family of names of functions
/// the user wants the current specification to designate the negation
/// of.
///
/// @return the regular expression for the possible names of the
/// function(s), or a null pointer if unset.
const regex_t_sptr&
function_suppression::get_name_not_regex() const
{return priv_->name_not_regex_;}

/// Setter for a regular expression for a family of names of functions
/// the user wants the current specification to designate the negation
/// of.
///
/// @param r the new the regular expression for the possible names of
/// the function(s).
void
function_suppression::set_name_not_regex(const regex_t_sptr& r)
{priv_->name_not_regex_ = r;}

/// Getter for the name of the return type of the function the user
/// wants this specification to designate.  This property might be
/// empty, in which case it's ignored at evaluation time.
///
/// @return the name of the return type of the function.
const string&
function_suppression::get_return_type_name() const
{return priv_->return_type_name_;}

/// Setter for the name of the return type of the function the user
/// wants this specification to designate.  This property might be
/// empty, in which case it's ignored at evaluation time.
///
/// @param tr the new name of the return type of the function to set.
void
function_suppression::set_return_type_name(const string& tr)
{priv_->return_type_name_ = tr;}

/// Getter for a regular expression for a family of return type names
/// for functions the user wants the current specification to
/// designate.
///
/// If the name of the return type of the function as returned by
/// function_suppression::get_return_type_name() is not empty, then
/// this property is ignored at specification evaluation time.  This
/// property might be empty, in which case it's ignored at evaluation
/// time.
///
/// @return the regular expression for the possible names of the
/// return types of the function(s), or a null pointer if unset.
const regex_t_sptr&
function_suppression::get_return_type_regex() const
{return priv_->return_type_regex_;}

/// Setter for a regular expression for a family of return type names
/// for functions the user wants the current specification to
/// designate.
///
/// If the name of the return type of the function as returned by
/// function_suppression::get_return_type_name() is not empty, then
/// this property is ignored at specification evaluation time.  This
/// property might be empty, in which case it's ignored at evaluation
/// time.
///
/// @param r the new regular expression for the possible names of the
/// return types of the function(s) to set.
void
function_suppression::set_return_type_regex(const regex_t_sptr& r)
{priv_->return_type_regex_ = r;}

/// Getter for a vector of parameter specifications to specify
/// properties of the parameters of the functions the user wants this
/// specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return the specifications of the parameters of the function(s).
const function_suppression::parameter_specs_type&
function_suppression::get_parameter_specs() const
{return priv_->parm_specs_;}

/// Setter for a vector of parameter specifications to specify
/// properties of the parameters of the functions the user wants this
/// specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @param p the new specifications of the parameters of the
/// function(s) to set.
void
function_suppression::set_parameter_specs(parameter_specs_type& p)
{priv_->parm_specs_ = p;}

/// Append a specification of a parameter of the function specification.
///
/// @param p the parameter specification to add.
void
function_suppression::append_parameter_specs(const parameter_spec_sptr p)
{priv_->parm_specs_.push_back(p);}

/// Getter for the name of symbol of the function the user wants this
/// specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return name of the symbol of the function.
const string&
function_suppression::get_symbol_name() const
{return priv_->symbol_name_;}

/// Setter for the name of symbol of the function the user wants this
/// specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return name of the symbol of the function.
void
function_suppression::set_symbol_name(const string& n)
{priv_->symbol_name_ = n;}

/// Getter for a regular expression for a family of names of symbols
/// of functions the user wants this specification to designate.
///
/// If the symbol name as returned by
/// function_suppression::get_symbol_name() is not empty, then this
/// property is ignored at specification evaluation time.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return the regular expression for a family of names of symbols of
/// functions to designate, or a null pointer if unset.
const regex_t_sptr&
function_suppression::get_symbol_name_regex() const
{return priv_->symbol_name_regex_;}

/// Setter for a regular expression for a family of names of symbols
/// of functions the user wants this specification to designate.
///
/// If the symbol name as returned by
/// function_suppression::get_symbol_name() is not empty, then this
/// property is ignored at specification evaluation time.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @param r the new regular expression for a family of names of
/// symbols of functions to set.
void
function_suppression::set_symbol_name_regex(const regex_t_sptr& r)
{priv_->symbol_name_regex_ = r;}

/// Getter for a regular expression for a family of names of symbols
/// of functions the user wants this specification to designate.
///
/// If a symbol name is matched by this regular expression, then the
/// suppression specification will *NOT* suppress the symbol.
///
/// If the symbol name as returned by
/// function_suppression::get_symbol_name() is not empty, then this
/// property is ignored at specification evaluation time.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return the regular expression for a family of names of symbols
/// that is to be *NOT* suppressed by this suppression specification,
/// or a null pointer if unset.
const regex_t_sptr&
function_suppression::get_symbol_name_not_regex() const
{return priv_->symbol_name_not_regex_;}

/// Setter for a regular expression for a family of names of symbols
/// of functions the user wants this specification to designate.
///
/// If a symbol name is matched by this regular expression, then the
/// suppression specification will *NOT* suppress the symbol.
///
/// If the symbol name as returned by
/// function_suppression::get_symbol_name() is not empty, then this
/// property is ignored at specification evaluation time.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @param the new regular expression for a family of names of
/// symbols that is to be *NOT* suppressed by this suppression
/// specification.
void
function_suppression::set_symbol_name_not_regex(const regex_t_sptr& r)
{priv_->symbol_name_not_regex_ = r;}

/// Getter for the name of the version of the symbol of the function
/// the user wants this specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return the symbol version of the function.
const string&
function_suppression::get_symbol_version() const
{return priv_->symbol_version_;}

/// Setter for the name of the version of the symbol of the function
/// the user wants this specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @param v the new symbol version of the function.
void
function_suppression::set_symbol_version(const string& v)
{priv_->symbol_version_ = v;}

/// Getter for a regular expression for a family of versions of
/// symbols of functions the user wants the current specification to
/// designate.
///
/// If the symbol version as returned by
/// function_suppression::get_symbol_version() is non empty, then this
/// property is ignored.  This property might be empty, in which case
/// it's ignored at evaluation time.
///
/// @return the regular expression for the versions of symbols of
/// functions to designate, or a null pointer if unset.
const regex_t_sptr&
function_suppression::get_symbol_version_regex() const
{return priv_->symbol_version_regex_;}

/// Setter for a regular expression for a family of versions of
/// symbols of functions the user wants the current specification to
/// designate.
///
/// If the symbol version as returned by
/// function_suppression::get_symbol_version() is non empty, then this
/// property is ignored.  This property might be empty, in which case
/// it's ignored at evaluation time.
///
/// @param the new regular expression for the versions of symbols of
/// functions to designate.
void
function_suppression::set_symbol_version_regex(const regex_t_sptr& r)
{priv_->symbol_version_regex_ = r;}

/// Getter for the "allow_other_aliases" property of the function
/// suppression specification.
///
/// @return the value of the "allow_other_aliases" property.
bool
function_suppression::get_allow_other_aliases() const
{return priv_->allow_other_aliases_;}

/// Setter for the "allow_other_aliases" property of the function
/// suppression specification.
///
/// @param f the new value of the property.
void
function_suppression::set_allow_other_aliases(bool f)
{priv_->allow_other_aliases_ = f;}

/// Evaluate this suppression specification on a given diff node and
/// say if the diff node should be suppressed or not.
///
/// @param diff the diff node to evaluate this suppression
/// specification against.
///
/// @return true if @p diff should be suppressed.
bool
function_suppression::suppresses_diff(const diff* diff) const
{
  const function_decl_diff* d = is_function_decl_diff(diff);
  if (!d)
    return false;

  function_decl_sptr ff = is_function_decl(d->first_function_decl()),
    sf = is_function_decl(d->second_function_decl());
  ABG_ASSERT(ff && sf);

  return (suppresses_function(ff,
			      FUNCTION_SUBTYPE_CHANGE_KIND,
			      diff->context())
	  || suppresses_function(sf,
				 FUNCTION_SUBTYPE_CHANGE_KIND,
				 diff->context()));
}

/// Evaluate the current function suppression specification on a given
/// @ref function_decl and say if a report about a change involving this
/// @ref function_decl should be suppressed or not.
///
/// @param fn the @ref function_decl to evaluate this suppression
/// specification against.
///
/// @param k the kind of function change @p fn is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the function @p
/// fn should be suppressed.
bool
function_suppression::suppresses_function(const function_decl* fn,
					  change_kind k,
					  const diff_context_sptr ctxt) const
{
  if (!(get_change_kind() & k))
    return false;

  // Check if the name and soname of the binaries match the current
  // suppr spec
  if (ctxt)
    {
      // Check if the name of the binaries match the current suppr spec
      if (!names_of_binaries_match(*this, *ctxt))
	if (has_file_name_related_property())
	  return false;

      // Check if the soname of the binaries match the current suppr spec
      if (!sonames_of_binaries_match(*this, *ctxt))
	if (has_soname_related_property())
	  return false;
    }

  string fname = fn->get_qualified_name();

  // Check if the "name" property matches.
  if (!get_name().empty())
    {
      if (get_name() != fn->get_qualified_name())
	return false;

      if (get_allow_other_aliases()
	  && fn->get_symbol()
	  && fn->get_symbol()->get_alias_from_name(fname))
	{
	  // So we are in a case of a languages in which the symbol
	  // name is the same as the function name and we want to
	  // allow the removal of change reports on an aliased
	  // function only if the suppression condition matches the
	  // names of all aliases.
	  string symbol_name;
	  elf_symbol_sptr sym = fn->get_symbol();
	  ABG_ASSERT(sym);
	  symbol_name = sym->get_name();
	  if (sym->has_aliases() && sym->get_alias_from_name(fname))
	    {
	      for (elf_symbol_sptr a = sym->get_next_alias();
		   a && !a->is_main_symbol();
		   a = a->get_next_alias())
		if (a->get_name() != symbol_name)
		  // There is an alias which name is different from
		  // the function (symbol) name given in the
		  // suppression condition.
		  return false;
	    }
	}
    }

  // check if the "name_regexp" property matches.
  const regex_t_sptr& name_regex = get_name_regex();
  if (name_regex)
    {
      if (!regex::match(name_regex, fname))
	return false;

      if (get_allow_other_aliases()
	  && fn->get_symbol()
	  && fn->get_symbol()->get_alias_from_name(fname))
	{
	  // So we are in a case of a languages in which the symbol
	  // name is the same as the function name and we want to
	  // allow the removal of change reports on an aliased
	  // function only if the suppression condition matches *all*
	  // the aliases.
	  string symbol_name;
	  elf_symbol_sptr sym = fn->get_symbol();
	  ABG_ASSERT(sym);
	  symbol_name = sym->get_name();
	  if (sym->has_aliases())
	    {
	      for (elf_symbol_sptr a = sym->get_next_alias();
		   a && !a->is_main_symbol();
		   a = a->get_next_alias())
		if (!regex::match(name_regex, a->get_name()))
		  return false;
	    }
	}
    }

  // check if the "name_not_regexp" property matches.
  const regex_t_sptr& name_not_regex = get_name_not_regex();
  if (name_not_regex)
    {
      if (regex::match(name_not_regex, fname))
	return false;

      if (get_allow_other_aliases()
	  && fn->get_symbol()
	  && fn->get_symbol()->get_alias_from_name(fname))
	{
	  // So we are in a case of a languages in which the symbol
	  // name is the same as the function name and we want to
	  // allow the removal of change reports on an aliased
	  // function only if the suppression condition matches *all*
	  // the aliases.
	  string symbol_name;
	  elf_symbol_sptr sym = fn->get_symbol();
	  ABG_ASSERT(sym);
	  symbol_name = sym->get_name();
	  if (sym->has_aliases())
	    {
	      for (elf_symbol_sptr a = sym->get_next_alias();
		   a && !a->is_main_symbol();
		   a = a->get_next_alias())
		if (regex::match(name_regex, a->get_name()))
		  return false;
	    }
	}
    }

  // Check if the "return_type_name" or "return_type_regexp"
  // properties matches.

  string fn_return_type_name = fn->get_type()->get_return_type()
    ? static_cast<string>
    ((get_type_declaration(fn->get_type()->get_return_type())
      ->get_qualified_name()))
    : "";

  if (!get_return_type_name().empty())
    {
      if (fn_return_type_name != get_return_type_name())
	return false;
    }
  else if (const regex_t_sptr& regex = get_return_type_regex())
    {
      if (!regex::match(regex, fn_return_type_name))
	return false;
    }

  // Check if the "symbol_name", "symbol_name_regexp", and
  // "symbol_name_not_regexp" properties match.
  string fn_sym_name, fn_sym_version;
  elf_symbol_sptr sym = fn->get_symbol();
  if (sym)
    {
      fn_sym_name = sym->get_name();
      fn_sym_version = sym->get_version().str();
    }

  if (sym && !get_symbol_name().empty())
    {
      if (fn_sym_name != get_symbol_name())
	return false;

      if (sym && get_allow_other_aliases())
	{
	  // In this case, we want to allow the suppression of change
	  // reports about an aliased symbol only if the suppression
	  // condition matches the name of all aliases.
	  if (sym->has_aliases())
	    {
	      for (elf_symbol_sptr a = sym->get_next_alias();
		   a && !a->is_main_symbol();
		   a = a->get_next_alias())
		if (a->get_name() != fn_sym_name)
		  return false;
	    }
	}
    }
  else if (sym)
    {
      const regex_t_sptr& symbol_name_regex = get_symbol_name_regex();
      const regex_t_sptr& symbol_name_not_regex = get_symbol_name_not_regex();

      if (symbol_name_regex)
	if (!regex::match(symbol_name_regex, fn_sym_name))
	  return false;
      if (symbol_name_not_regex)
	if (regex::match(symbol_name_not_regex, fn_sym_name))
	  return false;

      if (get_allow_other_aliases())
	{
	  // In this case, we want to allow the suppression of change
	  // reports about an aliased symbol only if the suppression
	  // condition matches the name of all aliases.
	  if (sym->has_aliases())
	    {
	      for (elf_symbol_sptr a = sym->get_next_alias();
		   a && !a->is_main_symbol();
		   a = a->get_next_alias())
		{
		  const std::string& alias_name = a->get_name();
		  if (symbol_name_regex)
		    if (!regex::match(symbol_name_regex, alias_name))
		      return false;
		  if (symbol_name_not_regex)
		    if (regex::match(symbol_name_not_regex, alias_name))
		      return false;
		}
	    }
	}
    }

  // Check if the "symbol_version" and "symbol_version_regexp"
  // properties match.
  if (sym)
    {
      if (!get_symbol_version().empty())
	{
	  if (fn_sym_version != get_symbol_version())
	    return false;
	}
      else
	{
	  if (const regex_t_sptr& regex = get_symbol_version_regex())
	    if (!regex::match(regex, fn_sym_version))
	      return false;
	}
    }

  // Check the 'parameter' property.
  if (!get_parameter_specs().empty())
    {
      function_type_sptr fn_type = fn->get_type();
      type_base_sptr parm_type;

      for (parameter_specs_type::const_iterator p =
	     get_parameter_specs().begin();
	   p != get_parameter_specs().end();
	   ++p)
	{
	  size_t index = (*p)->get_index();
	  function_decl::parameter_sptr fn_parm =
	    fn_type->get_parm_at_index_from_first_non_implicit_parm(index);
	  if (!fn_parm)
	    return false;

	  string fn_parm_type_qualified_name;
	  if (fn_parm)
	    {
	      parm_type = fn_parm->get_type();
	      fn_parm_type_qualified_name =
		get_type_declaration(parm_type)->get_qualified_name();
	    }

	  const string& tn = (*p)->get_parameter_type_name();
	  if (!tn.empty())
	    {
	      if (tn != fn_parm_type_qualified_name)
		return false;
	    }
	  else if (const regex_t_sptr& regex =
		     (*p)->get_parameter_type_name_regex())
	    {
	      if (!regex::match(regex, fn_parm_type_qualified_name))
		return false;
	    }
	}
    }

  return true;
}

/// Evaluate the current function suppression specification on a given
/// @ref function_decl and say if a report about a change involving this
/// @ref function_decl should be suppressed or not.
///
/// @param fn the @ref function_decl to evaluate this suppression
/// specification against.
///
/// @param k the kind of function change @p fn is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the function @p
/// fn should be suppressed.
bool
function_suppression::suppresses_function(const function_decl_sptr fn,
					  change_kind k,
					  const diff_context_sptr ctxt) const
{return suppresses_function(fn.get(), k, ctxt);}

/// Evaluate the current function suppression specification on a given
/// @ref elf_symbol and say if a report about a change involving this
/// @ref elf_symbol should be suppressed or not.
///
/// @param sym the @ref elf_symbol to evaluate this suppression
/// specification against.
///
/// @param k the kind of function change @p sym is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the symbol @p
/// sym should be suppressed.
bool
function_suppression::suppresses_function_symbol(const elf_symbol* sym,
						 change_kind k,
						 const diff_context_sptr ctxt)
{
  if (!sym)
    return false;

  if (!(get_change_kind() & k))
    return false;

  if (!sym->is_function())
    return false;

  ABG_ASSERT(k & function_suppression::ADDED_FUNCTION_CHANGE_KIND
	 || k & function_suppression::DELETED_FUNCTION_CHANGE_KIND);

  // Check if the name and soname of the binaries match the current
  // suppr spect
  if (ctxt)
    {
      // Check if the name of the binaries match the current
      // suppr spect
      if (!names_of_binaries_match(*this, *ctxt))
	if (has_file_name_related_property())
	  return false;

      // Check if the soname of the binaries match the current
      // suppr spect
      if (!sonames_of_binaries_match(*this, *ctxt))
	if (has_soname_related_property())
	  return false;
    }

  string sym_name = sym->get_name(), sym_version = sym->get_version().str();
  bool no_symbol_name = false, no_symbol_version = false;

  // Consider the symbol name.
  if (!get_symbol_name().empty())
    {
      if (sym_name != get_symbol_name())
	return false;
    }
  else if (const regex_t_sptr& regex = get_symbol_name_regex())
    {
      if (!regex::match(regex, sym_name))
	return false;
    }
  else
    no_symbol_name = true;

  // Consider the symbol version
  if (!get_symbol_version().empty())
    {
      if (sym_version != get_symbol_version())
	return false;
    }
  else if (const regex_t_sptr& regex = get_symbol_version_regex())
    {
      if (!regex::match(regex, sym_version))
	return false;
    }
  else
    no_symbol_version = true;

  if (no_symbol_name && no_symbol_version)
    return false;

  return true;
}

/// Evaluate the current function suppression specification on a given
/// @ref elf_symbol and say if a report about a change involving this
/// @ref elf_symbol should be suppressed or not.
///
/// @param sym the @ref elf_symbol to evaluate this suppression
/// specification against.
///
/// @param k the kind of function change @p sym is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the symbol @p
/// sym should be suppressed.
bool
function_suppression::suppresses_function_symbol(const elf_symbol_sptr sym,
						 change_kind k,
						 const diff_context_sptr ctxt)
{return suppresses_function_symbol(sym.get(), k, ctxt);}

/// Test if an instance of @ref suppression is an instance of @ref
/// function_suppression.
///
/// @param suppr the instance of @ref suppression to test for.
///
/// @return if @p suppr is an instance of @ref function_suppression, then
/// return the sub-object of the @p suppr of type @ref
/// function_suppression, otherwise return a nil pointer.
function_suppression_sptr
is_function_suppression(const suppression_sptr suppr)
{return dynamic_pointer_cast<function_suppression>(suppr);}

/// The bitwise 'and' operator for the enum @ref
/// function_suppression::change_kind.
///
/// @param l the first operand of the 'and' operator.
///
/// @param r the second operand of the 'and' operator.
///
/// @return the result of 'and' operation on @p l and @p r.
function_suppression::change_kind
operator&(function_suppression::change_kind l,
	  function_suppression::change_kind r)
{
  return static_cast<function_suppression::change_kind>
    (static_cast<unsigned>(l) & static_cast<unsigned>(r));
}

/// The bitwise 'or' operator for the enum @ref
/// function_suppression::change_kind.
///
/// @param l the first operand of the 'or' operator.
///
/// @param r the second operand of the 'or' operator.
///
/// @return the result of 'or' operation on @p l and @p r.
function_suppression::change_kind
operator|(function_suppression::change_kind l,
	  function_suppression::change_kind r)
{
    return static_cast<function_suppression::change_kind>
      (static_cast<unsigned>(l) | static_cast<unsigned>(r));
}

  /// Test whether if a given function suppression matches a function
  /// designated by a regular expression that describes its name.
  ///
  /// @param s the suppression specification to evaluate to see if it
  /// matches a given function name.
  ///
  /// @param fn_name the name of the function of interest.  Note that
  /// this name must be *non* qualified.
  ///
  /// @return true iff the suppression specification @p s matches the
  /// function whose name is @p fn_name.
bool
suppression_matches_function_name(const suppr::function_suppression& s,
				  const string& fn_name)
{
  if (const regex_t_sptr& regexp = s.get_name_regex())
    {
      if (!regex::match(regexp, fn_name))
	return false;
    }
  else if (const regex_t_sptr& regexp = s.get_name_not_regex())
    {
      if (regex::match(regexp, fn_name))
	return false;
    }
  else if (s.get_name().empty())
    return false;
  else // if (!s.get_name().empty())
    {
      if (s.get_name() != fn_name)
	return false;
    }

  return true;
}

/// Test whether if a given function suppression matches a function
/// designated by a regular expression that describes its linkage
/// name (symbol name).
///
/// @param s the suppression specification to evaluate to see if it
/// matches a given function linkage name
///
/// @param fn_linkage_name the linkage name of the function of interest.
///
/// @return true iff the suppression specification @p s matches the
/// function whose linkage name is @p fn_linkage_name.
bool
suppression_matches_function_sym_name(const suppr::function_suppression& s,
				      const string& fn_linkage_name)
{
  if (const regex_t_sptr& regexp = s.get_symbol_name_regex())
    {
      if (!regex::match(regexp, fn_linkage_name))
	return false;
    }
  else if (const regex_t_sptr& regexp = s.get_symbol_name_not_regex())
    {
      if (regex::match(regexp, fn_linkage_name))
	return false;
    }
  else if (s.get_symbol_name().empty())
    return false;
  else // if (!s.get_symbol_name().empty())
    {
      if (s.get_symbol_name() != fn_linkage_name)
	return false;
    }

  return true;
}

/// Test if a variable suppression matches a variable denoted by its name.
///
/// @param s the variable suppression to consider.
///
/// @param var_name the name of the variable to consider.
///
/// @return true if the variable is matches by the suppression
/// specification.
bool
suppression_matches_variable_name(const suppr::variable_suppression& s,
				  const string& var_name)
{
  if (const regex_t_sptr& regexp = s.get_name_regex())
    {
      if (!regex::match(regexp, var_name))
	return false;
    }
  else if (const regex_t_sptr& regexp = s.get_name_not_regex())
    {
      if (regex::match(regexp, var_name))
	return false;
    }
  else if (s.get_name().empty())
    return false;
  else // if (!s.get_name().empty())
    {
      if (s.get_name() != var_name)
	return false;
    }

  return true;
}

/// Test if a variable suppression matches a variable denoted by its
/// symbol name.
///
/// @param s the variable suppression to consider.
///
/// @param var_linkage_name the name of the variable to consider.
///
/// @return true if the variable is matches by the suppression
/// specification.
bool
suppression_matches_variable_sym_name(const suppr::variable_suppression& s,
				      const string& var_linkage_name)
{
  if (const regex_t_sptr& regexp = s.get_symbol_name_regex())
    {
      if (!regex::match(regexp, var_linkage_name))
	return false;
    }
  else if (const regex_t_sptr& regexp = s.get_symbol_name_not_regex())
    {
      if (regex::match(regexp, var_linkage_name))
	return false;
    }
  else if (s.get_symbol_name().empty())
    return false;
  else // if (!s.get_symbol_name().empty())
    {
      if (s.get_symbol_name() != var_linkage_name)
	return false;
    }

  return true;
}

/// Test if a type suppression matches a type designated by its fully
/// qualified name.
///
/// @param s the type suppression to consider.
///
/// @param type_name the name of the type to consider.
///
/// @return true iff the suppression s matches the type denoted by
/// name @p type_name.
bool
suppression_matches_type(const suppr::type_suppression& s,
			 const string& type_name)
{
  if (const regex_t_sptr& regexp = s.get_type_name_regex())
    {
      if (!regex::match(regexp, type_name))
	return false;
    }
  else if (!s.get_type_name().empty())
    {
      if (s.get_type_name() != type_name)
	return false;
    }
  else
    return false;

  return true;
}

/// Parse a string containing a parameter spec, build an instance of
/// function_suppression::parameter_spec from it and return a pointer
/// to that object.
///
/// @return a shared pointer pointer to the newly built instance of
/// function_suppression::parameter_spec.  If the parameter
/// specification could not be parsed, return a nil object.
static function_suppression::parameter_spec_sptr
read_parameter_spec_from_string(const string& str)
{
  string::size_type cur = 0;
  function_suppression::parameter_spec_sptr result;

  // skip leading white spaces.
  for (; cur < str.size(); ++cur)
    if (!isspace(str[cur]))
      break;

  // look for the parameter index
  string index_str;
  if (str[cur] == '\'')
    {
      ++cur;
      for (; cur < str.size(); ++cur)
	if (!isdigit(str[cur]))
	  break;
	else
	  index_str += str[cur];
    }

  // skip white spaces.
  for (; cur < str.size(); ++cur)
    if (!isspace(str[cur]))
      break;

  bool is_regex = false;
  if (str[cur] == '/')
    {
      is_regex = true;
      ++cur;
    }

  // look for the type name (regex)
  string type_name;
  for (; cur < str.size(); ++cur)
    if (!isspace(str[cur]))
      {
	if (is_regex && str[cur] == '/')
	  break;
	type_name += str[cur];
      }

  if (is_regex && str[cur] == '/')
    ++cur;

  if (!index_str.empty() || !type_name.empty())
    {
      regex_t_sptr type_name_regex;
      if (is_regex)
	{
	  type_name_regex = regex::compile(type_name);
	  type_name.clear();
	}
      function_suppression::parameter_spec* p =
	new function_suppression::parameter_spec(atoi(index_str.c_str()),
						 type_name, type_name_regex);
      result.reset(p);
    }

  return result;
}

/// Read a function suppression from an instance of
/// ini::config::section and build a @ref function_suppression as a
/// result.
///
/// @param section the section of the ini config to read.
///
/// @param suppr the @ref suppression to assign to.
///
/// @return whether the parse was successful.
static bool
read_function_suppression(const ini::config::section& section,
			  suppression_sptr& suppr)
{
  static const char *const sufficient_props[] = {
    "label",
    "file_name_regexp",
    "file_name_not_regexp",
    "soname_regexp",
    "soname_not_regexp",
    "name",
    "name_regexp",
    "name_not_regexp",
    "parameter",
    "return_type_name",
    "return_type_regexp",
    "symbol_name",
    "symbol_name_regexp",
    "symbol_name_not_regexp",
    "symbol_version",
    "symbol_version_regexp",
  };
  if (!check_sufficient_props(sufficient_props,
			      sizeof(sufficient_props)/sizeof(char*),
			      section))
    return false;

  function_suppression::parameter_spec_sptr parm;
  function_suppression::parameter_specs_type parms;
  for (ini::config::properties_type::const_iterator p =
	 section.get_properties().begin();
       p != section.get_properties().end();
       ++p)
    if ((*p)->get_name() == "parameter")
      {
	ini::simple_property_sptr prop = is_simple_property(*p);
	ABG_ASSERT(prop);
	if ((parm = read_parameter_spec_from_string
	      (prop->get_value()->as_string())))
	  parms.push_back(parm);
      }

  function_suppression result;

  if (ini::property_sptr prop = section.find_property("label"))
    {
      std::string str;
      if (read(prop, str))
	result.set_label(str);
    }

  if (ini::property_sptr prop = section.find_property("name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_name(str);
    }

  if (ini::property_sptr prop = section.find_property("name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("return_type_name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_return_type_name(str);
    }

  if (ini::property_sptr prop = section.find_property("return_type_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_return_type_regex(regex);
    }

  result.set_parameter_specs(parms);

  if (ini::property_sptr prop = section.find_property("symbol_name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_symbol_name(str);
    }

  if (ini::property_sptr prop = section.find_property("symbol_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_symbol_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("symbol_version"))
    {
      std::string str;
      if (read(prop, str))
	result.set_symbol_version(str);
    }

  if (ini::property_sptr prop = section.find_property("symbol_version_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_symbol_version_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("change_kind"))
    {
      std::string str;
      if (read(prop, str))
	if (!str.empty())
	  result.set_change_kind(function_suppression::parse_change_kind(str));
    }

  if (ini::property_sptr prop = section.find_property("allow_other_aliases"))
    {
      bool b;
      if (read(prop, b))
	result.set_allow_other_aliases(b);
    }

  if (ini::property_sptr prop = section.find_property("name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("symbol_name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_symbol_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("file_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("file_name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_not_regex(regex);
    }

  ini::property_sptr drop_prop = section.find_property("drop_artifact");
  if (!drop_prop)
    drop_prop = section.find_property("drop");
  if (drop_prop)
    {
      bool b;
      if (read(drop_prop, b))
	result.set_drops_artifact_from_ir(b);
    }

  if (result.get_drops_artifact_from_ir()
      && result.get_name().empty()
      && !result.get_name_regex()
      && !result.get_name_not_regex()
      && result.get_symbol_name().empty()
      && !result.get_symbol_name_regex()
      && !result.get_symbol_name_not_regex())
    {
      // TODO: maybe emit warning about 'drop' directive being ignored
      result.set_drops_artifact_from_ir(false);
    }

  suppr.reset(new function_suppression(result));
  return true;
}

// </function_suppression stuff>

// <variable_suppression stuff>

/// Default constructor for the @ref variable_suppression type.
///
/// It defines no suppression for now.  Suppressions have to be
/// specified by using the various accessors of the @ref
/// variable_suppression type.
variable_suppression::variable_suppression()
  : suppression_base(), priv_(new priv)
{}

/// Virtual destructor for the @erf variable_suppression type.
/// variable_suppression type.
variable_suppression::~variable_suppression()
{}

/// Parses a string containing the content of the "change-kind"
/// property and returns the an instance of @ref
/// variable_suppression::change_kind as a result.
///
/// @param s the string to parse.
///
/// @return the resulting @ref variable_suppression::change_kind.
variable_suppression::change_kind
variable_suppression::parse_change_kind(const string& s)
{
  if (s == "variable-subtype-change")
    return VARIABLE_SUBTYPE_CHANGE_KIND;
  else if (s == "added-variable")
    return ADDED_VARIABLE_CHANGE_KIND;
  else if (s == "deleted-variable")
    return DELETED_VARIABLE_CHANGE_KIND;
  else if (s == "all")
    return ALL_CHANGE_KIND;
  else
    return UNDEFINED_CHANGE_KIND;
}

/// Getter of the "change_king" property.
///
/// @return the value of the "change_kind" property.
variable_suppression::change_kind
variable_suppression::get_change_kind() const
{return priv_->change_kind_;}

/// Setter of the "change_kind" property.
///
/// @param k the new value of of the change_kind.
void
variable_suppression::set_change_kind(change_kind k)
{priv_->change_kind_ = k;}

/// Getter for the name of the variable the user wants the current
/// specification to designate.  This property might be empty, in
/// which case it's ignored at evaluation time.
///
/// @return the name of the variable.
const string&
variable_suppression::get_name() const
{return priv_->name_;}

/// Setter for the name of the variable the user wants the current
/// specification to designate.  This property might be empty, in
/// which case it's ignored at evaluation time.
///
/// @param n the new name of the variable to set.
void
variable_suppression::set_name(const string& n)
{priv_->name_ = n;}

/// Getter for the regular expression for a family of names of
/// variables the user wants the current specification to designate.
///
/// If the variable name as returned by
/// variable_suppression::get_name() is not empty, then this property
/// is ignored at evaluation time.  This property might be empty, in
/// which case it's ignored at evaluation time.
///
/// @return the regular expression for the variable name, or a null
/// pointer if unset.
const regex_t_sptr&
variable_suppression::get_name_regex() const
{return priv_->name_regex_;}

/// Setter for the regular expression for a family of names of
/// variables the user wants the current specification to designate.
///
/// If the variable name as returned by
/// variable_suppression::get_name() is not empty, then this property
/// is ignored at evaluation time.  This property might be empty, in
/// which case it's ignored at evaluation time.
///
/// @param r the new regular expression for the variable name.
void
variable_suppression::set_name_regex(const regex_t_sptr& r)
{priv_->name_regex_ = r;}

/// Getter for the "name_not_regexp" property of the specification.
///
/// @return the regular expression for variable name exclusion, or a
/// null pointer if unset.
const regex_t_sptr&
variable_suppression::get_name_not_regex() const
{return priv_->name_not_regex_;}

/// Setter for the "name_not_regexp" property of the specification.
///
/// @param r the new regular expression for variable name exclusion,
/// or a null pointer to unset this.
void
variable_suppression::set_name_not_regex(const regex_t_sptr& r)
{priv_->name_not_regex_ = r;}

/// Getter for the name of the symbol of the variable the user wants
/// the current specification to designate.
///
/// This property might be empty, in which case it is ignored at
/// evaluation time.
///
/// @return the name of the symbol of the variable.
const string&
variable_suppression::get_symbol_name() const
{return priv_->symbol_name_;}

/// Setter for the name of the symbol of the variable the user wants
/// the current specification to designate.
///
/// This property might be empty, in which case it is ignored at
/// evaluation time.
///
/// @param n the new name of the symbol of the variable.
void
variable_suppression::set_symbol_name(const string& n)
{priv_->symbol_name_ = n;}

/// Getter of the regular expression for a family of symbol names of
/// the variables this specification is about to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.  Otherwise, it is taken in account iff the
/// property returned by variable_suppression::get_symbol_name() is
/// empty.
///
/// @return the regular expression for a symbol name of the variable,
/// or a null pointer if unset.
const regex_t_sptr&
variable_suppression::get_symbol_name_regex() const
{return priv_->symbol_name_regex_;}

/// Setter of the regular expression for a family of symbol names of
/// the variables this specification is about to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.  Otherwise, it is taken in account iff the
/// property returned by variable_suppression::get_symbol_name() is
/// empty.
///
/// @param r the regular expression for a symbol name of the variable.
void
variable_suppression::set_symbol_name_regex(const regex_t_sptr& r)
{priv_->symbol_name_regex_ = r;}

/// Getter for a regular expression for a family of names of symbols
/// of variables the user wants this specification to designate.
///
/// If a symbol name is matched by this regular expression, then the
/// suppression specification will *NOT* suppress the symbol.
///
/// If the symbol name as returned by
/// variable_suppression::get_symbol_name() is not empty, then this
/// property is ignored at specification evaluation time.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return the regular expression for a family of names of symbols
/// that is to be *NOT* suppressed by this suppression specification,
/// or a null pointer if unset.
const regex_t_sptr&
variable_suppression::get_symbol_name_not_regex() const
{return priv_->symbol_name_not_regex_;}

/// Setter for a regular expression for a family of names of symbols
/// of variables the user wants this specification to designate.
///
/// If a symbol name is matched by this regular expression, then the
/// suppression specification will *NOT* suppress the symbol.
///
/// If the symbol name as returned by
/// variable_suppression::get_symbol_name() is not empty, then this
/// property is ignored at specification evaluation time.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @param the new regular expression for a family of names of
/// symbols that is to be *NOT* suppressed by this suppression
/// specification.
void
variable_suppression::set_symbol_name_not_regex(const regex_t_sptr& r)
{priv_->symbol_name_not_regex_ = r;}

/// Getter for the version of the symbol of the variable the user
/// wants the current specification to designate.  This property might
/// be empty, in which case it's ignored at evaluation time.
///
/// @return the symbol version of the variable.
const string&
variable_suppression::get_symbol_version() const
{return priv_->symbol_version_;}

/// Setter for the version of the symbol of the variable the user
/// wants the current specification to designate.  This property might
/// be empty, in which case it's ignored at evaluation time.
///
/// @return the new symbol version of the variable.
void
variable_suppression::set_symbol_version(const string& v)
{priv_->symbol_version_ = v;}

/// Getter of the regular expression for a family of versions of
/// symbol for the variables the user wants the current specification
/// to designate.
///
/// If the symbol version as returned by
/// variable_suppression::get_symbol_version() is not empty, then this
/// property is ignored at evaluation time.  This property might be
/// empty, in which case it's ignored at evaluation time.
///
/// @return the regular expression of the symbol version of the
/// variable, or a null pointer if unset.
const regex_t_sptr&
variable_suppression::get_symbol_version_regex() const
{return priv_->symbol_version_regex_;}

/// Setter of the regular expression for a family of versions of
/// symbol for the variables the user wants the current specification
/// to designate.
///
/// If the symbol version as returned by
/// variable_suppression::get_symbol_version() is not empty, then this
/// property is ignored at evaluation time.  This property might be
/// empty, in which case it's ignored at evaluation time.
///
/// @param v the new regular expression of the symbol version of the
/// variable.
void
variable_suppression::set_symbol_version_regex(const regex_t_sptr& r)
{priv_->symbol_version_regex_ = r;}

/// Getter for the name of the type of the variable the user wants the
/// current specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @return the name of the variable type.
const string&
variable_suppression::get_type_name() const
{return priv_->type_name_;}

/// Setter for the name of the type of the variable the user wants the
/// current specification to designate.
///
/// This property might be empty, in which case it's ignored at
/// evaluation time.
///
/// @param n the new name of the variable type.
void
variable_suppression::set_type_name(const string& n)
{priv_->type_name_ = n;}

/// Getter for the regular expression for a family of type names of
/// variables the user wants the current specification to designate.
///
/// If the type name as returned by
/// variable_suppression::get_type_name() is not empty, then this
/// property is ignored at evaluation time.  This property might be
/// empty, in which case it's ignored at evaluation time.
///
/// @return the regular expression of the variable type name, or a
/// null pointer if unset.
const regex_t_sptr&
variable_suppression::get_type_name_regex() const
{return priv_->type_name_regex_;}

/// Setter for the regular expression for a family of type names of
/// variables the user wants the current specification to designate.
///
/// If the type name as returned by
/// variable_suppression::get_type_name() is not empty, then this
/// property is ignored at evaluation time.  This property might be
/// empty, in which case it's ignored at evaluation time.
///
/// @param r the regular expression of the variable type name.
void
variable_suppression::set_type_name_regex(const regex_t_sptr& r)
{priv_->type_name_regex_ = r;}

/// Evaluate this suppression specification on a given diff node and
/// say if the diff node should be suppressed or not.
///
/// @param diff the diff node to evaluate this suppression
/// specification against.
///
/// @return true if @p diff should be suppressed.
bool
variable_suppression::suppresses_diff(const diff* diff) const
{
  const var_diff* d = is_var_diff(diff);
  if (!d)
    return false;

  var_decl_sptr fv = is_var_decl(is_decl(d->first_subject())),
    sv = is_var_decl(is_decl(d->second_subject()));

  ABG_ASSERT(fv && sv);

  return (suppresses_variable(fv,
			      VARIABLE_SUBTYPE_CHANGE_KIND,
			      diff->context())
	  || suppresses_variable(sv,
				 VARIABLE_SUBTYPE_CHANGE_KIND,
				 diff->context()));
}

/// Evaluate the current variable suppression specification on a given
/// @ref var_decl and say if a report about a change involving this
/// @ref var_decl should be suppressed or not.
///
/// @param var the @ref var_decl to evaluate this suppression
/// specification against.
///
/// @param k the kind of variable change @p var is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the variable @p
/// var should be suppressed.
bool
variable_suppression::suppresses_variable(const var_decl* var,
					  change_kind k,
					  const diff_context_sptr ctxt) const
{
  if (!(get_change_kind() & k))
    return false;

  // Check if the name and soname of the binaries match
  if (ctxt)
    {
      // Check if the name of the binaries match the current
      // suppr spec
      if (!names_of_binaries_match(*this, *ctxt))
	if (has_file_name_related_property())
	  return false;

      // Check if the soname of the binaries match the current suppr
      // spec
      if (!sonames_of_binaries_match(*this, *ctxt))
	if (has_soname_related_property())
	  return false;
    }

  string var_name = var->get_qualified_name();

  // Check for "name" property match.
  if (!get_name().empty())
    {
      if (get_name() != var_name)
	return false;
    }
  else
    {
      // If the "name" property is empty, then consider checking for the
      // "name_regex" and "name_not_regex" properties match
      if (get_name().empty())
	{
	  if (const regex_t_sptr& regex = get_name_regex())
	    if (!regex::match(regex, var_name))
	      return false;

	  if (const regex_t_sptr& regex = get_name_not_regex())
	    if (regex::match(regex, var_name))
	      return false;
	}
    }

  // Check for the symbol_name, symbol_name_regex and
  // symbol_name_not_regex property match.
  string var_sym_name = var->get_symbol() ? var->get_symbol()->get_name() : "";
  if (!get_symbol_name().empty())
    {
      if (get_symbol_name() != var_sym_name)
	return false;
    }
  else
    {
      if (const regex_t_sptr& regex = get_symbol_name_regex())
	if (!regex::match(regex, var_sym_name))
	  return false;

      if (const regex_t_sptr& regex = get_symbol_name_not_regex())
	if (regex::match(regex, var_sym_name))
	  return false;
    }

  // Check for symbol_version and symbol_version_regexp property match
  string var_sym_version =
    var->get_symbol() ? var->get_symbol()->get_version().str() : "";
  if (!get_symbol_version().empty())
    {
      if (get_symbol_version() != var_sym_version)
	return false;
    }
  else
    {
      if (const regex_t_sptr& regex = get_symbol_version_regex())
	if (!regex::match(regex, var_sym_version))
	  return false;
    }

  // Check for the "type_name" and type_name_regex properties match.
  string var_type_name =
    get_type_declaration(var->get_type())->get_qualified_name();

  if (!get_type_name().empty())
    {
      if (get_type_name() != var_type_name)
	return false;
    }
  else
    {
      if (const regex_t_sptr& regex = get_type_name_regex())
	if (!regex::match(regex, var_type_name))
	  return false;
    }

  return true;
}

/// Evaluate the current variable suppression specification on a given
/// @ref var_decl and say if a report about a change involving this
/// @ref var_decl should be suppressed or not.
///
/// @param var the @ref var_decl to evaluate this suppression
/// specification against.
///
/// @param k the kind of variable change @p var is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the variable @p
/// var should be suppressed.
bool
variable_suppression::suppresses_variable(const var_decl_sptr var,
					  change_kind k,
					  const diff_context_sptr ctxt) const
{return suppresses_variable(var.get(), k, ctxt);}

/// Evaluate the current variable suppression specification on a given
/// @ref elf_symbol and say if a report about a change involving this
/// @ref elf_symbol should be suppressed or not.
///
/// @param sym the @ref elf_symbol to evaluate this suppression
/// specification against.
///
/// @param k the kind of variable change @p sym is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the symbol @p
/// sym should be suppressed.
bool
variable_suppression::suppresses_variable_symbol(const elf_symbol* sym,
						 change_kind k,
						 const diff_context_sptr ctxt) const
{
  if (!sym)
    return false;

  if (!(get_change_kind() & k))
    return false;

  if (!sym->is_variable())
    return false;

  ABG_ASSERT(k & ADDED_VARIABLE_CHANGE_KIND
	 || k & DELETED_VARIABLE_CHANGE_KIND);

  // Check if the name and soname of the binaries match the current
  // suppr spec.
  if (ctxt)
    {
      // Check if the name of the binaries match the current suppr
      // spec
      if (!names_of_binaries_match(*this, *ctxt))
	if (has_file_name_related_property())
	  return false;

      // Check if the soname of the binaries match the current suppr spec
      if (!sonames_of_binaries_match(*this, *ctxt))
	if (has_soname_related_property())
	  return false;
    }

  string sym_name = sym->get_name(), sym_version = sym->get_version().str();

  bool no_symbol_name = false, no_symbol_version = false;

  // Consider the symbol name
  if (!get_name().empty())
    {
      if (get_name() != sym_name)
	return false;
    }
  else if (!get_symbol_name().empty())
    {
      if (get_symbol_name() != sym_name)
	return false;
    }
  else if (const regex_t_sptr& regex = get_symbol_name_regex())
    {
      if (!regex::match(regex, sym_name))
	return false;
    }
  else
    no_symbol_name = true;

  // Consider the symbol version.
  if (!get_symbol_version().empty())
    {
      if (get_symbol_version() != sym_version)
	return false;
    }
  else if (const regex_t_sptr& regex = get_symbol_version_regex())
    {
      if (!regex::match(regex, sym_version))
	return false;
    }
  else
    no_symbol_version = true;

  if (no_symbol_name && no_symbol_version)
    return false;

  return true;
}

/// Evaluate the current variable suppression specification on a given
/// @ref elf_symbol and say if a report about a change involving this
/// @ref elf_symbol should be suppressed or not.
///
/// @param sym the @ref elf_symbol to evaluate this suppression
/// specification against.
///
/// @param k the kind of variable change @p sym is supposed to have.
///
/// @param ctxt the context of the current diff.
///
/// @return true iff a report about a change involving the symbol @p
/// sym should be suppressed.
bool
variable_suppression::suppresses_variable_symbol(const elf_symbol_sptr sym,
						 change_kind k,
						 const diff_context_sptr ctxt) const
{return suppresses_variable_symbol(sym.get(), k, ctxt);}

/// Test if an instance of @ref suppression is an instance of @ref
/// variable_suppression.
///
/// @param suppr the instance of @ref suppression to test for.
///
/// @return if @p suppr is an instance of @ref variable_suppression, then
/// return the sub-object of the @p suppr of type @ref
/// variable_suppression, otherwise return a nil pointer.
variable_suppression_sptr
is_variable_suppression(const suppression_sptr s)
{return dynamic_pointer_cast<variable_suppression>(s);}

/// The bitwise 'and' operator for the enum @ref
/// variable_suppression::change_kind.
///
/// @param l the first operand of the 'and' operator.
///
/// @param r the second operand of the 'and' operator.
///
/// @return the result of 'and' operation on @p l and @p r.
variable_suppression::change_kind
operator&(variable_suppression::change_kind l,
	  variable_suppression::change_kind r)
{
  return static_cast<variable_suppression::change_kind>
    (static_cast<unsigned>(l) & static_cast<unsigned>(r));
}

/// The bitwise 'or' operator for the enum @ref
/// variable_suppression::change_kind.
///
/// @param l the first operand of the 'or' operator.
///
/// @param r the second operand of the 'or' operator.
///
/// @return the result of 'or' operation on @p l and @p r.
variable_suppression::change_kind
operator|(variable_suppression::change_kind l,
	  variable_suppression::change_kind r)
{
    return static_cast<variable_suppression::change_kind>
    (static_cast<unsigned>(l) | static_cast<unsigned>(r));
}

/// Read a variable suppression from an instance of
/// ini::config::section and build a @ref variable_suppression as a
/// result.
///
/// @param section the section of the ini config to read.
///
/// @param suppr the @ref suppression to assign to.
///
/// @return whether the parse was successful.
static bool
read_variable_suppression(const ini::config::section& section,
			  suppression_sptr& suppr)
{
  static const char *const sufficient_props[] = {
    "label",
    "file_name_regexp",
    "file_name_not_regexp",
    "soname_regexp",
    "soname_not_regexp",
    "name",
    "name_regexp",
    "name_not_regexp",
    "symbol_name",
    "symbol_name_regexp",
    "symbol_name_not_regexp",
    "symbol_version",
    "symbol_version_regexp",
    "type_name",
    "type_name_regexp",
  };
  if (!check_sufficient_props(sufficient_props,
			      sizeof(sufficient_props)/sizeof(char*),
			      section))
    return false;

  variable_suppression result;

  if (ini::property_sptr prop = section.find_property("label"))
    {
      std::string str;
      if (read(prop, str))
	result.set_label(str);
    }

  if (ini::property_sptr prop = section.find_property("name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_name(str);
    }

  if (ini::property_sptr prop = section.find_property("name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("symbol_name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_symbol_name(str);
    }

  if (ini::property_sptr prop = section.find_property("symbol_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_symbol_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("symbol_version"))
    {
      std::string str;
      if (read(prop, str))
	result.set_symbol_version(str);
    }

  if (ini::property_sptr prop = section.find_property("symbol_version_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_symbol_version_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("type_name"))
    {
      std::string str;
      if (read(prop, str))
	result.set_type_name(str);
    }

  if (ini::property_sptr prop = section.find_property("type_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_type_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("symbol_name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_symbol_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("change_kind"))
    {
      std::string str;
      if (read(prop, str))
	if (!str.empty())
	  result.set_change_kind(variable_suppression::parse_change_kind(str));
    }

  if (ini::property_sptr prop = section.find_property("file_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("file_name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_not_regex(regex);
    }

  ini::property_sptr drop_prop = section.find_property("drop_artifact");
  if (!drop_prop)
    drop_prop = section.find_property("drop");
  if (drop_prop)
    {
      bool b;
      if (read(drop_prop, b))
	result.set_drops_artifact_from_ir(b);
    }

  if (result.get_drops_artifact_from_ir()
      && result.get_name().empty()
      && !result.get_name_regex()
      && !result.get_name_not_regex()
      && result.get_symbol_name().empty()
      && !result.get_symbol_name_regex()
      && !result.get_symbol_name_not_regex())
    {
      // TODO: maybe emit warning about 'drop' directive being ignored
      result.set_drops_artifact_from_ir(false);
    }

  suppr.reset(new variable_suppression(result));
  return true;
}

// </variable_suppression stuff>

// <file_suppression stuff>

/// Default constructor for the the @ref file_suppression type.
file_suppression::file_suppression()
{}

/// Test if instances of this @ref file_suppression suppresses a
/// certain instance of @ref diff.
///
/// This function always returns false because, obviously, a
/// file_suppression is meants to prevents Abigail tools from loading
/// some files.  It is not meant to act on instance of @ref diff.
/// @return false.
bool
file_suppression::suppresses_diff(const diff*) const
{return false;}

/// Test if a instances of this @ref file_suppression suppresses a
/// given file.
///
/// @param file_path the file path to test against.
///
/// @return true iff this file_suppression matches the file path @p
/// file_path.
bool
file_suppression::suppresses_file(const string& file_path)
{
  if (file_path.empty())
    return false;

  string fname;
  tools_utils::base_name(file_path, fname);

  bool has_regexp = false;

  if (const regex_t_sptr& regexp = get_file_name_regex())
    {
      has_regexp = true;
      if (!regex::match(regexp, fname))
	return false;
    }

  if (const regex_t_sptr& regexp = get_file_name_not_regex())
    {
      has_regexp = true;
      if (regex::match(regexp, fname))
	return false;
    }

  if (!has_regexp)
    return false;

  return true;
}

/// Destructor of @ref file_suppression.
file_suppression::~file_suppression()
{
}

/// Read a file suppression from an instance of ini::config::section
/// and build a @ref file_suppression as a result.
///
/// @param section the section of the ini config to read.
///
/// @param suppr the @ref suppression to assign to.
///
/// @return whether the parse was successful.
static bool
read_file_suppression(const ini::config::section& section,
		      suppression_sptr& suppr)
{
  static const char *const sufficient_props[] = {
    "file_name_regexp",
    "file_name_not_regexp",
    "soname_regexp",
    "soname_not_regexp",
  };
  if (!check_sufficient_props(sufficient_props,
			      sizeof(sufficient_props)/sizeof(char*),
			      section))
    return false;

  file_suppression result;

  if (ini::property_sptr prop = section.find_property("label"))
    {
      std::string str;
      if (read(prop, str))
	result.set_label(str);
    }

  if (ini::property_sptr prop = section.find_property("file_name_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("file_name_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_file_name_not_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_regex(regex);
    }

  if (ini::property_sptr prop = section.find_property("soname_not_regexp"))
    {
      regex_t_sptr regex;
      if (read(prop, regex))
	result.set_soname_not_regex(regex);
    }

  // TODO: investigate this, there is currently no user control possible.
  result.set_drops_artifact_from_ir(result.has_soname_related_property());

  suppr.reset(new file_suppression(result));
  return true;
}

/// Test if a given suppression specification is a file suppression
/// specification.
///
/// @param s the instance of @ref suppression_base to test.
///
/// @return the instance of @ref file_suppression that @p s points to,
/// iff s is an instance of @ref file_suppression.  Otherwise, returns
/// nil.
file_suppression_sptr
is_file_suppression(const suppression_sptr s)
{return dynamic_pointer_cast<file_suppression>(s);}

/// Test if a given file path is "suppressed" by at least one file
/// suppression specification among a vector of suppression
/// specifications.
///
/// @param file_path the file path to test.
///
/// @param sprs the vector of suppressions to use to test if one of
/// them at lease matches the file path @p file_path.
///
/// @return a pointer to the first instance of @ref file_suppression
/// that matches @p file_path, or nil if no file suppression matches.
file_suppression_sptr
file_is_suppressed(const string& file_path,
		   const suppressions_type& sprs)
{
  for (suppressions_type::const_iterator i = sprs.begin(); i != sprs.end(); ++i)
    if (file_suppression_sptr s = is_file_suppression(*i))
      if (s->suppresses_file(file_path))
	return s;

  return file_suppression_sptr();
}

/// Test if a given SONAME is matched by a given suppression
/// specification.
///
/// @param soname the SONAME to consider.
///
/// @param suppr the suppression specification to consider.
///
/// @return true iff a given SONAME is matched by a given suppression
/// specification.
bool
suppression_matches_soname(const string& soname,
			   const suppression_base& suppr)
{
  return suppr.matches_soname(soname);
}

/// Test if a given SONAME or file name is matched by a given
/// suppression specification.
///
/// @param soname the SONAME to consider.
///
/// @param filename the file name to consider.
///
/// @param suppr the suppression specification to consider.
///
/// @return true iff either @p soname or @p filename is matched by the
/// suppression specification @p suppr.
bool
suppression_matches_soname_or_filename(const string& soname,
				       const string& filename,
				       const suppression_base& suppr)
{
  return (suppression_matches_soname(soname, suppr)
	  || suppr.matches_binary_name(filename));
}

/// @return the name of the artificial private type suppression
/// specification that is auto-generated by libabigail to suppress
/// change reports about types that are not defined in public headers.
const char*
get_private_types_suppr_spec_label()
{
  static const char *PRIVATE_TYPES_SUPPR_SPEC_NAME =
    "Artificial private types suppression specification";

  return PRIVATE_TYPES_SUPPR_SPEC_NAME;
}

/// Test if a type suppression specification represents a private type
/// suppression automatically generated by libabigail from the user
/// telling us where public headers are.
///
/// @param s the suppression specification we are looking at.
///
/// @return true iff @p s is a private type suppr spec.
bool
is_private_type_suppr_spec(const type_suppression& s)
{return s.get_label() == get_private_types_suppr_spec_label();}

/// Test if a type suppression specification represents a private type
/// suppression automatically generated by libabigail from the user
/// telling us where public headers are.
///
/// @param s the suppression specification we are looking at.
///
/// @return true iff @p s is a private type suppr spec.
bool
is_private_type_suppr_spec(const suppression_sptr& s)
{
  type_suppression_sptr type_suppr = is_type_suppression(s);
  return (type_suppr
	  && type_suppr->get_label() == get_private_types_suppr_spec_label());
}

// </file_suppression stuff>
}// end namespace suppr
} // end namespace abigail
