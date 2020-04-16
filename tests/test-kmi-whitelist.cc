// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2020 Google, Inc.
//
// Author: Matthias Maennich

/// @file
///
/// This program tests suppression generation from KMI whitelists.

#include <string>

#include "lib/catch.hpp"

#include "abg-fwd.h"
#include "abg-regex.h"
#include "abg-tools-utils.h"
#include "abg-suppression.h"
#include "test-utils.h"

using abigail::regex::regex_t_sptr;
using abigail::regex::compile;
using abigail::regex::match;
using abigail::tools_utils::gen_suppr_spec_from_kernel_abi_whitelists;
using abigail::suppr::suppression_sptr;
using abigail::suppr::suppressions_type;
using abigail::suppr::function_suppression_sptr;
using abigail::suppr::variable_suppression_sptr;
using abigail::suppr::is_function_suppression;
using abigail::suppr::is_variable_suppression;

const static std::string whitelist_with_single_entry
    = std::string(abigail::tests::get_src_dir())
      + "/tests/data/test-kmi-whitelist/whitelist-with-single-entry";

const static std::string whitelist_with_another_single_entry
    = std::string(abigail::tests::get_src_dir())
      + "/tests/data/test-kmi-whitelist/whitelist-with-another-single-entry";

const static std::string whitelist_with_two_sections
    = std::string(abigail::tests::get_src_dir())
      + "/tests/data/test-kmi-whitelist/whitelist-with-two-sections";

const static std::string whitelist_with_duplicate_entry
    = std::string(abigail::tests::get_src_dir())
      + "/tests/data/test-kmi-whitelist/whitelist-with-duplicate-entry";

// These are strings, not regexes, we cannot exhaustively check all
// strings, but we can do some sampling and match sure we haven't got
// the regex logic completely wrong.
static const char* const random_symbols[] =
{
  "",
  ".*",
  "^$",
  "test_symbol",
  "test-symbol",
  "test symbol",
  "Test Symbol",
  "est_symbo",
  ".*test_symbol.*",
  "test_symbol ",
  " test_symbol",
  " test_symbol ",
  "test_another_symbol",
  "$test_another_symbol",
};

void
test_suppressions_are_consistent(const suppressions_type& suppr,
				 const std::string&	  expr)
{
  REQUIRE(suppr.size() == 2);

  function_suppression_sptr left = is_function_suppression(suppr[0]);
  variable_suppression_sptr right = is_variable_suppression(suppr[1]);

  // correctly casted
  REQUIRE(left);
  REQUIRE(right);
  // same label
  REQUIRE(left->get_label() == right->get_label());
  // same mode
  REQUIRE(left->get_drops_artifact_from_ir()
	  == right->get_drops_artifact_from_ir());

  // these parts of the symbol name matching should be absent
  REQUIRE(left->get_symbol_name().empty());
  REQUIRE(!left->get_symbol_name_regex());
  REQUIRE(right->get_symbol_name().empty());
  REQUIRE(!right->get_symbol_name_regex());

  regex_t_sptr left_regex = left->get_symbol_name_not_regex();
  regex_t_sptr right_regex = right->get_symbol_name_not_regex();
  regex_t_sptr check_regex = compile(expr);

  // all regexes present (compiled)
  REQUIRE(left_regex);
  REQUIRE(right_regex);
  REQUIRE(check_regex);

  // all regexes match or do not match a random symbol
  for (size_t i = 0; i < sizeof(random_symbols)/sizeof(random_symbols[0]); ++i)
    {
      const std::string symbol(random_symbols[i]);
      bool left_matches = match(left_regex, symbol);
      bool right_matches = match(right_regex, symbol);
      bool check_matches = match(check_regex, symbol);
      REQUIRE(left_matches == right_matches);
      REQUIRE(left_matches == check_matches);
    }
}

TEST_CASE("NoWhitelists", "[whitelists]")
{
  const std::vector<std::string> abi_whitelist_paths;
  suppressions_type		 suppr =
      gen_suppr_spec_from_kernel_abi_whitelists(abi_whitelist_paths);
  REQUIRE(suppr.empty());
}

TEST_CASE("WhitelistWithASingleEntry", "[whitelists]")
{
  std::vector<std::string> abi_whitelist_paths;
  abi_whitelist_paths.push_back(whitelist_with_single_entry);
  suppressions_type suppr
      = gen_suppr_spec_from_kernel_abi_whitelists(abi_whitelist_paths);
  REQUIRE(!suppr.empty());
  test_suppressions_are_consistent(suppr, "^(test_symbol)$");
}

TEST_CASE("WhitelistWithADuplicateEntry", "[whitelists]")
{
  std::vector<std::string> abi_whitelist_paths;
  abi_whitelist_paths.push_back(whitelist_with_duplicate_entry);
  suppressions_type suppr
      = gen_suppr_spec_from_kernel_abi_whitelists(abi_whitelist_paths);
  REQUIRE(!suppr.empty());
  test_suppressions_are_consistent(suppr, "^(test_symbol)$");
}

TEST_CASE("TwoWhitelists", "[whitelists]")
{
  std::vector<std::string> abi_whitelist_paths;
  abi_whitelist_paths.push_back(whitelist_with_single_entry);
  abi_whitelist_paths.push_back(whitelist_with_another_single_entry);
  suppressions_type suppr =
      gen_suppr_spec_from_kernel_abi_whitelists(abi_whitelist_paths);
  REQUIRE(!suppr.empty());
  test_suppressions_are_consistent(suppr,
				   "^(test_another_symbol|test_symbol)$");
}

TEST_CASE("TwoWhitelistsWithDuplicates", "[whitelists]")
{
  std::vector<std::string> abi_whitelist_paths;
  abi_whitelist_paths.push_back(whitelist_with_duplicate_entry);
  abi_whitelist_paths.push_back(whitelist_with_another_single_entry);
  suppressions_type suppr
      = gen_suppr_spec_from_kernel_abi_whitelists(abi_whitelist_paths);
  REQUIRE(!suppr.empty());
  test_suppressions_are_consistent(suppr,
				   "^(test_another_symbol|test_symbol)$");
}

TEST_CASE("WhitelistWithTwoSections", "[whitelists]")
{
  std::vector<std::string> abi_whitelist_paths;
  abi_whitelist_paths.push_back(whitelist_with_two_sections);
  suppressions_type suppr
      = gen_suppr_spec_from_kernel_abi_whitelists(abi_whitelist_paths);
  REQUIRE(!suppr.empty());
  test_suppressions_are_consistent(suppr, "^(test_symbol1|test_symbol2)$");
}
