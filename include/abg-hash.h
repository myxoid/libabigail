// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2013-2020 Red Hat, Inc.

/// @file

#ifndef __ABG_HASH_H__
#define __ABG_HASH_H__

#include <stdint.h>
#include <cstddef>
#include <string>
#include <utility>

namespace abigail
{
/// Namespace for hashing.
namespace hashing
{
  /// Produce good hash value combining val1 and val2.
  /// This is copied from tree.c in GCC.
  std::size_t
  combine_hashes(std::size_t, std::size_t);

  template<typename A, typename B>
  std::size_t hash_value(const std::pair<A, B> & p)
  {
    return combine_hashes(std::hash<A>(p.first), std::hash<B>(p.second));
  }

  uint32_t
  fnv_hash(const std::string& str);
}//end namespace hashing
}//end namespace abigail

#endif //__ABG_HASH_H__
