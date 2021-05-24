// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2020 Google, Inc.
//
// Author: Maria Teguiani

#include "abg-btf.h"

int main(int argc, const char *argv[]) {
  if (argc != 2) {
    std::cerr << "Please specify the path to a BTF file.";
    return 1;
  }

  (void) abigail::btf::ReadFile(argv[1], /* verbose = */ true);

  return 0;
}
