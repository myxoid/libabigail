// SPDX-License-Identifier: LGPL-3.0-or-later
// -*- Mode: C++ -*-
//
// Copyright (C) 2013-2020 Red Hat, Inc.

/// @file

#include "abg-internal.h"
// <headers defining libabigail's API go under here>
ABG_BEGIN_EXPORT_DECLARATIONS

#include "abg-traverse.h"

ABG_END_EXPORT_DECLARATIONS
// </headers defining libabigail's API>

namespace abigail
{

namespace ir
{

bool
traversable_base::traverse(node_visitor_base&)
{return true;}

}// end namaspace ir
}// end namespace abigail
