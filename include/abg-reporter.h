// -*- Mode: C++ -*-
//
// Copyright (C) 2017-2018 Red Hat, Inc.
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
/// The declaration of the reporting types of libabigail's diff
/// engine.

#ifndef __ABG_REPORTER_H__
#define __ABG_REPORTER_H__

namespace abigail
{
namespace comparison
{
class diff;
class type_decl_diff;
class enum_diff;
class typedef_diff;
class qualified_type_diff;
class distinct_diff;
class pointer_diff;
class reference_diff;
class array_diff;
class base_diff;
class class_or_union_diff;
class class_diff;
class union_diff;
class scope_diff;
class fn_parm_diff;
class function_type_diff;
class function_decl_diff;
class var_diff;
class translation_unit_diff;
class corpus_diff;
class diff_maps;
class reporter_base;

/// A convenience typedef for a shared pointer to a @ref
/// reporter_base.
typedef shared_ptr<reporter_base> reporter_base_sptr;

/// The base class of all the reporting classes.
class reporter_base
{
public:

  virtual void
  report(const type_decl_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const enum_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const typedef_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const qualified_type_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const distinct_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const pointer_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const reference_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const array_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const base_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const class_or_union_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const class_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const union_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const scope_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const fn_parm_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const function_type_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const function_decl_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const var_diff& d, ostream& out, const string& indent = "") const = 0;

  virtual void
  report(const translation_unit_diff& d, ostream& out,
	 const string& indent = "") const = 0;

  virtual void
  report(const corpus_diff& d, ostream& out,
	 const string& indent = "") const = 0;

/// Notifies the reporter that the children nodes of a given diff node
/// were skipped during the redundancy detection pass.
///
/// @param d the diff node whose children got skipped.
  virtual void categorize_redundant_diff_nodes(corpus_diff&) = 0;

/// Tests if the children of a diff node should be skipped during the
/// diff graph walk which goal is to detect redundant diff nodes.
///
/// This function is called by the @ref redundancy_marking_visitor
/// pass visitor while walking the diff graph to detect redundant diff
/// nodes.
///
/// @param d the diff node to considerK
///
/// @return true if the caller should skip the children nodes of the
/// diff node @p d, false otherwise.
  virtual bool skip_children_during_redundancy_detection(const diff *d) = 0;

/// Notifies the reporter that the children nodes of a given diff node
/// were skipped during the redundancy detection pass.
///
/// @param d the diff node whose children got skipped.
  virtual void notify_children_nodes_skiped_during_redundancy_detection(const diff *) = 0;

  /// Tests if a diff node has local changes that are meant to be
  /// reported, in the context of the current reporter.
  ///
  /// @param d the diff node to consider.
  ///
  /// @return true iff the diff @p d has a local change that is meant
  /// to be reported.
  virtual bool diff_has_local_changes_to_be_reported(const diff *d) const = 0;

  /// Test if a given diff node is meant to be reported in the context
  /// of the current reporter.
  ///
  /// @param d the diff node to consider.
  ///
  /// @return true if @p d is meant to be reported.
  virtual bool diff_to_be_reported(const diff *d) const;

  virtual void print_diff_tree(const corpus_diff * diff_tree,
			       std::ostream& out) const = 0;
}; //end class reporter_base

class default_reporter;

/// A convenience typedef for a shared_ptr to a @ref default_reporter.
typedef shared_ptr<default_reporter> default_reporter_sptr;

/// The default, initial, reporter of the libabigail comparison engine.
class default_reporter : public reporter_base
{
public:

  virtual void
  report(const type_decl_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const enum_diff& d, ostream& out,
	 const string& indent = "") const;

  bool
  report_local_typedef_changes(const typedef_diff &d,
			       ostream& out,
			       const string& indent) const;

  virtual void
  report(const typedef_diff& d, ostream& out,
	 const string& indent = "") const;

  bool
  report_local_qualified_type_changes(const qualified_type_diff& d,
				      ostream& out,
				      const string& indent) const;

  virtual void
  report(const qualified_type_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const pointer_diff& d, ostream& out, const string& indent = "") const;

  void
  report_local_reference_type_changes(const reference_diff& d,
				      ostream& out,
				      const string& indent) const;

  virtual void
  report(const reference_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const fn_parm_diff& d, ostream& out,
	 const string& indent = "") const;

  void
  report_local_function_type_changes(const function_type_diff& d,
				     ostream& out,
				     const string& indent) const;

  virtual void
  report(const function_type_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const array_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const base_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const scope_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const class_or_union_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const class_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const union_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const distinct_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const function_decl_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const var_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const translation_unit_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const corpus_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual bool skip_children_during_redundancy_detection(const diff *d);

  virtual void notify_children_nodes_skiped_during_redundancy_detection(const diff *);

  /// Tests if a diff node has local changes that are meant to be
  /// reported, in the context of the current reporter.
  ///
  /// @param d the diff node to consider.
  ///
  /// @return true iff the diff @p d has a local change that is meant
  /// to be reported.
virtual bool diff_has_local_changes_to_be_reported(const diff *) const;

  virtual void categorize_redundant_diff_nodes(corpus_diff&);

  virtual void print_diff_tree(const corpus_diff * diff_tree,
			       std::ostream& out) const;
}; // end class default_reporter

/// A reporter that only reports leaf changes
class leaf_reporter : public default_reporter
{
public:

  void
  report_changes_from_diff_maps(const diff_maps&,
				ostream& out,
				const string& indent) const;

  virtual void
  report(const typedef_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const qualified_type_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const pointer_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const reference_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const fn_parm_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const function_type_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const array_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const scope_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const class_or_union_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const class_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const union_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const distinct_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const function_decl_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const var_diff& d, ostream& out, const string& indent = "") const;

  virtual void
  report(const translation_unit_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual void
  report(const corpus_diff& d, ostream& out,
	 const string& indent = "") const;

  virtual bool skip_children_during_redundancy_detection(const diff *d);

  virtual void notify_children_nodes_skiped_during_redundancy_detection
  (const diff *);

  virtual bool diff_to_be_reported(const diff *d) const;

  /// Tests if a diff node has local changes that are meant to be
  /// reported, in the context of the current reporter.
  ///
  /// @param d the diff node to consider.
  ///
  /// @return true iff the diff @p d has a local change that is meant
  /// to be reported.
  virtual bool diff_has_local_changes_to_be_reported(const diff *) const;

  virtual void categorize_redundant_diff_nodes(corpus_diff&);

  virtual void print_diff_tree(const corpus_diff * diff_tree,
			       std::ostream& out) const;
}; // end class leaf_reporter

} // end namespace comparison
} // end namespace abigail

#endif // __ABG_REPORTER_H__
