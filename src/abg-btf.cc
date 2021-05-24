// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2020-2021 Google, Inc.
//
// Author: Maria Teguiani
// Author: Giuliano Procida

#include <elfutils/libdwfl.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <set>
#include <sstream>

#include "abg-elf-helpers.h"
#include "abg-symtab-reader.h"
#include "abg-tools-utils.h"

#include "abg-btf.h"

namespace abigail
{
namespace btf
{

// This is a helper map that yields the name of a Type in the preferred
// print style by indexing into the vector with a Kind
static constexpr std::array<std::string_view, 16> kKindNames = {
    "void type",
    "integer type",
    "pointer type",
    "array type",
    "struct type",
    "union type",
    "enum type",
    "forward declaration",
    "typedef",
    "volatile",
    "const",
    "restrict",
    "function",
    "function type",
    "variable",
    "data section"};

// This matches bpftool dump format raw.
static constexpr std::array<std::string_view, 16> kRawKindNames = {
    "VOID",
    "INT",
    "PTR",
    "ARRAY",
    "STRUCT",
    "UNION",
    "ENUM",
    "FWD",
    "TYPEDEF",
    "VOLATILE",
    "CONST",
    "RESTRICT",
    "FUNC",
    "FUNC_PROTO",
    "VAR",
    "DATASEC"};

static constexpr std::array<std::string_view, 3> kVarLinkage = {
    "static",
    "global-alloc",
    "global-extern" // NOTE: bpftool currently says "(unknown)"
};

static constexpr std::array<std::string_view, 3> kFunLinkage = {
    "static", "global", "extern"};

Name
Name::Add(Side side, Precedence precedence, std::string_view text) const
{
  bool bracket = precedence < precedence_;
  std::ostringstream left;
  std::ostringstream right;

  // Bits on the left need (sometimes) to be separated by whitespace.
  left << left_;
  if (bracket)
    left << '(';
  else if (side == Side::LEFT)
    left << ' ';

  (side == Side::LEFT ? left : right) << text;

  // Bits on the right are arrays [] and functions () and need no whitespace.
  if (bracket)
    right << ')';
  right << right_;

  return Name{left.str(), precedence, right.str()};
}

Name
Name::Qualify(const std::set<Kind>& qualifiers) const
{
  // this covers the case when bad qualifiers have been dropped
  if (qualifiers.empty())
    return *this;
  // add qualifiers to the left or right of the type stem
  std::ostringstream os;
  if (precedence_ == Precedence::NIL)
    {
      for (const auto& qualifier : qualifiers)
	os << kKindNames[qualifier] << ' ';
      os << left_;
    }
  else if (precedence_ == Precedence::POINTER)
    {
      os << left_;
      for (const auto& qualifier : qualifiers)
	os << ' ' << kKindNames[qualifier];
    }
  else
    {
      m_assert(false, "unqualifiable element");
    }
  // qualifiers attach without affecting precedence
  return Name{os.str(), precedence_, right_};
}

std::ostream&
Name::Print(std::ostream& os) const
{
  return os << left_ << right_;
}

std::ostream&
operator<<(std::ostream& os, const Name& name)
{
  return name.Print(os);
}

// There are several reasons for treating CV-qualifiers specially.
// 1. They upset the precedence scheme we've got going here.
// 2. Qualifiers need to be placed according to what they qualify.
// 3. The BTF model doesn't preclude ordering and duplication issues.
// 4. A better model would have qualifiers as part of the types.
const Name&
Type::GetDescription(NameCache& names) const
{
  // infinite recursion prevention - insert at most once
  static const Name black_hole{"#"};

  auto insertion = names.insert({this, black_hole});
  Name& cached = insertion.first->second;

  if (insertion.second)
    {
      // newly inserted, need to determine name of type
      std::set<Kind> qualifiers;
      const Type& under = ResolveQualifiers(qualifiers);
      if (this == &under)
	{
	  // unqualified, simple case
	  cached = MakeDescription(names);
	}
      else
	{
	  // qualified, but we may end up adding no qualifiers
	  auto insertion_under = names.insert({&under, black_hole});
	  Name& cached_under = insertion_under.first->second;

	  // newly inserted underlying type name
	  if (insertion_under.second)
	    cached_under = under.MakeDescription(names);

	  // add the qualifiers (to the appropriate side)
	  cached = cached_under.Qualify(qualifiers);
	}
    }

  return cached;
}

std::string
GetPlainDescription(NameCache& names, const Type& type)
{
  std::ostringstream os;
  os << '"' << type.GetDescription(names) << '"';
  return os.str();
}

std::string
GetTypedefDescription(NameCache& names, const Type& given)
{
  std::ostringstream os;
  std::vector<std::string_view> typedefs;
  const Type& type = given.ResolveTypedef(typedefs);
  for (auto td : typedefs)
    os << std::quoted(td) << " = ";
  os << GetPlainDescription(names, type);
  return os.str();
}

constexpr size_t INDENT_INCREMENT = 2;

void
Print(const Comparison& comparison,
      const Outcomes& outcomes,
      Seen& seen,
      NameCache& names,
      std::ostream& os,
      size_t indent)
{
  const auto* lhs = comparison.first;
  const auto* rhs = comparison.second;
  if (!rhs)
    {
      os << GetPlainDescription(names, *lhs) << " was removed\n";
      return;
    }
  if (!lhs)
    {
      os << GetPlainDescription(names, *rhs) << " was added\n";
      return;
    }
  bool td =
      lhs->GetKind() == BTF_KIND_TYPEDEF || rhs->GetKind() == BTF_KIND_TYPEDEF;
  const std::string lhs_descr = td ? GetTypedefDescription(names, *lhs)
				   : GetPlainDescription(names, *lhs);
  const std::string rhs_descr = td ? GetTypedefDescription(names, *rhs)
				   : GetPlainDescription(names, *rhs);
  if (lhs_descr == rhs_descr)
    os << lhs_descr << " changed";
  else
    os << "changed from " << lhs_descr << " to " << rhs_descr;
  const auto& details = outcomes.find(comparison)->second;
  auto insertion = seen.insert({comparison, false});
  if (!insertion.second)
    {
      if (!insertion.first->second)
	os << " (being reported)";
      else if (!details.empty())
	os << " (already reported)";
    }
  os << '\n';
  if (insertion.second)
    {
      Print(details, outcomes, seen, names, os, indent + INDENT_INCREMENT);
      insertion.first->second = true;
    }
  // paragraph spacing
  if (!indent)
    os << '\n';
}

void
Print(const Diff& details,
      const Outcomes& outcomes,
      Seen& seen,
      NameCache& names,
      std::ostream& os,
      size_t indent)
{
  for (const auto& detail : details)
    {
      os << std::string(indent, ' ') << detail.text_;
      if (!detail.edge_)
	{
	  os << '\n';
	}
      else
	{
	  os << ' ';
	  Print(detail.edge_.value(), outcomes, seen, names, os, indent);
	}
    }
}

const Type&
Type::GetTypeAtIndex(size_t index) const
{
  m_assert(index < types_.size(), "Index out of bounds.");
  return *(types_[index].get());
}

std::string
QualifiersMessage(Kind qualifier, const std::string& action)
{
  std::ostringstream os;
  os << "qualifier " << kKindNames[qualifier] << ' ' << action;
  return os.str();
}

Result
Type::CompareSymbols(const std::map<std::string_view, const Type* const>& lhs,
		     const std::map<std::string_view, const Type* const>& rhs,
		     Outcomes& outcomes)
{
  Result result;
  State state(outcomes);
  auto lit = lhs.begin();
  auto rit = rhs.begin();
  // Each branch contains a NULL pointer check in case BTF information is
  // missing for a symbol. We conservatively have to assume that any symbol
  // without BTF information may have changed type.
  //
  // NOTE: this currently happens for all global variables
  while (lit != lhs.end() || rit != rhs.end())
    {
      if (rit == rhs.end() || (lit != lhs.end() && lit->first < rit->first))
	{
	  // removed
	  if (lit->second)
	    {
	      auto diff = Removed(*lit->second, state);
	      result.AddDiff("symbol", diff);
	    }
	  else
	    {
	      std::ostringstream os;
	      os << "symbol " << std::quoted(lit->first)
		 << " (of unknown type) was removed";
	      result.AddDiff(os.str());
	    }
	  ++lit;
	}
      else if (lit == lhs.end()
	       || (rit != rhs.end() && lit->first > rit->first))
	{
	  // added
	  if (rit->second)
	    {
	      auto diff = Added(*rit->second, state);
	      result.AddDiff("symbol", diff);
	    }
	  else
	    {
	      std::ostringstream os;
	      os << "symbol " << std::quoted(rit->first)
		 << " (if unknown type) was added";
	      result.AddDiff(os.str());
	    }
	  ++rit;
	}
      else
	{
	  // in both
	  if (lit->second && rit->second)
	    {
	      auto diff = Compare(*lit->second, *rit->second, state);
	      result.MaybeAddDiff("symbol", diff);
	    }
	  else
	    {
	      std::ostringstream os;
	      os << "symbol " << std::quoted(lit->first)
		 << " (of unknown type) may have changed";
	      result.AddDiff(os.str());
	    }
	  ++lit;
	  ++rit;
	}
    }
  return result;
}

Comparison
Type::Removed(const Type& lhs, State& state)
{
  Comparison comparison{&lhs, nullptr};
  state.outcomes.insert({comparison, {}});
  return comparison;
}

Comparison
Type::Added(const Type& rhs, State& state)
{
  Comparison comparison{nullptr, &rhs};
  state.outcomes.insert({comparison, {}});
  return comparison;
}

/*
 * We compute a diff for every visited node.
 *
 * Each node has one of:
 * 1. equals = true; perhaps only tentative edge differences
 * 2. equals = false; at least one definitive node or edge difference
 *
 * On the first visit to a node we can put a placeholder in, the equals value
 * is irrelevant, the diff may contain local and edge differences. If an SCC
 * contains only internal edge differences (and equivalently equals is true)
 * then the differences can all (eventually) be discarded.
 *
 * On exit from the first visit to a node, equals reflects the tree of
 * comparisons below that node in the DFS and similarly, the diff graph
 * starting from the node contains a subtree of this tree plus potentially
 * edges to existing nodes to the side or below (already visited SCCs,
 * sharing), or above (back links forming cycles).
 *
 * When an SCC is closed, all equals implies deleting all diffs, any false
 * implies updating all to false.
 *
 * On subsequent visits to a node, there are 2 cases. The node is still open:
 * return true and an edge diff. The node is closed, return the stored value
 * and an edge diff.
 */
std::pair<bool, std::optional<Comparison>>
Type::Compare(const Type& lhs, const Type& rhs, Type::State& state)
{
  Comparison comparison{&lhs, &rhs};

  // 1. Check if the comparison has an already known result.
  if (state.known_equal.count(comparison))
    {
      // Already visited and closed. Equal.
      return {true, {}};
    }
  if (state.outcomes.count(comparison))
    {
      // Already visited and closed. Different.
      return {false, {comparison}};
    }
  // Either open or not visited at all

  // 2. Record node with Strongly-Connected Component finder.
  auto handle = state.scc.Open({comparison, {}});
  if (!handle)
    {
      // Already open.
      //
      // Return a dummy true outcome and some tentative diffs. The diffs may
      // end up not being used and, while it would be nice to be lazier, they
      // encode all the cycling-breaking edges needed to recreate a full diff
      // structure.
      return {true, {comparison}};
    }
  // Comparison opened, need to close it before returning.

  Result result;

  std::set<Kind> lhs_quals;
  std::set<Kind> rhs_quals;
  const Type& l = lhs.ResolveQualifiers(lhs_quals);
  const Type& r = rhs.ResolveQualifiers(rhs_quals);
  if (!lhs_quals.empty() || !rhs_quals.empty())
    {
      // 3.1 Qualified type difference.
      auto lit = lhs_quals.begin();
      auto rit = rhs_quals.begin();
      auto lend = lhs_quals.end();
      auto rend = rhs_quals.end();
      while (lit != lend || rit != rend)
	{
	  if (rit == rend || (lit != lend && *lit < *rit))
	    {
	      result.AddDiff(QualifiersMessage(*lit, "removed"));
	      ++lit;
	    }
	  else if (lit == lend || (rit != rend && *lit > *rit))
	    {
	      result.AddDiff(QualifiersMessage(*rit, "added"));
	      ++rit;
	    }
	  else
	    {
	      ++lit;
	      ++rit;
	    }
	}
      const auto comp = Compare(l, r, state);
      result.MaybeAddDiff("underlying type", comp);
    }
  else if (l.GetKind() == BTF_KIND_TYPEDEF || r.GetKind() == BTF_KIND_TYPEDEF)
    {
      // 3.2 Typedef difference.
      std::vector<std::string_view> l_typedefs;
      std::vector<std::string_view> r_typedefs;
      const Type& l_ref = l.ResolveTypedef(l_typedefs);
      const Type& r_ref = r.ResolveTypedef(r_typedefs);
      const auto comp = Compare(l_ref, r_ref, state);
      result.MaybeAddDiff("via typedefs", comp);
    }
  else if (typeid(l) != typeid(r))
    {
      // 4. Incomparable.
      result.equals_ = false;
    }
  else
    {
      // 5. Actually compare with dynamic type dispatch.
      result = l.Equals(r, state);
    }

  // 6. Update result and check for a complete Strongly-Connected Component.
  auto comparisons =
      state.scc.Close(handle.value(), [&result](Outcomes::value_type& p) {
	p.second = result.details_;
      });
  if (!comparisons.empty())
    {
      // Closed SCC.
      //
      // Note that result now incorporates every inequality and difference in
      // the SCC via the DFS spanning tree.
      if (result.equals_)
	{
	  // Same. Record equalities.
	  for (auto& c : comparisons)
	    state.known_equal.insert(c.first);
	  return {true, {}};
	}
      else
	{
	  // Different. Record diffs.
	  state.outcomes.insert(std::make_move_iterator(comparisons.begin()),
				std::make_move_iterator(comparisons.end()));
	}
    }

  // Note that both equals and diff are tentative iff comparison is open.
  return {result.equals_, {comparison}};
}

Name
Void::MakeDescription(NameCache& names) const
{
  return Name{"void"};
}

Name
Ptr::MakeDescription(NameCache& names) const
{
  return GetTypeAtIndex(GetPointeeTypeId())
      .GetDescription(names)
      .Add(Side::LEFT, Precedence::POINTER, "*");
}

Name
Typedef::MakeDescription(NameCache& names) const
{
  return Name{GetName()};
}

Name
Qualifier::MakeDescription(NameCache& names) const
{
  m_assert(false, "should not be called"); // NOLINT
  return Name{GetName()};
}

Name
Integer::MakeDescription(NameCache& names) const
{
  return Name{GetName()};
}

Name
Array::MakeDescription(NameCache& names) const
{
  std::ostringstream os;
  os << '[' << GetNumberOfElements() << ']';
  return GetTypeAtIndex(GetElementTypeId())
      .GetDescription(names)
      .Add(Side::RIGHT, Precedence::ARRAY_FUNCTION, os.str());
}

Name
StructUnion::MakeDescription(NameCache& names) const
{
  std::ostringstream os;
  os << (GetKind() == BTF_KIND_STRUCT ? "struct" : "union") << ' '
     << (GetName().empty() ? "<anon>" : GetName());
  return Name{os.str()};
}

Name
Enumeration::MakeDescription(NameCache& names) const
{
  std::ostringstream os;
  os << "enum " << (GetName().empty() ? "<anon>" : GetName());
  if (GetEnums().empty())
    os << "<incomplete>";
  return Name{os.str()};
}

Name
ForwardDeclaration::MakeDescription(NameCache& names) const
{
  std::ostringstream os;
  os << GetFwdKind() << ' ' << GetName() << "<incomplete>";
  return Name{os.str()};
}

Name
FunctionPrototype::MakeDescription(NameCache& names) const
{
  std::ostringstream os;
  os << '(';
  bool sep = false;
  for (const auto& p : GetParameters())
    {
      if (sep)
	os << ", ";
      else
	sep = true;
      const auto& arg_descr = GetTypeAtIndex(p.typeId_).GetDescription(names);
      if (p.name_.empty())
	os << arg_descr;
      else
	os << arg_descr.Add(Side::LEFT, Precedence::ATOMIC, p.name_);
    }
  os << ')';
  return GetTypeAtIndex(GetReturnTypeId())
      .GetDescription(names)
      .Add(Side::RIGHT, Precedence::ARRAY_FUNCTION, os.str());
}

Name
Variable::MakeDescription(NameCache& names) const
{
  return GetTypeAtIndex(GetVarTypeId())
      .GetDescription(names)
      .Add(Side::LEFT, Precedence::ATOMIC, GetName());
}

Name
Function::MakeDescription(NameCache& names) const
{
  return GetTypeAtIndex(GetReferredTypeId())
      .GetDescription(names)
      .Add(Side::LEFT, Precedence::ATOMIC, GetName());
}

Name
DataSection::MakeDescription(NameCache& names) const
{
  // NOTE: not yet encountered in the wild
  return Name{"Unimplemented"};
}

Name
ElfSymbol::MakeDescription(NameCache& names) const
{
  return Name{symbol_->get_name()};
}

Result
Void::Equals(const Type& other, State& state) const
{
  return {};
}

Result
Ptr::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<Ptr>();

  const auto ref_diff = Compare(GetTypeAtIndex(GetPointeeTypeId()),
				o.GetTypeAtIndex(o.GetPointeeTypeId()),
				state);
  result.MaybeAddDiff("pointed-to type", ref_diff);
  return result;
}

Result
Typedef::Equals(const Type& other, State& state) const
{
  m_assert(false, "should not be called"); // NOLINT
  return {};
}

Result
Qualifier::Equals(const Type& other, State& state) const
{
  m_assert(false, "should not be called"); // NOLINT
  return {};
}

Result
Integer::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<Integer>();

  if (isBool() != o.isBool())
    {
      result.AddDiff(isBool() ? "the first one is a boolean"
			      : "the second one is a boolean");
    }
  if (isSigned() != o.isSigned())
    {
      result.AddDiff(isSigned() ? "the first one is signed"
				: "the second one is signed");
    }
  if (isChar() != o.isChar())
    {
      result.AddDiff(isChar() ? "the first one is a char"
			      : "the second one is a char");
    }
  result.MaybeAddDiff("offset", GetOffset(), o.GetOffset());
  result.MaybeAddDiff("bit size", GetBitSize(), o.GetBitSize());
  if (GetBitSize() != GetByteSize() * 8
      && o.GetBitSize() != o.GetByteSize() * 8)
    result.MaybeAddDiff("byte size", GetByteSize(), o.GetByteSize());
  return result;
}

Result
Array::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<Array>();

  result.MaybeAddDiff(
      "number of elements", GetNumberOfElements(), o.GetNumberOfElements());
  const auto index_type_diff = Compare(GetTypeAtIndex(GetIndexTypeId()),
				       o.GetTypeAtIndex(o.GetIndexTypeId()),
				       state);
  result.MaybeAddDiff("index type", index_type_diff);
  const auto element_type_diff =
      Compare(GetTypeAtIndex(GetElementTypeId()),
	      o.GetTypeAtIndex(o.GetElementTypeId()),
	      state);
  result.MaybeAddDiff("element type", element_type_diff);

  return result;
}

Result
StructUnion::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<StructUnion>();

  if (GetKind() != o.GetKind())
    {
      result.AddDiff(GetKind() == BTF_KIND_STRUCT
			 ? "changed from struct to union"
			 : "changed from union to struct");
    }

  result.MaybeAddDiff("byte size", GetByteSize(), o.GetByteSize());

  const auto& members1 = GetMembers();
  const auto& members2 = o.GetMembers();
  std::set<std::string> visited_members;
  for (const auto& m1 : members1)
    {
      visited_members.insert(m1.first);
      auto iter = members2.find(m1.first);
      if (iter == members2.end())
	{
	  std::ostringstream os;
	  os << "member " << std::quoted(m1.first) << " of type";
	  auto diff = Removed(GetTypeAtIndex(m1.second.typeId_), state);
	  result.AddDiff(os.str(), diff);
	}
      else
	{
	  result.MaybeAddDiff(
	      [&](std::ostream& os) {
		os << "member " << std::quoted(m1.first) << " offset";
	      },
	      m1.second.offset_,
	      iter->second.offset_);
	  result.MaybeAddDiff(
	      [&](std::ostream& os) {
		os << "member " << std::quoted(m1.first) << " bitfield size";
	      },
	      m1.second.bitfieldSize_,
	      iter->second.bitfieldSize_);
	  const auto sub_diff = Compare(GetTypeAtIndex(m1.second.typeId_),
					o.GetTypeAtIndex(iter->second.typeId_),
					state);
	  result.MaybeAddDiff(
	      [&](std::ostream& os) {
		os << "member " << std::quoted(m1.first) << " type";
	      },
	      sub_diff);
	}
    }
  for (const auto& m2 : members2)
    {
      if (visited_members.find(m2.first) == visited_members.end())
	{
	  std::ostringstream os;
	  os << "member " << std::quoted(m2.first) << " of type";
	  auto diff = Added(o.GetTypeAtIndex(m2.second.typeId_), state);
	  result.AddDiff(os.str(), diff);
	}
    }

  return result;
}

Result
Enumeration::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<Enumeration>();

  result.MaybeAddDiff("byte size", GetByteSize(), o.GetByteSize());

  const auto& enums1 = GetEnums();
  const auto& enums2 = o.GetEnums();
  std::set<std::string> visited_enums;
  for (const auto& e1 : enums1)
    {
      visited_enums.insert(e1.first);
      auto iter = enums2.find(e1.first);
      if (iter == enums2.end())
	{
	  std::ostringstream os;
	  os << "enumerator " << std::quoted(e1.first) << " (" << e1.second
	     << ") was removed";
	  result.AddDiff(os.str());
	}
      else
	{
	  result.MaybeAddDiff(
	      [&](std::ostream& os) {
		os << "enumerator " << std::quoted(e1.first) << " value";
	      },
	      e1.second,
	      iter->second);
	}
    }
  for (const auto& e2 : enums2)
    {
      if (visited_enums.find(e2.first) == visited_enums.end())
	{
	  std::ostringstream os;
	  os << "enumerator " << std::quoted(e2.first) << " (" << e2.second
	     << ") was added";
	  result.AddDiff(os.str());
	}
    }

  return result;
}

Result
ForwardDeclaration::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<ForwardDeclaration>();

  result.MaybeAddDiff("kind", GetFwdKind(), o.GetFwdKind());

  return result;
}

Result
Function::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<Function>();

  result.MaybeAddDiff("linkage", GetLinkage(), o.GetLinkage());
  const auto func_proto_diff = Compare(GetTypeAtIndex(GetReferredTypeId()),
				       o.GetTypeAtIndex(o.GetReferredTypeId()),
				       state);
  result.MaybeAddDiff("type", func_proto_diff);

  return result;
}

Result
FunctionPrototype::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<FunctionPrototype>();

  const auto return_type_diff = Compare(GetTypeAtIndex(GetReturnTypeId()),
					o.GetTypeAtIndex(o.GetReturnTypeId()),
					state);
  result.MaybeAddDiff("return type", return_type_diff);

  const auto& parameters1 = GetParameters();
  const auto& parameters2 = o.GetParameters();
  size_t min = std::min(parameters1.size(), parameters2.size());
  for (size_t i = 0; i < min; ++i)
    {
      const auto& p1 = parameters1.at(i);
      const auto& p2 = parameters2.at(i);
      const auto sub_diff = Compare(
	  GetTypeAtIndex(p1.typeId_), o.GetTypeAtIndex(p2.typeId_), state);
      result.MaybeAddDiff(
	  [&](std::ostream& os) {
	    os << "parameter " << i + 1;
	    const auto& n1 = p1.name_;
	    const auto& n2 = p2.name_;
	    if (n1 == n2 && !n1.empty())
	      {
		os << " (" << std::quoted(n1) << ")";
	      }
	    else if (n1 != n2)
	      {
		os << " (";
		if (!n1.empty())
		  os << "was " << std::quoted(n1);
		if (!n1.empty() && !n2.empty())
		  os << ", ";
		if (!n2.empty())
		  os << "now " << std::quoted(n2);
		os << ")";
	      }
	    os << " type";
	  },
	  sub_diff);
    }

  bool added = parameters1.size() < parameters2.size();
  const auto& parameters = added ? parameters2 : parameters1;
  for (size_t i = min; i < parameters.size(); ++i)
    {
      const auto& parameter = parameters.at(i);
      std::ostringstream os;
      os << "parameter " << i + 1;
      if (!parameter.name_.empty())
	os << " (" << std::quoted(parameter.name_) << ")";
      os << " of type";
      const auto& parameter_type = GetTypeAtIndex(parameter.typeId_);
      auto diff = added ? Added(parameter_type, state)
			: Removed(parameter_type, state);
      result.AddDiff(os.str(), diff);
    }

  return result;
}

// NOTE: not yet encountered in the wild
Result
Variable::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<Variable>();

  result.MaybeAddDiff("linkage", GetLinkage(), o.GetLinkage());
  const auto var_diff = Compare(GetTypeAtIndex(GetVarTypeId()),
				o.GetTypeAtIndex(o.GetVarTypeId()),
				state);
  result.MaybeAddDiff("type", var_diff);

  return result;
}

Result
DataSection::Equals(const Type& other, State& state) const
{
  Result result;
  result.AddDiff("Unimplemented");

  // NOTE: not yet encountered in the wild
  m_assert(false, "Unimplemented\n"); // NOLINT

  return result;
}

Result
ElfSymbol::Equals(const Type& other, State& state) const
{
  Result result;
  const auto& o = other.as<ElfSymbol>();
  // TODO: compare ELF symbol attributes
  const auto type_diff =
      Compare(GetTypeAtIndex(type_id_), o.GetTypeAtIndex(o.type_id_), state);
  result.MaybeAddDiff("type", type_diff);
  return result;
}

const Type&
Type::ResolveQualifiers(std::set<Kind>& qualifiers) const
{
  if (kind_ == BTF_KIND_ARRAY || kind_ == BTF_KIND_FUNC_PROTO)
    {
      // There should be no qualifiers here.
      qualifiers.clear();
    }
  return *this;
}

const Type&
Qualifier::ResolveQualifiers(std::set<Kind>& qualifiers) const
{
  qualifiers.insert(GetKind());
  return GetTypeAtIndex(GetQualifiedTypeId()).ResolveQualifiers(qualifiers);
}

const Type&
Type::ResolveTypedef(std::vector<std::string_view>& typedefs) const
{
  return *this;
}

const Type&
Typedef::ResolveTypedef(std::vector<std::string_view>& typedefs) const
{
  typedefs.push_back(GetName());
  return GetTypeAtIndex(GetReferredTypeId()).ResolveTypedef(typedefs);
}

std::ostream&
operator<<(std::ostream& os, const Type& bt)
{
  auto name = bt.GetName();
  os << kRawKindNames[bt.GetKind()] << " '" << (name.empty() ? "(anon)" : name)
     << '\'';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Ptr& bp)
{
  os << static_cast<const Type&>(bp) << " type_id=" << bp.GetPointeeTypeId()
     << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Typedef& bp)
{
  os << static_cast<const Type&>(bp) << " type_id=" << bp.GetReferredTypeId()
     << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Qualifier& bp)
{
  os << static_cast<const Type&>(bp) << " type_id=" << bp.GetQualifiedTypeId()
     << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Integer& bi)
{
  os << static_cast<const Type&>(bi) << " size=" << bi.GetByteSize()
     << " bits_offset=" << bi.GetOffset() << " nr_bits=" << bi.GetBitSize()
     << " bool=" << bi.isBool() << " char=" << bi.isChar()
     << " signed=" << bi.isSigned() << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Array& ba)
{
  os << static_cast<const Type&>(ba) << " type_id=" << ba.GetElementTypeId()
     << " index_type_id=" << ba.GetIndexTypeId()
     << " nr_elems=" << ba.GetNumberOfElements() << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const StructUnion& bsu)
{
  os << static_cast<const Type&>(bsu) << " size=" << bsu.GetByteSize()
     << " vlen=" << bsu.GetMembers().size() << '\n';
  for (const auto& member : bsu.GetMembers())
    {
      os << "\t'" << member.first << '\''
	 << " type_id=" << member.second.typeId_
	 << " bits_offset=" << member.second.offset_;
      if (member.second.bitfieldSize_)
	os << " bitfield_size=" << member.second.bitfieldSize_;
      os << '\n';
    }
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Enumeration& be)
{
  os << static_cast<const Type&>(be) << " size=" << be.GetByteSize()
     << " vlen=" << be.GetEnums().size() << '\n';
  for (const auto& e : be.GetEnums())
    {
      os << "\t'" << e.first << "' val=" << e.second << '\n';
    }
  return os;
}

std::ostream&
operator<<(std::ostream& os, const ForwardDeclaration& bfd)
{
  os << static_cast<const Type&>(bfd) << " fwd_kind=" << bfd.GetFwdKind()
     << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Function& bf)
{
  os << static_cast<const Type&>(bf) << " type_id=" << bf.GetReferredTypeId()
     << " linkage=" << bf.GetLinkage() << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const FunctionPrototype& bfp)
{
  os << static_cast<const Type&>(bfp)
     << " ret_type_id=" << bfp.GetReturnTypeId()
     << " vlen=" << bfp.GetParameters().size() << '\n';
  for (const auto& param : bfp.GetParameters())
    {
      os << "\t'" << (param.name_.empty() ? "(anon)" : param.name_)
	 << "' type_id=" << param.typeId_ << '\n';
    }
  return os;
}

std::ostream&
operator<<(std::ostream& os, const Variable& bv)
{
  // NOTE: The odd comma is to match bpftool dump.
  os << static_cast<const Type&>(bv) << " type_id=" << bv.GetVarTypeId()
     << ", linkage=" << bv.GetLinkage() << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, const DataSection& bds)
{
  os << static_cast<const Type&>(bds) << " size=" << bds.GetByteSize() << '\n';
  for (const auto& secinfo : bds.GetSecinfos())
    {
      os << "\ttype_id=" << secinfo.typeId_ << " offset=" << secinfo.offset_
	 << " size=" << secinfo.bytesize_ << '\n';
    }
  return os;
}

std::ostream&
operator<<(std::ostream& os, const ElfSymbol& bes)
{
  os << static_cast<const Type&>(bes);
  // TODO: report ELF symbol attributes
  os << " type=" << bes.GetTypeId() << '\n';
  return os;
}

std::ostream&
operator<<(std::ostream& os, ForwardDeclarationKind kind)
{
  switch (kind)
    {
    case ForwardDeclarationKind::STRUCT:
      os << "struct";
      break;
    case ForwardDeclarationKind::UNION:
      os << "union";
      break;
    }
  return os;
}

std::ostream&
operator<<(std::ostream& os, Variable::Linkage linkage)
{
  auto ix = static_cast<size_t>(linkage);
  return os << (ix < kVarLinkage.size() ? kVarLinkage[ix] : "(unknown)");
}

std::ostream&
operator<<(std::ostream& os, Function::Linkage linkage)
{
  auto ix = static_cast<size_t>(linkage);
  return os << (ix < kFunLinkage.size() ? kFunLinkage[ix] : "(unknown)");
}

Structs::Structs(const char* start,
		 std::unique_ptr<abigail::ir::environment> env,
		 const abigail::symtab_reader::symtab_sptr tab,
		 const bool verbose)
  : env_(std::move(env)), tab_(tab), verbose_(verbose)
{
  header_ = reinterpret_cast<const btf_header*>(start);
  m_assert(header_->magic == 0xEB9F, "Magic field must be 0xEB9F for BTF");

  type_section_ = reinterpret_cast<const btf_type*>(start + header_->hdr_len
						    + header_->type_off);
  str_section_ = start + header_->hdr_len + header_->str_off;

  // every btf_type struct in the type section has an implicit type id.
  // type id 0 is reserved for void type, so it is set to a Void here.
  // The type section is parsed sequentially and type id is assigned to each
  // recognized type starting from id 1.
  types_.push_back(std::make_unique<Void>(types_, 0, "void", 0));

  if (verbose_)
    {
      PrintHeader();
    }
  BuildTypes();
  if (verbose_)
    {
      PrintStringSection();
    }

  // NOTE: a whole bunch of Linux kernel symbols appear with duplicate (but not
  // necessarily identical) BTF type information
  //
  // TODO: find a better way of resolving this
  bad_prefix_1_ = "__arm64_sys_";
  bad_prefix_2_ = "__arm64_compat_sys_";
  bad_names_ = {"arch_prctl_spec_ctrl_get",
		"arch_prctl_spec_ctrl_set",
		"ioremap_cache",
		"kvm_arch_set_irq_inatomic",
		"module_frob_arch_sections",
		"vsnprintf"};
}

void
Structs::PrintHeader()
{
  std::cout << "BTF header:\n"
	    << "\tmagic " << header_->magic << ", version "
	    << static_cast<int>(header_->version) << ", flags "
	    << static_cast<int>(header_->flags) << ", hdr_len "
	    << header_->hdr_len << "\n"
	    << "\ttype_off " << header_->type_off << ", type_len "
	    << header_->type_len << "\n"
	    << "\tstr_off " << header_->str_off << ", str_len "
	    << header_->str_len << "\n";
}

// vlen: vector length, the number of struct/union members
std::map<std::string, Member>
Structs::BuildMembers(bool kflag, const btf_member* members, size_t vlen)
{
  std::map<std::string, Member> result;
  int anonymous = 0;
  for (size_t i = 0; i < vlen; ++i)
    {
      const auto raw_offset = members[i].offset;
      Member member{
	  .typeId_ = members[i].type,
	  .offset_ = kflag ? BTF_MEMBER_BIT_OFFSET(raw_offset) : raw_offset,
	  .bitfieldSize_ = kflag ? BTF_MEMBER_BITFIELD_SIZE(raw_offset) : 0};
      std::string name = std::string(GetName(members[i].name_off));
      if (name.empty())
	{
	  name = "anon member #" + std::to_string(anonymous);
	  ++anonymous;
	}
      result.emplace(name, member);
    }
  return result;
}

// vlen: vector length, the number of enum values
std::map<std::string, int>
Structs::BuildEnums(const struct btf_enum* enums, size_t vlen)
{
  std::map<std::string, int> result;
  for (size_t i = 0; i < vlen; ++i)
    {
      result.emplace(std::string(GetName(enums[i].name_off)), enums[i].val);
    }
  return result;
}

// vlen: vector length, the number of parameters
std::vector<Parameter>
Structs::BuildParams(const struct btf_param* params, size_t vlen)
{
  std::vector<Parameter> result;
  result.reserve(vlen);
  for (size_t i = 0; i < vlen; ++i)
    {
      Parameter parameter{.name_ = std::string(GetName(params[i].name_off)),
			  .typeId_ = params[i].type};
      result.push_back(parameter);
    }
  return result;
}

// vlen: vector length, the number of variables
std::vector<Secinfo>
Structs::BuildDatasec(const btf_type* type, size_t vlen)
{
  std::vector<Secinfo> result;
  result.reserve(vlen);
  const auto* secinfos = reinterpret_cast<const btf_var_secinfo*>(type + 1);
  for (size_t i = 0; i < vlen; ++i)
    {
      Secinfo secinfo{.typeId_ = secinfos[i].type,
		      .offset_ = secinfos[i].offset,
		      .bytesize_ = secinfos[i].size};
      result.push_back(secinfo);
    }
  return result;
}

void
Structs::BuildTypes()
{
  m_assert(!(header_->type_off & (sizeof(uint32_t) - 1)),
	   "Unaligned type_off");
  if (header_->type_len == 0)
    {
      std::cerr << "No types found";
      return;
    }
  if (verbose_)
    {
      std::cout << "Type section:\n";
    }

  const char* curr = reinterpret_cast<const char*>(type_section_);
  const char* end = curr + header_->type_len;
  uint32_t index = 1;
  while (curr < end)
    {
      const btf_type* t = reinterpret_cast<const btf_type*>(curr);
      int type_size = BuildOneType(t, index);
      m_assert(type_size > 0, "Could not identify BTF type");
      curr += type_size;
      ++index;
    }

  BuildElfSymbols();
}

int
Structs::BuildOneType(const btf_type* t, uint32_t index)
{
  const auto kind = BTF_INFO_KIND(t->info);
  const auto vlen = BTF_INFO_VLEN(t->info);
  // Data following the btf_type struct.
  const void* data = reinterpret_cast<const void*>(t + 1);
  m_assert(kind >= 0 && kind < NR_BTF_KINDS, "Unknown BTF kind");

  if (verbose_)
    std::cout << '[' << index << "] ";
  int type_size = sizeof(struct btf_type);
  switch (kind)
    {
    case BTF_KIND_INT:
      {
	const auto bits = *reinterpret_cast<const uint32_t*>(data);
	types_.push_back(std::make_unique<Integer>(types_,
						   index,
						   GetName(t->name_off),
						   kind,
						   BTF_INT_ENCODING(bits),
						   BTF_INT_OFFSET(bits),
						   BTF_INT_BITS(bits),
						   t->size));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Integer>();
	  }
	type_size += sizeof(uint32_t);
	break;
      }
    case BTF_KIND_PTR:
      {
	types_.push_back(std::make_unique<Ptr>(
	    types_, index, GetName(t->name_off), kind, t->type));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Ptr>();
	  }
	break;
      }
    case BTF_KIND_TYPEDEF:
      {
	types_.push_back(std::make_unique<Typedef>(
	    types_, index, GetName(t->name_off), kind, t->type));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Typedef>();
	  }
	break;
      }
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
      {
	types_.push_back(std::make_unique<Qualifier>(
	    types_, index, GetName(t->name_off), kind, t->type));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Qualifier>();
	  }
	break;
      }
    case BTF_KIND_ARRAY:
      {
	const auto* array = reinterpret_cast<const struct btf_array*>(data);
	types_.push_back(std::make_unique<Array>(types_,
						 index,
						 GetName(t->name_off),
						 kind,
						 array->type,
						 array->index_type,
						 array->nelems));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Array>();
	  }
	type_size += sizeof(struct btf_array);
	break;
      }
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
      {
	const bool kflag = BTF_INFO_KFLAG(t->info);
	const auto* btf_members = reinterpret_cast<const btf_member*>(data);
	const auto members = BuildMembers(kflag, btf_members, vlen);
	types_.push_back(std::make_unique<StructUnion>(
	    types_, index, GetName(t->name_off), kind, t->size, members));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<StructUnion>();
	  }
	type_size += vlen * sizeof(struct btf_member);
	break;
      }
    case BTF_KIND_ENUM:
      {
	const auto* enums = reinterpret_cast<const struct btf_enum*>(data);
	std::map<std::string, int> enumerators = BuildEnums(enums, vlen);
	types_.push_back(std::make_unique<Enumeration>(
	    types_, index, GetName(t->name_off), kind, t->size, enumerators));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Enumeration>();
	  }
	type_size += vlen * sizeof(struct btf_enum);
	break;
      }
    case BTF_KIND_FWD:
      {
	const bool kflag = BTF_INFO_KFLAG(t->info);
	types_.push_back(std::make_unique<ForwardDeclaration>(
	    types_, index, GetName(t->name_off), kind, kflag));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<ForwardDeclaration>();
	  }
	break;
      }
    case BTF_KIND_FUNC:
      {
	const auto name = GetName(t->name_off);
	types_.push_back(std::make_unique<Function>(
	    types_, index, name, kind, t->type, Function::Linkage(vlen)));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Function>();
	  }
	bool inserted = btf_symbol_types_.insert({name, t->type}).second;
	if (!inserted)
	  {
	    // NOTE: duplicate BTF symbols could be considered a bug in pahole
	    //
	    // TODO: remove these checks once resolved
	    bool known =
		!name.compare(0, bad_prefix_1_.size(), bad_prefix_1_)
		|| !name.compare(0, bad_prefix_2_.size(), bad_prefix_2_)
		|| std::find(bad_names_.begin(), bad_names_.end(), name)
		       != bad_names_.end();
	    m_assert(known, "Insertion failed, duplicate found in symbol map");
	    (void) known;
	  }
	btf_symbols_.insert({name, types_.back().get()});
	break;
      }
    case BTF_KIND_FUNC_PROTO:
      {
	const auto* params = reinterpret_cast<const btf_param*>(data);
	std::vector<Parameter> parameters = BuildParams(params, vlen);
	types_.push_back(std::make_unique<FunctionPrototype>(
	    types_, index, GetName(t->name_off), kind, t->type, parameters));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<FunctionPrototype>();
	  }
	type_size += vlen * sizeof(struct btf_param);
	break;
      }
    case BTF_KIND_VAR:
      {
	// NOTE: not yet encountered in the wild
	const auto* variable = reinterpret_cast<const struct btf_var*>(data);
	const auto name = GetName(t->name_off);
	types_.push_back(
	    std::make_unique<Variable>(types_,
				       index,
				       name,
				       kind,
				       t->type,
				       Variable::Linkage(variable->linkage)));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<Variable>();
	  }

	bool inserted = btf_symbol_types_.insert({name, t->type}).second;
	m_assert(inserted, "Insertion failed, duplicate found in symbol map");
	(void) inserted;
	btf_symbols_.insert({name, types_.back().get()});

	type_size += sizeof(struct btf_var);
	break;
      }
    case BTF_KIND_DATASEC:
      {
	std::vector<Secinfo> secinfos = BuildDatasec(t, vlen);
	types_.push_back(std::make_unique<DataSection>(
	    types_, index, GetName(t->name_off), kind, t->size, secinfos));
	if (verbose_)
	  {
	    std::cout << types_.back()->as<DataSection>();
	  }
	type_size += vlen * sizeof(struct btf_var_secinfo);
      }
    }
  return type_size;
}

std::string_view
Structs::GetName(uint32_t name_off)
{
  m_assert(name_off < header_->str_len,
	   "The name offset exceeds the section length");
  const char* section_end = str_section_ + header_->str_len;
  const char* name_end = std::find(&str_section_[name_off], section_end, '\0');
  m_assert(name_end < section_end,
	   "The name continues past the string section limit");
  (void) name_end;

  std::string_view name{&str_section_[name_off]};
  return name;
}

void
Structs::PrintStringSection()
{
  std::cout << "String section:\n";
  const char* curr = str_section_;
  const char* limit = str_section_ + header_->str_len;
  while (curr < limit)
    {
      const char* pos = std::find(curr, limit, '\0');
      m_assert(pos < limit, "Error reading the string section");
      std::cout << ' ' << curr;
      curr = pos + 1;
    }
  std::cout << '\n';
}

void
Structs::BuildElfSymbols()
{
  const auto filter = [&]() {
    auto filter = tab_->make_filter();
    filter.set_public_symbols();
    return filter;
  }();
  for (const auto& symbol :
       abigail::symtab_reader::filtered_symtab(*tab_, filter))
    {
      const auto& symbol_name = symbol->get_name();
      const auto& main_symbol_name = symbol->get_main_symbol()->get_name();
      auto it = btf_symbol_types_.find(main_symbol_name);
      if (it == btf_symbol_types_.end())
	{
	  // missing BTF information is tracked explicitly
	  std::cerr << "ELF symbol " << std::quoted(symbol_name);
	  if (symbol_name != main_symbol_name)
	    std::cerr << " (aliased to " << std::quoted(main_symbol_name)
		      << ')';
	  std::cerr << " BTF info missing\n";
	  types_.push_back(nullptr);
	}
      else
	{
	  uint32_t type_id = it->second;
	  types_.push_back(
	      std::make_unique<ElfSymbol>(types_, symbol, type_id));
	}
      elf_symbols_.emplace(symbol_name, types_.back().get());
    }
}

class ElfHandle
{
public:
  ElfHandle(const std::string& path) : dwfl_(nullptr, dwfl_end)
  {
    string name;
    tools_utils::base_name(path, name);
    elf_version(EV_CURRENT);

    dwfl_ = std::unique_ptr<Dwfl, decltype(&dwfl_end)>(
	dwfl_begin(&offline_callbacks_), dwfl_end);
    auto dwfl_module =
	dwfl_report_offline(dwfl_.get(), name.c_str(), path.c_str(), -1);
    GElf_Addr bias;
    elf_handle_ = dwfl_module_getelf(dwfl_module, &bias);
  }

  // Conversion operator to act as a drop-in replacement for Elf*
  operator Elf*() const { return elf_handle_; }

  Elf*
  get() const
  {
    return elf_handle_;
  }

private:
  // Dwfl owns all our data, hence only keep track of this
  std::unique_ptr<Dwfl, decltype(&dwfl_end)> dwfl_;
  Elf* elf_handle_;

  Dwfl_Callbacks offline_callbacks_;
};

Structs
ReadFile(const std::string& path, bool verbose)
{
  using abigail::symtab_reader::symtab;

  ElfHandle elf(path);
  m_assert(elf.get() != nullptr, "Could not get elf handle from file.");

  Elf_Scn* btf_section =
      abigail::elf_helpers::find_section(elf, ".BTF", SHT_PROGBITS);
  m_assert(btf_section != nullptr,
	   "The given file does not have a BTF section");
  Elf_Data* elf_data = elf_rawdata(btf_section, 0);
  m_assert(elf_data != nullptr, "The BTF section is invalid");
  const char* btf_start = static_cast<char*>(elf_data->d_buf);

  auto env = std::make_unique<abigail::ir::environment>();
  auto tab = symtab::load(elf, env.get());

  return Structs(btf_start, std::move(env), std::move(tab), verbose);
}

} // end namespace btf
} // end namespace abigail
