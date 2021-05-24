// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- mode: C++ -*-
//
// Copyright (C) 2020-2021 Google, Inc.
//
// Author: Maria Teguiani
// Author: Giuliano Procida

#ifndef __ABG_BTF_H__
#define __ABG_BTF_H__

#include <fcntl.h>
#include <linux/btf.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "abg-ir.h"
#include "abg-scc.h"

namespace abigail
{
namespace btf
{

#define m_assert(expr, msg) assert(((void) (msg), (expr)))

using Kind = uint32_t;

// A Member refers to a data element of a struct or union, used in the context
// of StructUnion
struct Member
{
  uint32_t typeId_;
  uint32_t offset_;
  uint32_t bitfieldSize_;
};

// A Parameter refers to a variable declared in the function declaration, used
// in the context of Function
struct Parameter
{
  std::string name_;
  uint32_t typeId_;
};

struct Secinfo
{
  uint32_t typeId_;
  uint32_t offset_;
  uint32_t bytesize_;
};

enum class ForwardDeclarationKind
{
  STRUCT,
  UNION
};

std::ostream&
operator<<(std::ostream& os, ForwardDeclarationKind kind);

class Type;

using Comparison = std::pair<const Type*, const Type*>;

enum class Precedence
{
  NIL,
  POINTER,
  ARRAY_FUNCTION,
  ATOMIC
};
enum class Side
{
  LEFT,
  RIGHT
};

class Name
{
public:
  explicit Name(std::string_view name)
    : left_(name), precedence_(Precedence::NIL), right_()
  {
  }
  Name(std::string_view left, Precedence precedence, std::string_view right)
    : left_(left), precedence_(precedence), right_(right)
  {
  }
  Name
  Add(Side side, Precedence precedence, std::string_view text) const;
  Name
  Qualify(const std::set<Kind>& qualifiers) const;
  std::ostream&
  Print(std::ostream& os) const;

private:
  std::string left_;
  Precedence precedence_;
  std::string right_;
};

std::ostream&
operator<<(std::ostream& os, const Name& name);

using NameCache = std::unordered_map<const Type*, Name>;

struct DiffDetail
{
  DiffDetail(const std::string& text, const std::optional<Comparison>& edge)
    : text_(text), edge_(edge)
  {
  }
  std::string text_;
  std::optional<Comparison> edge_;
};

using Diff = std::vector<DiffDetail>;

struct Result
{
  void
  AddDiff(const std::string& text)
  {
    equals_ = false;
    details_.emplace_back(text, std::optional<Comparison>());
  }

  void
  AddDiff(const std::string& text, Comparison comparison)
  {
    equals_ = false;
    details_.emplace_back(text, comparison);
  }

  void
  MaybeAddDiff(const std::string& text,
	       const std::pair<bool, std::optional<Comparison>>& p)
  {
    equals_ &= p.first;
    const auto& diff = p.second;
    if (diff)
      details_.emplace_back(text, diff);
  }

  // Maximally powerful lazy version, takes a function that outputs an "edge"
  // diff description, to be used only when a diff is present.
  void
  MaybeAddDiff(std::function<void(std::ostream&)> text,
	       const std::pair<bool, std::optional<Comparison>>& p)
  {
    equals_ &= p.first;
    const auto& diff = p.second;
    if (diff)
      {
	std::ostringstream os;
	text(os);
	details_.emplace_back(os.str(), diff);
      }
  }

  template <typename T>
  void
  MaybeAddDiff(const std::string& text, const T& before, const T& after)
  {
    if (before != after)
      {
	equals_ = false;
	std::ostringstream os;
	os << text << " changed from " << before << " to " << after;
	AddDiff(os.str());
      }
  }

  // Lazy version.
  template <typename T>
  void
  MaybeAddDiff(std::function<void(std::ostream&)> text,
	       const T& before,
	       const T& after)
  {
    if (before != after)
      {
	equals_ = false;
	std::ostringstream os;
	text(os);
	os << " changed from " << before << " to " << after;
	AddDiff(os.str());
      }
  }

  bool equals_ = true;
  Diff details_;
};

using Outcomes = std::map<Comparison, Diff>;
// unvisited (absent) -> started (false) -> finished (true)
using Seen = std::map<Comparison, bool>;

void
Print(const Comparison& comparison,
      const Outcomes& outcomes,
      Seen& seen,
      NameCache& names,
      std::ostream& os,
      size_t indent = 0);

void
Print(const Diff& details,
      const Outcomes& outcomes,
      Seen& seen,
      NameCache& names,
      std::ostream& os,
      size_t indent = 0);

class Type
{
public:
  Type(const std::vector<std::unique_ptr<Type>>& types,
       uint32_t index,
       std::string_view name,
       Kind kind)
    : types_(types), index_(index), name_(name), kind_(kind)
  {
  }
  virtual ~Type() = default;
  uint32_t
  GetIndex() const
  {
    return index_;
  }
  std::string_view
  GetName() const
  {
    return name_;
  }
  Kind
  GetKind() const
  {
    return kind_;
  }
  const std::vector<std::unique_ptr<Type>>&
  GetTypes() const
  {
    return types_;
  }

  // as<Type>() provides a method to defer downcasting to the base class,
  // instead of needing to use dynamic_cast in a local context. If the type is
  // not correct, the assert will trigger in debug mode. In release mode, this
  // will crash dereferencing the nullptr.
  template <typename Target>
  const Target&
  as() const
  {
    static_assert(std::is_convertible<Target*, Type*>::value,
		  "Target must publically inherit Type");
    const Target* t = dynamic_cast<const Target*>(this);
    m_assert(t, "Invalid downcast");
    return *t;
  }
  // Separate qualifiers from underlying type.
  //
  // The caller must always be prepared to receive a different type as
  // qualifiers are sometimes discarded.
  virtual const Type&
  ResolveQualifiers(std::set<Kind>& qualifiers) const;
  virtual const Type&
  ResolveTypedef(std::vector<std::string_view>& typedefs) const;

  const Name&
  GetDescription(NameCache& names) const;
  static Result
  CompareSymbols(const std::map<std::string_view, const Type* const>& lhs,
		 const std::map<std::string_view, const Type* const>& rhs,
		 Outcomes& outcomes);

protected:
  struct State
  {
    explicit State(Outcomes& o) : outcomes(o), scc(o.value_comp()) {}
    Outcomes& outcomes;
    std::set<Comparison> known_equal;
    SCC<Outcomes::value_type> scc;
  };
  const Type&
  GetTypeAtIndex(size_t index) const;

  virtual Name
  MakeDescription(NameCache& names) const = 0;
  virtual Result
  Equals(const Type& other, State& state) const = 0;
  static Comparison
  Removed(const Type& lhs, State& state);
  static Comparison
  Added(const Type& rhs, State& state);
  static std::pair<bool, std::optional<Comparison>>
  Compare(const Type& lhs, const Type& rhs, State& state);

private:
  static std::string
  GetDiffMessage(NameCache& names,
		 const Type& lhs,
		 const Type& rhs,
		 const std::string& message = std::string());
  const std::vector<std::unique_ptr<Type>>& types_;
  const uint32_t index_;
  const std::string name_;
  const Kind kind_;
};

class Void : public Type
{
public:
  Void(const std::vector<std::unique_ptr<Type>>& types,
       uint32_t index,
       std::string_view name,
       Kind kind)
    : Type(types, index, name, kind)
  {
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;
};

class Ptr : public Type
{
public:
  Ptr(const std::vector<std::unique_ptr<Type>>& types,
      uint32_t index,
      std::string_view name,
      Kind kind,
      uint32_t pointeeTypeId)
    : Type(types, index, name, kind), pointeeTypeId_(pointeeTypeId)
  {
  }
  uint32_t
  GetPointeeTypeId() const
  {
    return pointeeTypeId_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t pointeeTypeId_;
};

class Typedef : public Type
{
public:
  Typedef(const std::vector<std::unique_ptr<Type>>& types,
	  uint32_t index,
	  std::string_view name,
	  Kind kind,
	  uint32_t referredTypeId)
    : Type(types, index, name, kind), referredTypeId_(referredTypeId)
  {
  }
  uint32_t
  GetReferredTypeId() const
  {
    return referredTypeId_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;
  const Type&
  ResolveTypedef(std::vector<std::string_view>& typedefs) const final;

private:
  const uint32_t referredTypeId_;
};

class Qualifier : public Type
{
public:
  Qualifier(const std::vector<std::unique_ptr<Type>>& types,
	    uint32_t index,
	    std::string_view name,
	    Kind kind,
	    uint32_t qualifiedTypeId)
    : Type(types, index, name, kind), qualifiedTypeId_(qualifiedTypeId)
  {
  }
  uint32_t
  GetQualifiedTypeId() const
  {
    return qualifiedTypeId_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;
  const Type&
  ResolveQualifiers(std::set<Kind>& qualifiers) const final;

private:
  const uint32_t qualifiedTypeId_;
};

class Integer : public Type
{
public:
  Integer(const std::vector<std::unique_ptr<Type>>& types,
	  uint32_t index,
	  std::string_view name,
	  Kind kind,
	  uint32_t encoding,
	  uint32_t offset,
	  uint32_t bitsize,
	  uint32_t bytesize)
    : Type(types, index, name, kind),
      offset_(offset),
      bitsize_(bitsize),
      bytesize_(bytesize),
      isBool_(encoding & BTF_INT_BOOL),
      isSigned_(encoding & BTF_INT_SIGNED),
      isChar_(encoding & BTF_INT_CHAR)
  {
  }
  bool
  isBool() const
  {
    return isBool_;
  }
  bool
  isSigned() const
  {
    return isSigned_;
  }
  bool
  isChar() const
  {
    return isChar_;
  }
  uint32_t
  GetOffset() const
  {
    return offset_;
  }

  // GetBitSize() gives the semantics of the field. GetByteSize() gives the
  // storage size, and is equal or greater than GetBitSize()*8
  uint32_t
  GetBitSize() const
  {
    return bitsize_;
  }
  uint32_t
  GetByteSize() const
  {
    return bytesize_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t offset_;
  const uint32_t bitsize_;
  const uint32_t bytesize_;
  const bool isBool_;
  const bool isSigned_;
  const bool isChar_;
};

class Array : public Type
{
public:
  Array(const std::vector<std::unique_ptr<Type>>& types,
	uint32_t index,
	std::string_view name,
	Kind kind,
	uint32_t elementTypeId,
	uint32_t indexTypeId,
	uint32_t numOfElements)
    : Type(types, index, name, kind),
      elementTypeId_(elementTypeId),
      indexTypeId_(indexTypeId),
      numOfElements_(numOfElements)
  {
  }
  uint32_t
  GetElementTypeId() const
  {
    return elementTypeId_;
  }
  uint32_t
  GetIndexTypeId() const
  {
    return indexTypeId_;
  }
  uint32_t
  GetNumberOfElements() const
  {
    return numOfElements_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t elementTypeId_;
  const uint32_t indexTypeId_;
  const uint32_t numOfElements_;
};

class StructUnion : public Type
{
public:
  StructUnion(const std::vector<std::unique_ptr<Type>>& types,
	      uint32_t index,
	      std::string_view name,
	      Kind kind,
	      uint32_t bytesize,
	      std::map<std::string, Member> members)
    : Type(types, index, name, kind), bytesize_(bytesize), members_(members)
  {
  }
  uint32_t
  GetByteSize() const
  {
    return bytesize_;
  }
  const std::map<std::string, Member>&
  GetMembers() const
  {
    return members_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t bytesize_;
  const std::map<std::string, Member> members_;
};

class Enumeration : public Type
{
public:
  Enumeration(const std::vector<std::unique_ptr<Type>>& types,
	      uint32_t index,
	      std::string_view name,
	      Kind kind,
	      uint32_t bytesize,
	      std::map<std::string, int> enumerators)
    : Type(types, index, name, kind),
      bytesize_(bytesize),
      enumerators_(enumerators)
  {
  }
  uint32_t
  GetByteSize() const
  {
    return bytesize_;
  }
  const std::map<std::string, int>&
  GetEnums() const
  {
    return enumerators_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t bytesize_;
  const std::map<std::string, int> enumerators_;
};

// BTF only considers structs and unions as forward-declared types, and does
// not include forward-declared enums. They are treated as BTF_KIND_ENUMs with
// vlen set to zero
class ForwardDeclaration : public Type
{
public:
  ForwardDeclaration(const std::vector<std::unique_ptr<Type>>& types,
		     uint32_t index,
		     std::string_view name,
		     Kind kind,
		     bool isUnion)
    : Type(types, index, name, kind),
      fwdKind_(isUnion ? ForwardDeclarationKind::UNION
		       : ForwardDeclarationKind::STRUCT)
  {
  }
  ForwardDeclarationKind
  GetFwdKind() const
  {
    return fwdKind_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const ForwardDeclarationKind fwdKind_;
};

class Function : public Type
{
public:
  enum class Linkage : uint16_t
  {
    STATIC,
    GLOBAL,
    EXTERN
  };
  Function(const std::vector<std::unique_ptr<Type>>& types,
	   uint32_t index,
	   std::string_view name,
	   Kind kind,
	   uint32_t referredTypeId,
	   Linkage linkage)
    : Type(types, index, name, kind),
      referredTypeId_(referredTypeId),
      linkage_(linkage)
  {
  }
  uint32_t
  GetReferredTypeId() const
  {
    return referredTypeId_;
  }
  Linkage
  GetLinkage() const
  {
    return linkage_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t referredTypeId_;
  const Linkage linkage_;
};

class FunctionPrototype : public Type
{
public:
  FunctionPrototype(const std::vector<std::unique_ptr<Type>>& types,
		    uint32_t index,
		    std::string_view name,
		    Kind kind,
		    uint32_t returnTypeId,
		    std::vector<Parameter> parameters)
    : Type(types, index, name, kind),
      returnTypeId_(returnTypeId),
      parameters_(parameters)
  {
  }
  uint32_t
  GetReturnTypeId() const
  {
    return returnTypeId_;
  }
  const std::vector<Parameter>&
  GetParameters() const
  {
    return parameters_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t returnTypeId_;
  const std::vector<Parameter> parameters_;
};

class Variable : public Type
{
public:
  enum class Linkage : uint32_t
  {
    STATIC,
    GLOBAL_ALLOC,
    GLOBAL_EXTERN
  };
  Variable(const std::vector<std::unique_ptr<Type>>& types,
	   uint32_t index,
	   std::string_view name,
	   Kind kind,
	   unsigned varTypeId,
	   Linkage linkage)
    : Type(types, index, name, kind), varTypeId_(varTypeId), linkage_(linkage)
  {
  }
  uint32_t
  GetVarTypeId() const
  {
    return varTypeId_;
  }
  Linkage
  GetLinkage() const
  {
    return linkage_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t varTypeId_;
  const Linkage linkage_;
};

class DataSection : public Type
{
public:
  DataSection(const std::vector<std::unique_ptr<Type>>& types,
	      uint32_t index,
	      std::string_view name,
	      Kind kind,
	      uint32_t bytesize,
	      std::vector<Secinfo> secinfos)
    : Type(types, index, name, kind), bytesize_(bytesize), secinfos_(secinfos)
  {
  }
  uint32_t
  GetByteSize() const
  {
    return bytesize_;
  }
  const std::vector<Secinfo>&
  GetSecinfos() const
  {
    return secinfos_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  const uint32_t bytesize_;
  const std::vector<Secinfo> secinfos_;
};

// Not actually a BTF type but needed for uniformity of representation.
class ElfSymbol : public Type
{
public:
  ElfSymbol(const std::vector<std::unique_ptr<Type>>& types,
	    abigail::elf_symbol_sptr symbol,
	    uint32_t type_id)
    : Type(types, -1, {}, -1), symbol_(symbol), type_id_(type_id)
  {
  }
  abigail::elf_symbol_sptr
  GetElfSymbol() const
  {
    return symbol_;
  }
  uint32_t
  GetTypeId() const
  {
    return type_id_;
  }
  Name
  MakeDescription(NameCache& names) const final;
  Result
  Equals(const Type& other, State& state) const final;

private:
  abigail::elf_symbol_sptr symbol_;
  uint32_t type_id_;
};

std::ostream&
operator<<(std::ostream& os, const Type& bt);
std::ostream&
operator<<(std::ostream& os, const Ptr& bp);
std::ostream&
operator<<(std::ostream& os, const Typedef& bp);
std::ostream&
operator<<(std::ostream& os, const Qualifier& bp);
std::ostream&
operator<<(std::ostream& os, const Integer& bi);
std::ostream&
operator<<(std::ostream& os, const Array& ba);
std::ostream&
operator<<(std::ostream& os, const StructUnion& bsu);
std::ostream&
operator<<(std::ostream& os, const Enumeration& be);
std::ostream&
operator<<(std::ostream& os, const ForwardDeclaration& bfd);
std::ostream&
operator<<(std::ostream& os, const Function& bf);
std::ostream&
operator<<(std::ostream& os, const FunctionPrototype& bfp);
std::ostream&
operator<<(std::ostream& os, const Variable& bv);
std::ostream&
operator<<(std::ostream& os, const DataSection& bds);
std::ostream&
operator<<(std::ostream& os, const ElfSymbol& bes);
std::ostream&
operator<<(std::ostream& os, Variable::Linkage linkage);
std::ostream&
operator<<(std::ostream& os, Function::Linkage linkage);

// BTF Specification: https://www.kernel.org/doc/html/latest/bpf/btf.html
class Structs
{
public:
  Structs(const char* start,
	  std::unique_ptr<abigail::ir::environment> env,
	  const abigail::symtab_reader::symtab_sptr tab,
	  const bool verbose = false);
  ~Structs() = default;
  void
  PrintHeader();
  void
  BuildTypes();
  void
  PrintStringSection();
  const std::map<std::string_view, const Type* const>&
  GetSymbols(bool use_elf_symbols) const
  {
    return use_elf_symbols ? elf_symbols_ : btf_symbols_;
  }

private:
  const btf_header* header_;
  const btf_type* type_section_;
  const char* str_section_;
  const std::unique_ptr<abigail::ir::environment> env_;
  const abigail::symtab_reader::symtab_sptr tab_;
  const bool verbose_;

  std::vector<std::unique_ptr<Type>> types_;
  std::unordered_map<std::string_view, uint32_t> btf_symbol_types_;
  std::map<std::string_view, const Type* const> btf_symbols_;
  std::map<std::string_view, const Type* const> elf_symbols_;

  std::vector<std::string> bad_names_;
  std::string bad_prefix_1_;
  std::string bad_prefix_2_;

  int
  BuildOneType(const btf_type* t, uint32_t index);
  void
  BuildElfSymbols();
  std::map<std::string, Member>
  BuildMembers(bool kflag, const btf_member* members, size_t vlen);
  std::map<std::string, int>
  BuildEnums(const struct btf_enum* enums, size_t vlen);
  std::vector<Parameter>
  BuildParams(const struct btf_param* params, size_t vlen);
  std::vector<Secinfo>
  BuildDatasec(const btf_type* type, size_t vlen);
  std::string_view
  GetName(uint32_t name_off);
};

Structs
ReadFile(const std::string& path, bool verbose = false);

} // end namespace btf
} // end namespace abigail

#endif // __ABG_BTF_H__
