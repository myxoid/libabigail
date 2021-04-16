// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// -*- Mode: C++ -*-
//
// Copyright (C) 2021 Google, Inc.
//
// Author: Giuliano Procida

/// @file

#include <fcntl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <libxml/xpath.h>

#include "abg-config.h"
//#include "abg-libxml-utils.h"
#include "abg-tools-utils.h"

const unsigned char* to_libxml(const char* str)
{
  return reinterpret_cast<const unsigned char*>(str);
}

const char* from_libxml(const unsigned char* str)
{
  return reinterpret_cast<const char*>(str);
}

// Remove a node and free its storage.
//
// Args:
//   node
void remove_node(xmlNodePtr node)
{
  xmlUnlinkNode(node);
  xmlFreeNode(node);
}

// Process nodes matching an XPath expression.
//
// Args:
//   doc
//   path
void process_nodes(xmlDocPtr doc, const char* path, std::function<void(const xmlNodePtr node)> fun)
{
  xmlXPathContextPtr path_context = xmlXPathNewContext(doc);
  xmlXPathObjectPtr path_object = xmlXPathEvalExpression(to_libxml(path), path_context);
  for (size_t i = 0; i < path_object->nodesetval->nodeNr; ++i) {
    xmlNodePtr node = path_object->nodesetval->nodeTab[i];
    fun(node);
  }
  xmlXPathFreeObject(path_object);
  xmlXPathFreeContext(path_context);
}

// Find nodes matching an XPath expression.
//
// Args:
//   doc
//   path
std::vector<xmlNodePtr> find_nodes(xmlDocPtr doc, const char* path)
{
  std::vector<xmlNodePtr> result;
  process_nodes(doc, path, [&result](const xmlNodePtr node) { result.push_back(node); });
  return result;
}

// Get child nodes of given node.
//
// Args:
//   doc
//   path
std::vector<xmlNodePtr> get_children(xmlNodePtr node)
{
  std::vector<xmlNodePtr> result;
  for (xmlNodePtr child = node->children; child; child = child->next)
    result.push_back(child);
  return result;
}

// Strip text (non-element) nodes from XML.
//
// This simplifies DOM analysis and manipulation.
//
void strip_text(xmlDocPtr doc)
{
  process_nodes(doc, "//text()", [](const xmlNodePtr node) { remove_node(node); });
}

// Make a text node.
//
// Args:
//   doc
//   text
xmlNodePtr make_text(const std::string& str)
{
  return xmlNewTextLen(to_libxml(str.data()), str.size());
}

// Insert node before

// Format XML by adding indentation and newlines.
//
// This makes the XML readable.
//
// Args:
//   indent - the current indentation level
void format_xml(size_t indent, xmlNodePtr node)
{
  ABG_ASSERT(node->type != XML_TEXT_NODE);
  std::vector<xmlNodePtr> children = get_children(node);
  if (!children.empty())
    {
      // The ordering of operations here is incidental. The outcomes we want
      // are: 1. an extra newline after the opening tag and indentation of the
      // closing tag to match, and 2. indentation and newline for each child.
      size_t more_indent = indent + 2;
      xmlAddPrevSibling(children[0], make_text("\n"));
      xmlAddNextSibling(children[children.size()-1], make_text(std::string(indent, ' ')));
      for (xmlNodePtr child : children)
        {
          xmlAddPrevSibling(child, make_text(std::string(more_indent, ' ')));
          format_xml(more_indent, child);
          xmlAddNextSibling(child, make_text("\n"));
        }
    }
  else
    {
      for (xmlNodePtr child : children)
        format_xml(indent, child);
    }
}

static const std::unordered_set<std::string> drop_if_empty = {
  "elf-variable-symbols",
  "elf-function-symbols",
  "namespace-decl",
  "abi-instr",
  "abi-corpus",
  "abi-corpus-group",
};

// Drop empty elements, if safe to do so, recursively.
//
// Args:
//   node
//
void drop_empty(xmlNodePtr node)
{
  for (xmlNodePtr child : get_children(node))
    drop_empty(child);
  if (!node->children && node->type == XML_ELEMENT_NODE && drop_if_empty.count(from_libxml(node->name)))
    // Until abidiff accepts empty ABIs, avoid dropping top-level elements.
    if (node->parent->type == XML_ELEMENT_NODE)
      remove_node(node);
}

// Prune unreachable elements.
//
// Reachability is defined to be union of contains, containing and refers to
// relationships for types, decls and symbols. The roots for reachability are
// the ELF elements in the ABI.
//
// Args:
//
//
void prune_unreachable(xmlDocPtr doc)
{
  std::unordered_set<std::string> elf_symbols;
  // Graph vertices (only needed for statistics).
  std::unordered_set<std::string> vertices;
  // Graph edges.
  std::unordered_map<std::string, std::unordered_set<std::string>> edges;

  // Keep track of type / symbol nesting.
  std::vector<std::string> stack;

  // Traverse the whole XML DOM.
  auto make_graph = [&](xmlNodePtr node) {
    // The XML attributes we care about.
    std::string name;
    std::string id;
    std::string type_id;
    std::string symbol;
    std::string naming_typedef_id;

    // Not every node we encounter is an XML element.
    if (node->type == XML_ELEMENT_NODE) {
      $name = $node->getAttribute("name");
      $id = $node->getAttribute("id");
      $type_id = $node->getAttribute("type-id");
      $symbol = $node->getAttribute("mangled-name");
      $naming_typedef_id = $node->getAttribute("naming-typedef-id");
      die if defined $id && defined $symbol;
    }

    if (defined $name && $node->getName() == "elf-symbol")
      {
        elf_symbols.insert(name);
        // Early return is safe, but not necessary.
        return;
      }

    if (defined $id) {
      my $vertex = "type:$id";
      # This element defines a type (but there may be more than one
      # defining the same type - we cannot rely on uniqueness).
      $vertices{$vertex} = undef;
      if (defined $naming_typedef_id) {
        # This is an odd one, there can be a backwards link from an
        # anonymous type to the typedef that refers to it, so we need to
        # pull in the typedef, even if nothing else refers to it.
        $edges{$vertex}{"type:$naming_typedef_id"} = undef;
      }
      if (@stack) {
        # Parent<->child dependencies; record dependencies both
        # ways to avoid holes in XML types and declarations.
        $edges{$stack[-1]}{$vertex} = undef;
        $edges{$vertex}{$stack[-1]} = undef;
      }
      push @stack, $vertex;
    }

    if (defined $symbol) {
      my $vertex = "symbol:$symbol";
      # This element is a declaration linked to a symbol (whether or not
      # exported).
      $vertices{$vertex} = undef;
      if (@stack) {
        # Parent<->child dependencies; record dependencies both ways
        # to avoid holes in XML types and declarations.
        #
        # Symbols exist outside of the type hierarchy, so choosing to
        # make them depend on a containing type scope and vice versa
        # is conservative and probably not necessary.
        $edges{$stack[-1]}{$vertex} = undef;
        $edges{$vertex}{$stack[-1]} = undef;
      }
      # The symbol depends on the types mentioned in this element, so
      # record it.
      push @stack, $vertex;
      # In practice there will be at most one symbol on the stack; we
      # could verify this here, but it wouldn't achieve anything.
    }

    if (defined $type_id) {
      if (@stack) {
        # The enclosing type or symbol refers to another type.
        $edges{$stack[-1]}{"type:$type_id"} = undef;
      }
    }

    for my $child ($node->childNodes()) {
      __SUB__->($child);
    }

    if (defined $symbol) {
      pop @stack;
    }
    if (defined $id) {
      pop @stack;
    }
  }

  # Build a graph.
  make_graph($dom);
  die if @stack;
  #warn Dumper(\%elf_symbols, \%vertices, \%edges);

  # DFS visited state. Would be nicer with a flat namespace of nodes.
  my %seen;
  my sub dfs($vertex) {
    no warnings 'recursion';
    return if exists $seen{$vertex};
    $seen{$vertex} = undef;

    my $tos = $edges{$vertex};
    if (defined $tos) {
      for my $to (keys %$tos) {
        __SUB__->($to);
      }
    }
  }

  # Traverse the graph, starting from the exported symbols.
  for my $symbol (keys %elf_symbols) {
    my $vertex = "symbol:$symbol";
    if (exists $vertices{$vertex}) {
      dfs($vertex);
    } else {
      warn "no declaration found for ELF symbol $symbol\n";
    }
  }

  #warn Dumper(\%seen);

  # Useful counts.
  my sub print_report() {
    my $count_elf_symbols = scalar keys %elf_symbols;
    my $count_vertices = scalar keys %vertices;
    my $count_seen = scalar keys %seen;

    warn qq{ELF = $count_elf_symbols
vertices = $count_vertices
seen = $count_seen
};
  }

  #print_report();

  # XPath selection is too slow as we end up enumerating lots of
  # nested items whose preservation is entirely determined by their
  # containing items. DFS with early stopping for the win.
  my sub remove_unwanted($node) {
    my $node_name = $node->getName();
    my $name;
    my $id;
    my $symbol;

    if ($node->nodeType == XML_ELEMENT_NODE) {
      $name = $node->getAttribute('name');
      $id = $node->getAttribute('id');
      $symbol = $node->getAttribute('mangled-name');
      die if defined $id && defined $symbol;
    }

    # Return if we know that this is a type or declaration to keep or
    # drop in its entirety.
    if (defined $id) {
      remove_node($node) unless exists $seen{"type:$id"};
      return;
    }
    if ($node_name eq 'var-decl' || $node_name eq 'function-decl') {
      remove_node($node) unless defined $symbol && exists $seen{"symbol:$symbol"};
      return;
    }

    # Otherwise, this is not a type, declaration or part thereof, so
    # process child elements.
    for my $child ($node->childNodes()) {
      __SUB__->($child);
    }
  }

  remove_unwanted($dom);
}
}

int main(int argc, char * argv[])
{
  // Defaults.
  const char * opt_in = NULL;
  const char * opt_out = NULL;
  bool opt_drop_empty = false;
  bool opt_prune_unreachable = false;

  // Process command line.
  auto usage = [&]() -> int {
    std::cerr << "usage: " << argv[0]
              << " [-i|--input file]"
              << " [-o|--output file]"
              << " [-a|--all]"
              << " [-d|--[no-]drop-empty]"
              << " [-p|--[no-]prune-unreachable]",
              << '\n';
    return 1;
  };
  int opt_index = 1;
  auto get_arg = [&]() {
    if (opt_index < argc)
      return argv[opt_index++];
    exit(usage());
  };
  while (opt_index < argc)
    {
      const char * arg = get_arg();
      if (!strcmp(arg, "-i") || !strcmp(arg, "--input"))
        opt_in = get_arg();
      else if (!strcmp(arg, "-o") || !strcmp(arg, "--output"))
        opt_out = get_arg();
      else if (!strcmp(arg, "-a") || !strcmp(arg, "--all"))
        opt_prune_unreachable = opt_drop_empty = true;
      else if (!strcmp(arg, "-d") || !strcmp(arg, "--drop-empty"))
        opt_drop_empty = true;
      else if (!strcmp(arg, "--no-drop-empty"))
        opt_drop_empty = false;
      else if (!strcmp(arg, "-p") || !strcmp(arg, "--prune-unreachable"))
        opt_prune_unreachable = true;
      else if (!strcmp(arg, "--no-prune-unreachable"))
        opt_prune_unreachable = false;
      else
        exit(usage());
    }

  // Open input for reading.
  int in_fd = STDIN_FILENO;
  if (opt_in)
    {
      in_fd = open(opt_in, O_RDONLY);
      if (in_fd < 0)
        {
          std::cerr << "could not open '" << opt_in << "' for reading: " << strerror(errno) << '\n';
          exit(1);
        }
    }

  // Read the XML.
  xmlParserCtxtPtr parser_context = xmlNewParserCtxt();
  xmlDocPtr doc = xmlCtxtReadFd(parser_context, in_fd, NULL, NULL, 0);
  close(in_fd);

  // Strip text nodes to simplify other operations.
  strip_text(doc);

  // Prune unreachable elements.
  if (opt_prune_unreachable)
    prune_unreachable(doc);

  // Drop empty elements.
  if (opt_drop_empty)
    for (xmlNodePtr node = doc->children; node; node = node->next)
      drop_empty(node);

  // Reformat XML for human consumption.
  for (xmlNodePtr node = doc->children; node; node = node->next)
    format_xml(0, node);

  // Open output for writing.
  int out_fd = STDOUT_FILENO;
  if (opt_out)
    {
      open(opt_out, O_CREAT|O_TRUNC|O_WRONLY);
      if (out_fd < 0)
        {
          std::cerr << "could not open '" << opt_out << "' for writing: " << strerror(errno) << '\n';
          exit(1);
        }
    }

  // Write the XML.
  // To memory, as we need to do a little post-processing.
  xmlChar * out_data;
  int out_size;
  xmlDocDumpFormatMemory(doc, &out_data, &out_size, 0);
  // Remove the XML declaration as this is not currently accepted by abidiff.
  xmlChar * out_limit = out_data + out_size;
  while (out_data < out_limit && *out_data != '\n')
    ++out_data;
  if (out_data < out_limit)
    ++out_data;
  size_t count = out_limit - out_data;
  // Use single quotes for attributes as that's what abidw does.
  for (xmlChar * c = out_data; c < out_limit; ++c)
    if (*c == '"')
      *c = '\'';
  // And now to a file.
  if (write(out_fd, out_data, count) != count)
    {
      std::cerr << "could not write output: " << strerror(errno) << '\n';
      exit(1);
    }
  if (close(out_fd) < 0)
    {
      std::cerr << "could not close output: " << strerror(errno) << '\n';
      exit(1);
    }

  // Free XML data structures.
  xmlFreeDoc(doc);
  xmlFreeParserCtxt(parser_context);
  return 0;
}
