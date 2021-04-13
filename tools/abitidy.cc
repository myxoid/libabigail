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

int main(int argc, char * argv[])
{
  // Defaults.
  const char * opt_in = NULL;
  const char * opt_out = NULL;

  // Process command line.
  auto usage = [&]() -> int {
    std::cerr << "usage: " << argv[0]
              << " [-i|--input file]"
              << " [-o|--output file]"
              << " [-a|--all]"
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
        ;
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
