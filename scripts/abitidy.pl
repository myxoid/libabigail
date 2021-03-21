#!/usr/bin/perl

# This script is intended to consume libabigail ABI XML as generated
# by abidw and produce a possibly smaller representation that captures
# the same ABI. In particular, the output should be such that abidiff
# --harmless reports no differences (or is empty).

use v5.32.0;
use strict;
use warnings;
use experimental 'signatures';

use autodie;

use Data::Dumper;
use Getopt::Long;
use IO::File;
use XML::LibXML;

# Overview of ABI XML elements and their roles
#
# ELF
#
# elf-needed - container
#  dependency - names a library
# elf-variable-symbols - contains a list of symbols
# elf-function-symbols - contains a list of symbols
#  elf-symbol - describes an ELF variable or function
#
# Grouping and scoping
#
# abi-corpus-group
#  abi-corpus
#   abi-instr - compilation unit containers
#    namespace-decl - pure container, possibly named
#
# Types (some introduce scopes, only in C++)
#
# type-decl - defines a primitive type
# typedef-decl - defines a type, links to a type
# qualified-type-def - defines a type, links to a type
# pointer-type-def - defines a type, links to a type
# reference-type-def - defines a type, links to a type
# array-type-def - defines a (multidimensional array) type, refers to element type, contains subranges
#  subrange - contains array length, refers to element type; defines types (never referred to; duplicated)
# function-type - defines a type
#  parameter - belongs to function-type and -decl, links to a type
#  return - belongs to function-type and -decl, links to a type
# enum-decl - defines a type, names it, contains a list of enumerators and an underlying-type
#  underlying-type - belongs to enum-decl
#  enumerator - belongs to enum-decl
# union-decl - defines and names a type, contains member elements linked to other things
# class-decl - defines and names a type, contains base type, member elements linking to other things
#  base-class - belongs to class-decl
#  data-member - container for a member; holds access level
#  member-function - container for a member; holds access level
#  member-type - container for a type declaration; holds access level
#  member-template - container for a (function?) template declaration; holds access level
#
# Higher order Things
#
# class-template-decl - defines a type (function), but without instantiation this isn't usable
# function-template-decl - defines a type (function), but without instantiation this isn't usable
#  template-type-parameter - defines a type (variable), perhaps one which should be excluded from the real type graph
#  template-non-type-parameter - names a template parameter, links to a type
#  template-parameter-type-composition - container?
#
# Values
#
# var-decl - names a variable, can link to a symbol, links to a type
# function-decl - names a function, can link to a symbol
#     has same children as function-type, rather than linking to a type

# Remove all text nodes.
sub strip_text($dom) {
  for my $node ($dom->findnodes('//text()')) {
    $node->unbindNode();
  }
}

# Make XML nicely indented. We could make the code a bit less inside
# out by passing the parent node as an extra argument. Efforts in this
# direction ran into trouble.
sub indent;
sub indent($indent, $node) {
  if ($node->nodeType == XML_ELEMENT_NODE) {
    my @children = $node->childNodes();
    return unless @children;
    my $more_indent = $indent + 2;
    # The ordering of operations here is incidental. The outcomes we
    # want are 1. an extra newline after the opening tag and
    # reindenting the closing tag to match, and 2. indentation for the
    # children.
    $node->insertBefore(new XML::LibXML::Text("\n"), $children[0]);
    for my $child (@children) {
      $node->insertBefore(new XML::LibXML::Text(' ' x $more_indent), $child);
      indent($more_indent, $child);
      $node->insertAfter(new XML::LibXML::Text("\n"), $child);
    }
    $node->appendText(' ' x $indent);
  } else {
    for my $child ($node->childNodes()) {
      indent($indent, $child);
    }
  }
}

# Parse arguments.
my $input_opt;
my $output_opt;
my $all_opt;
GetOptions('i|input=s' => \$input_opt,
           'o|output=s' => \$output_opt,
           'a|all' => sub {
             1
           },
  ) and !@ARGV or die("usage: $0",
                      map { (' ', $_) } (
                        '[-i|--input file]',
                        '[-o|--output file]',
                        '[-a|--all]',
                      ), "\n");

exit 0 unless defined $input_opt;

# Load the XML.
my $input = defined $input_opt ? new IO::File $input_opt, '<' : \*STDIN;
my $dom = XML::LibXML->load_xml(IO => $input);
close $input;

# This simplifies DOM analysis and manipulation.
strip_text($dom);

exit 0 unless defined $output_opt;

# Reformat for human consumption.
indent(0, $dom);

# Emit the XML, removing the XML declaration.
my $output = defined $output_opt ? new IO::File $output_opt, '>' : \*STDOUT;
my $out = $dom->toString();
$out =~ s;^<\?xml .*\?>\n;;m;
$out =~ s;";';g;
print $output $out;
close $output;

exit 0;
