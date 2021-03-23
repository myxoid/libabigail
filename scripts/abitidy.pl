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

use Algorithm::Diff qw(diff);
use Data::Dumper;
use Getopt::Long;
use IO::File;
use List::Util qw(any all uniq);
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

# Remove an XML element and any preceeding comment.
sub remove_node($node) {
  my $prev = $node->previousSibling();
  if ($prev && $prev->nodeType == XML_COMMENT_NODE) {
    $prev->unbindNode();
  }
  $node->unbindNode();
}

# These container elements can be dropped if empty.
my %drop_if_empty = map { $_ => undef } qw(
  elf-variable-symbols
  elf-function-symbols
  namespace-decl
  abi-instr
  abi-corpus
  abi-corpus-group
);

# This is a XML DOM traversal as we want post-order traversal so we
# delete nodes that become empty during the process.
sub drop_empty;
sub drop_empty($node) {
  return if $node->nodeType != XML_ELEMENT_NODE;
  for my $child ($node->childNodes()) {
    drop_empty($child);
  }
  if (!$node->hasChildNodes() && exists $drop_if_empty{$node->getName()}) {
    # Until abidiff accepts empty ABIs, avoid dropping top-level elements.
    if ($node->parentNode->nodeType == XML_ELEMENT_NODE) {
      remove_node($node);
    }
  }
}

# Remove unreachable declarations and types.
#
# When making a graph from ABI XML, the following are the types of
# "node" we care about. The "edges" are obtained from a few XML
# attributes as well as via XML element containment.
#
#  ELF (exported) symbols
#
#   elf-symbol (has a name; the code here currently knows nothing
#     about aliases)
#
#  Declarations (that mention a symbol)
#
#   These live in a scope. In C++ scopes can be nested and include
#   namespaces and class types.
#
#  var-decl (also used for member variables)
#    elf-symbol linked to symbol via mangled-name
#    type-id links to a type
#  function-decl (also used for member functions)
#    elf-symbol linked to symbol via mangled-name
#    parameter and return type-ids link to types
#      (alas, not just a link to a function type)
#
#  Types
#
#   These occupy pretty much all the other elements, besides those
#   that act as simple containers.
sub prune_unreachable($dom) {
  my %elf_symbols;
  # Graph vertices (only needed for statistics).
  my %vertices;
  # Graph edges.
  my %edges;

  # Keep track of type / symbol nesting.
  my @stack;

  # Traverse the whole XML DOM.
  my sub make_graph($node) {
    # The XML attributes we care about.
    my $name;
    my $id;
    my $type_id;
    my $symbol;
    my $naming_typedef_id;

    # Not every node we encounter is an XML element.
    if ($node->nodeType == XML_ELEMENT_NODE) {
      $name = $node->getAttribute('name');
      $id = $node->getAttribute('id');
      $type_id = $node->getAttribute('type-id');
      $symbol = $node->getAttribute('mangled-name');
      $naming_typedef_id = $node->getAttribute('naming-typedef-id');
      die if defined $id && defined $symbol;
    }

    if (defined $name && $node->getName() eq 'elf-symbol') {
      $elf_symbols{$name} = undef;
      # Early return is safe, but not necessary.
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

# Read symbols from a file.
sub read_symbols($file) {
  my %symbols;
  my $fh = new IO::File $file, '<';
  while (<$fh>) {
    chomp;
    $symbols{$_} = undef;
  }
  close $fh;
  return \%symbols;
}

# Remove unlisted ELF symbols,
sub filter_symbols($symbols, $dom) {
  for my $node ($dom->findnodes('elf-symbol')) {
    remove_node($node) unless exists $symbols->{$node->getAttribute('name')};
  }
}

sub normalise_anonymous_type_names($) {
  my ($doc) = @_;
  my $name_path = new XML::LibXML::XPathExpression('//abi-instr//*[@name]');
  for my $node ($doc->findnodes($name_path)) {
    my $value = $node->getAttribute('name');
    $value =~ s;^(__anonymous_[a-z]+__)\d*$;$1;;
    $node->setAttribute('name', $value);
  }
}

sub sub_tree;
sub sub_tree($l, $r) {
  # Node name must be an exact match.
  return 0 if $l->getName() ne $r->getName();
  # Left attributes may be missing on the left, but otherwise must match.
  # With one exception: libabigail emits the access specifier for the
  # type it's trying to "emit in scope" rather than what may be a
  # containing type; so allow access to differ on member-type nodes.
  for my $k (keys %$l) {
    my $lv = $l->{$k};
    my $rv = $r->{$k};
    return 0 unless defined $rv;
    next if $k eq 'access' && $l->getName() eq 'member-type';
    return 0 unless $lv eq $rv;
  }
  # Left elements must be a subsequence of right elements.
  my @lc = grep { $_->nodeType != XML_COMMENT_NODE } $l->childNodes();
  my @rc = grep { $_->nodeType != XML_COMMENT_NODE } $r->childNodes();
  unless (scalar @lc <= scalar @rc) {
    return 0;
  }
  # Only handle three forms of subsequence. Otherwise need some kind
  # of backtracking check.
  unless (@lc) {
    # empty
    return 1;
  }
  if (scalar @lc == 1) {
    # singleton
    return any { $_ } map { sub_tree($lc[0], $_) } @rc;
  }
  if (scalar @lc == scalar @rc) {
    # same length
    return all { $_ } map { sub_tree($lc[$_], $rc[$_]) } (0..$#lc);
  }
  warn "XML elements have interestingly different subelements\n",
    $l->toString(), "\n", $r->toString(), "\n";
  return 0;
}

sub get_scope($node) {
  my @names;
  while (1) {
    $node = $node->parentNode;
    last unless defined $node && $node->nodeType == XML_ELEMENT_NODE;
    my $kind = $node->getName();
    last if $kind eq 'abi-instr';
    # Some C++ enums introduce scope but we don't need to worry.
    next unless $kind eq 'class-decl' || $kind eq 'union-decl' || $kind eq 'namespace-decl';
    # Anonymous type are not permitted to contain type members (but
    # this still works with g++ -fpermissive).
    my $name = $node->getAttribute('name');
    unshift @names, $name;
  }
  return @names;
}

sub eliminate_duplicate_types($dom) {
  my %hash;
  # Collect all (unnested) types and their namespace scopes.
  for my $type ($dom->findnodes('//abi-corpus/abi-instr/*[@id] | //abi-corpus/abi-instr//namespace-decl/*[@id]')) {
    my $id = $type->getAttribute('id');
    my $scope = join(':', get_scope($type));
    for my $list ($hash{$id}{$scope}) {
      $list //= [];
      push @$list, $type;
    }
  }
  for my $id (keys %hash) {
    my $scopes = $hash{$id};
    if (scalar keys %$scopes > 1) {
      warn "inconsistent scopes found for duplicate types with id $id\n";
      next;
    }
    my ($ns) = keys %$scopes;
    my $types = $scopes->{$ns};
    next if scalar @$types == 1;
    # Find a potential maximal candidate.
    my $candidate = 0;
    for my $ix (1..$#$types) {
      $candidate = $ix if sub_tree($types->[$candidate], $types->[$ix]);
    }
    # Verify it is indeed maximal.
    my @losers = grep { $_ != $candidate } (0..$#$types);
    for my $ix (@losers) {
      unless (sub_tree($types->[$ix], $types->[$candidate])) {
        warn "conflicting duplicate types with id $id\n";
        my @strs = map { $types->[$_]->toString() } ($ix, $candidate);
        map { $_ =~ s;><;>\n<;g } @strs;
        my @lines = map { [split("\n", $_)] } @strs;
        warn Dumper(diff(@lines));
        $candidate = undef;
        last;
      }
    }
    if (defined $candidate) {
      map { remove_node($types->[$_]) } @losers;
      warn "successfully eliminated duplicate types with id $id\n";
    }
  }
}

sub report_duplicate_types($dom) {
  my %hash;
  for my $type ($dom->findnodes('*[@id]')) {
    # subranges are not really types and shouldn't be considered
    next if $type->getName() eq 'subrange';
    my $id = $type->getAttribute('id');
    for my $ids ($hash{$id}) {
      $ids //= [];
      push @$ids, $type;
    }
  }
  for my $id (keys %hash) {
    warn "residual duplicated types with id $id\n";
  }
}

# Stabilise types and declarations.
sub stabilise_types_and_declarations($dom) {
  my $corpus_path = new XML::LibXML::XPathExpression('//abi-corpus');
  my $instr_path = new XML::LibXML::XPathExpression('abi-instr');
  my $type_or_decl_path = new XML::LibXML::XPathExpression('*[@id]|*[@name]');

  my @corpora = $dom->findnodes($corpus_path);
  for my $corpus (@corpora) {
    # Let's squish it. We expect its abi-instr elements to have
    # consistent attributes, ignoring path.
    my %attrs;
    my @children = $corpus->findnodes($instr_path);
    for my $child (@children) {
      for my $attr (keys %$child) {
        my $value = $child->{$attr};
        $attrs{$attr}{$value} = undef;
      }
    }
    next unless scalar keys %attrs;

    # Create a replacement abi-instr node.
    my $replacement = new XML::LibXML::Element('abi-instr');
    # Original attribute ordering is lost, may as well be deterministic here.
    for my $attr (sort keys %attrs) {
      # Check attribute consistency.
      for my $values ($attrs{$attr}) {
        if (scalar keys %{$values} > 1) {
          die "unexpected non-constant abi-instr attribute $attr\n"
            unless $attr eq 'path' || $attr eq 'comp-dir-path' || $attr eq 'language';
          $values = { 'various' => undef };
        }
        for my $value (keys %$values) {
          $replacement->setAttribute($attr, $value);
        }
      }
    }

    # Gather sorted types and decls.
    my @types_and_decls = sort {
      my $a_id = $a->{id};
      my $a_name = $a->{name};
      die unless defined $a_id || defined $a_name;
      my $b_id = $b->{id};
      my $b_name = $b->{name};
      die unless defined $b_id || defined $b_name;
      # types before declarations
      # order types by id
      # order declarations by name
      defined $a_id != defined $b_id ? !defined $a_id <=> !defined $b_id
        : defined $a_id ? $a_id cmp $b_id
        : $a_name cmp $b_name
    } map { $_->findnodes($type_or_decl_path) } @children;

    # Add them to replacement abi-instr
    map {
      my $prev = $_->previousSibling();
      if ($prev && $prev->nodeType == XML_COMMENT_NODE) {
        $prev->unbindNode();
        $replacement->appendChild($prev);
      }
      $_->unbindNode();
      $replacement->appendChild($_)
    } @types_and_decls;
    # Remove the old abi-instr nodes.
    for my $child (@children) {
      if ($child->hasChildNodes()) {
        warn "failed to evacuate abi-instr: ", $child->toString(), "\n";
        next;
      }
      remove_node($child);
    }
    # Add the replacement abi-instr node to the abi-corpus.
    $corpus->appendChild($replacement);
  }
}

# Parse arguments.
my $input_opt;
my $output_opt;
my $symbols_opt;
my $all_opt;
my $drop_opt;
my $prune_opt;
my $normalise_opt;
my $eliminate_opt;
my $stabilise_opt;
my $report_opt;
GetOptions('i|input=s' => \$input_opt,
           'o|output=s' => \$output_opt,
           'S|symbols=s' => \$symbols_opt,
           'a|all' => sub {
             $drop_opt = $prune_opt = $normalise_opt = $eliminate_opt = $stabilise_opt = $report_opt = 1
           },
           'd|drop-empty!' => \$drop_opt,
           'p|prune-unreachable!' => \$prune_opt,
           'n|normalise-anonymous!' => \$normalise_opt,
           'e|eliminate-duplicates!' => \$eliminate_opt,
           's|stabilise-order!' => \$stabilise_opt,
           'r|report-duplicates!' => \$report_opt,
  ) and !@ARGV or die("usage: $0",
                      map { (' ', $_) } (
                        '[-i|--input file]',
                        '[-o|--output file]',
                        '[-S|--symbols file]',
                        '[-a|--all]',
                        '[-d|--[no-]drop-empty]',
                        '[-p|--[no-]prune-unreachable]',
                        '[-n|--[no-]normalise-anonymous]',
                        '[-e|--[no-]eliminate-duplicates]',
                        '[-s|--[no-]stabilise-order]',
                        '[-r|--[no-]report-duplicates]',
                      ), "\n");

exit 0 unless defined $input_opt;

# Load the XML.
my $input = defined $input_opt ? new IO::File $input_opt, '<' : \*STDIN;
my $dom = XML::LibXML->load_xml(IO => $input);
close $input;

# This simplifies DOM analysis and manipulation.
strip_text($dom);

# Remove unlisted symbols.
filter_symbols(read_symbols($symbols_opt), $dom) if defined $symbols_opt;

# Normalise anonymous type names.
normalise_anonymous_type_names($dom) if $normalise_opt;

# Eliminate complete duplicates and extra fragments of types.
eliminate_duplicate_types($dom) if $eliminate_opt;

# Check for duplicate types.
report_duplicate_types($dom) if $report_opt;

# Prune unreachable elements.
prune_unreachable($dom) if $prune_opt;

# Stabilise types and declarations.
stabilise_types_and_declarations($dom) if $stabilise_opt;

# Drop empty elements.
if ($drop_opt) {
  for my $node ($dom->childNodes()) {
    drop_empty($node);
  }
}

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
