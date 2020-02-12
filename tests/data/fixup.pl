#!/usr/bin/perl

use strict;
use warnings;

my %modes = (
  Changed => 'C',
  Added => 'A',
  Removed => 'D',
  insertions => undef,
  changes => undef,
  change => undef,
  changed => undef,
);

my $tag;
my $saved_indent;

while (my $line = <STDIN>) {
  chomp $line;
  if ($line =~ m/\b(Changed|Added|Removed|insertions|changes|change|changed)\b.*:$/) {
    $tag = $modes{$1};
    $saved_indent = undef if defined $tag;
  }
  elsif ($line =~ m/^( *)(\[[ACD]\] )?([^ ].*)$/) {
    my ($indent, $junk, $symbol) = ($1, $2, $3);
    if (defined $tag && (!defined $saved_indent || $saved_indent eq $indent)) {
      $line = $indent . '[' . $tag . '] ' . $symbol;
      $saved_indent = $indent;
    }
  }
  print "$line\n";
}
