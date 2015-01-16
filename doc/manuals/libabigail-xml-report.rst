======================================
Interchange ABI diff reporting format
======================================

Libabigail can emit ABI diff reports in an extensible format that can
be consumed and manipulated by programs with relative ease.

This document presents the format in a semi-formal way.

Relax-NG schema
===============

Below is the Relax-NG schema of the Interchange Format for ABI Change
that is used by libabigail to report about ABI changes in a machine
readable way.


.. literalinclude:: ifac-schema.rng
   :language: xml
   :encoding: utf-8
