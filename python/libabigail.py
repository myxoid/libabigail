#!/usr/bin/python
#
# Copyright (C) 2015 Red Hat, Inc.

# This file is part of the GNU Application Binary Interface Generic
# Analysis and Instrumentation Library (libabigail).  This library is
# free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the
# Free Software Foundation; either version 3, or (at your option) any
# later version.

# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Lesser Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this program; see the file COPYING-LGPLV3.  If
# not, see <http://www.gnu.org/licenses/>.

# Author: Sinny Kumari <sinny@redhat.com>

import pylibabigail
import cStringIO
import ir

class CorpusDiff:
    def __init__(self, _obj=None):
        if _obj != None:
            self._o = _obj
            return
        self._o = None

    def report(self, stream):
        """
        Report abi diff in serialized form
        """
        buffer = cStringIO.StringIO()
        pylibabigail.corpus_diff_report(self._o, buffer)
        stream.write(buffer.getvalue())
        return stream

    def has_changes(self):
        """
        Check if there is any ABI diff
        """
        return pylibabigail.corpus_diff_has_changes(self._o)

    def soname_changed(self):
        """
        Check if soname of the underying corpus has changed
        """
        return pylibabigail.corpus_diff_soname_changed(self._o)

    def deleted_functions(self):
        """
        Details about deleted functions from abi diff
        """
        return pylibabigail.corpus_diff_deleted_functions(self._o)

    def added_functions(self):
        """
        Details about added functions from abi diff
        """
        return pylibabigail.corpus_diff_added_functions(self._o)

def enum(**enums):
    return type('Enum', (), enums)

dwarf_reader_status = enum(STATUS_UNKNOWN=0, STATUS_OK=1,
                           STATUS_DEBUG_INFO_NOT_FOUND=2,
                           STATUS_NO_SYMBOLS_FOUND=4)
