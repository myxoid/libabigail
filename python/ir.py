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

class FunctionDecl:
    def __init__(self, _obj=None):
        if _obj != None:
            self._o = _obj
            return
        self._o = None

    def get_pretty_representation(self):
        """
        Return pretty representation for a function
        """
        return pylibabigail.function_decl_get_pretty_representation(self._o)

    def get_type(self):
        """
        Return the type of the current instance of function_decl which can be
        either function_type or method_type
        """
        return pylibabigail.function_decl_get_type(self._o)

    def get_return_type(self):
        """
        Return type of the current instance of function_decl
        """
        return pylibabigail.function_decl_get_return_type(self._o)

    def get_parameters(self):
        """
        parameters of the function
        """
        return pylibabigail.function_decl_get_parameters(self._o)

    def get_symbol(self):
        """
        Provides underlying ELF symbol
        """
        return pylibabigail.function__decl_get_symbol(self._o)

    def is_declared_inline(self):
        """
        Check if function is declared inline
        """
        return pylibabigail.function_decl_is_declared_inline(self._o)

    def get_binding(self):
        """
        Provies binding of function i.e local, global or weak
        """
        return pylibabigail.function_decl_get_binding(self._o)

    def is_variadic(self):
        """
        Check if function takes variable number of parameter
        """
        return pylibabigail.function_decl_is_vardict(self._o)

    def get_hash(self):
        """
        Hash value of function_declaration
        """
        return pylibabigail.function_decl_get_hash(self._o)

    def get_id(self):
        """
        Returns ID which uniquely identifies function in library
        """
        return pylibabigail.function_decl_get_id(self._o)

def enum(**enums):
    return type('Enum', (), enums)

binding = enum(BINDING_NONE = 0, BINDING_LOCAL = 1,
                            BINDING_GLOBAL = 2, BINDING_WEAK = 3)
