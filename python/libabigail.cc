// -*- Mode: C++ -*-
//
// Copyright (C) 2015 Red Hat, Inc.
//
// This file is part of the GNU Application Binary Interface Generic
// Analysis and Instrumentation Library (libabigail).  This library is
// free software; you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the
// Free Software Foundation; either version 3, or (at your option) any
// later version.

// This library is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Lesser Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this program; see the file COPYING-LGPLV3.  If
// not, see <http://www.gnu.org/licenses/>.
//
// Author: Sinny Kumari <sinny@redhat.com>

/// @file
///
/// This program implements how libabigail's C++ APIs interact with
/// Python interpreter using Python wrapper.

#include <Python.h>
#include <abg-dwarf-reader.h>
#include <abg-comp-filter.h>
#include <iostream>
#include <string>
#include <cStringIO.h>

using abigail::corpus_sptr;
using namespace abigail::dwarf_reader;
using abigail::comparison::diff_context;
using abigail::comparison::corpus_diff_sptr;
using abigail::comparison::diff_context_sptr;

static PyObject* read_corpus_from_elf(PyObject* self, PyObject* args)
{
    char *file;
    char *di_dir = 0;
    if (!PyArg_ParseTuple(args, "s|s", &file, &di_dir)) {
        return Py_None;
    }
    corpus_sptr c;
    abigail::dwarf_reader::status status =
    abigail::dwarf_reader::read_corpus_from_elf(file, &di_dir, c);
    PyObject *corpus_res = PyTuple_New(2);
    PyTuple_SetItem(corpus_res, 0, PyInt_FromSize_t(status));
    corpus_sptr *p = new corpus_sptr(c);
    PyTuple_SetItem(corpus_res, 1, PyCapsule_New((void*)p, "corpus_sptr", NULL));
    return corpus_res;
}

static PyObject* compute_diff(PyObject* self, PyObject* args)
{
    PyObject *c1, *c2;
    if (!PyArg_ParseTuple(args, "OO", &c1, &c2 )) {
        return Py_None;
    }
    diff_context_sptr ctxt(new diff_context);
    corpus_sptr corpus_ptr1 = *((corpus_sptr*) PyCapsule_GetPointer(c1, PyCapsule_GetName(c1)));
    corpus_sptr corpus_ptr2 = *((corpus_sptr*) PyCapsule_GetPointer(c2, PyCapsule_GetName(c2)));
    corpus_diff_sptr changes = abigail::comparison::compute_diff(corpus_ptr1, corpus_ptr2, ctxt);
    corpus_diff_sptr *p = new corpus_diff_sptr(changes);
    return PyCapsule_New((void*)p, "corpus_diff_sptr", NULL);
}

static PyObject* corpus_diff_report(PyObject* self, PyObject* args)
{
    PyObject *ob, *buffer;
    std::stringstream buf;
    if (!PyArg_ParseTuple(args, "OO", &ob, &buffer )) {
        return Py_None;
    }
    corpus_diff_sptr ptr = *((corpus_diff_sptr*) PyCapsule_GetPointer(
        ob, PyCapsule_GetName(ob)));
    ptr->report(buf);
    const char *diff_buff = buf.str().c_str();
    PycStringIO->cwrite(buffer, diff_buff , buf.str().length());
    return Py_None;
}

static PyObject* corpus_diff_has_changes(PyObject* self, PyObject* args)
{
    PyObject *ob;
    if (!PyArg_ParseTuple(args, "O", &ob)) {
        return Py_None;
    }
    corpus_diff_sptr ptr = *((corpus_diff_sptr*) PyCapsule_GetPointer(
        ob, PyCapsule_GetName(ob)));
    return PyBool_FromLong(ptr->has_changes());
}

static PyObject* corpus_diff_soname_changed(PyObject* self, PyObject* args)
{
    PyObject *ob;
    if (!PyArg_ParseTuple(args, "O", &ob)) {
        return Py_None;
    }
    corpus_diff_sptr ptr = *((corpus_diff_sptr*) PyCapsule_GetPointer(
        ob, PyCapsule_GetName(ob)));
    return PyBool_FromLong(ptr->soname_changed());
}

static PyMethodDef PyliabigailMethods[] =
{
    {"read_corpus_from_elf", read_corpus_from_elf, METH_VARARGS, "Read all abig\
        ail::translation_unit possible from the debug info accessible from an\
        elf file"},
    {"compute_diff", compute_diff, METH_VARARGS, "Computes diff between two\
        corpus"},
    {"corpus_diff_report", corpus_diff_report, METH_VARARGS, "Report abi diff in serialized\
        form"},
    {"corpus_diff_has_changes", corpus_diff_has_changes, METH_VARARGS,
        "Checking if ABIdiff has changes"},
    {"corpus_diff_soname_changed", corpus_diff_soname_changed, METH_VARARGS,
        "Check if soname of the underying corpus has changed"},
    {NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC initpylibabigail()
{
     PyObject *module = Py_InitModule("pylibabigail", PyliabigailMethods);
     if (module == NULL)
         return;
     PycString_IMPORT;
}
