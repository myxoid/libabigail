from distutils.core import setup, Extension
import os

module1 = Extension('pylibabigail',
                     libraries = ['abigail'],
                     include_dirs = ['/usr/include/libabigail/'],
                     sources = ['libabigail.cc'])

setup (name = 'python-libabigail',
       version = '0.1',
       description = 'Python extension of libabigail',
       long_description = 'C++-Python extension of libabigail providing APIs \
which is provided in C++ libabigail',
       platforms=["Linux"],
       author = 'Sinny Kumari',
       author_email = 'sinny@redhat.com',
       url = 'https://sourceware.org/libabigail/',
       License = 'LGPLv3+' ,
       ext_modules = [module1]
       )
