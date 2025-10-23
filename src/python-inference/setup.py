#!/usr/bin/env python3
import os

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
from Cython.Compiler import Options
from Cython.Build import cythonize


ext_modules=[ Extension("tls_fingerprint_min",
                        [os.path.dirname(os.path.abspath(__file__))+"/tls_fingerprint_min.pyx"],
                        language="c++",
                        libraries=["m"],
                        extra_compile_args = ["-ffast-math",'-O2','-march=native','-mtune=native'],
                        extra_link_args = ["-ffast-math",'-O2','-march=native','-mtune=native'])]

setup(
  name = "tls_fingerprint_min",
  cmdclass = {"build_ext": build_ext},
    ext_modules = ext_modules)
