# setup2.py -- Cython build that links against a prebuilt libmerc.a
#
# Used by the Makefile2 build system.  Unlike setup.py (which
# recompiles libmerc from source), this script only compiles the
# Cython wrapper and links it against a prebuilt libmerc.a.
#
# mk/cython.mk copies this file into a per-variant build tree as
# setup.py so that the PEP 517 build backend (setuptools.build_meta)
# finds it.  All project metadata lives in pyproject.toml (PEP 621).
#
# Required environment variables (set by mk/cython.mk):
#   LIBMERC_A    -- absolute path to the prebuilt libmerc.a
#   MERCURY_DIR  -- root of the mercury source tree
#
# Optional:
#   ENV_CFLAGS   -- compile flags forwarded verbatim from $(CXXFLAGS);
#                   shlex.split() parses them so that quoted defines like
#                   -DGIT_COMMIT_ID="..." survive word-splitting correctly.
#                   -fvisibility=hidden is stripped (see below).
#   ENV_LDFLAGS  -- extra linker flags

from __future__ import annotations

import os
import shlex
import shutil

from Cython.Build import cythonize
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

# --- Environment ------------------------------------------------------

mercury_dir = os.getenv("MERCURY_DIR")
if not mercury_dir:
    raise SystemExit(
        "error: MERCURY_DIR environment variable must point to the mercury source root"
    )
libmerc_a = os.getenv("LIBMERC_A")
if not libmerc_a:
    raise SystemExit(
        "error: LIBMERC_A environment variable must point to the prebuilt libmerc.a"
    )

# -fvisibility=hidden must be stripped: Python < 3.9 doesn't annotate
# PyMODINIT_FUNC with visibility("default"), so PyInit_mercury would be
# hidden and dlopen couldn't find the module init symbol.
extra_cflags = [
    f for f in shlex.split(os.getenv("ENV_CFLAGS", ""))
    if f != "-fvisibility=hidden"
]
extra_ldflags = shlex.split(os.getenv("ENV_LDFLAGS", ""))


# --- Custom build_ext -------------------------------------------------

class LinkAgainstStaticLib(build_ext):
    """Compile mercury.pyx, then link against the prebuilt libmerc.a."""

    def build_extension(self, ext: Extension) -> None:
        cc = self.compiler
        cxx = os.getenv("CXX") or shutil.which("g++")
        if cxx:
            parts = shlex.split(cxx)
            cc.linker_so[0:1] = parts

        compile_args = list(ext.extra_compile_args)
        objects = []
        for src in ext.sources:
            objs = cc.compile(
                [src],
                output_dir=self.build_temp,
                include_dirs=ext.include_dirs,
                extra_preargs=compile_args,
                debug=self.debug,
            )
            objects.extend(objs)

        # Append the prebuilt static library so the linker can resolve
        # libmerc symbols without needing a shared-library dependency.
        objects.append(libmerc_a)

        cc.link_shared_object(
            objects,
            self.get_ext_fullpath(ext.name),
            libraries=ext.libraries,
            library_dirs=ext.library_dirs,
            runtime_library_dirs=ext.runtime_library_dirs,
            extra_postargs=ext.extra_link_args,
            debug=self.debug,
        )


# --- Extension definition ---------------------------------------------

mercury_ext = Extension(
    "mercury",
    sources=["mercury.pyx"],
    include_dirs=[os.path.join(mercury_dir, "src/libmerc")],
    language="c++",
    extra_compile_args=[
        "-std=c++17",
        "-Wno-narrowing",
        "-Wno-deprecated-declarations",
    ] + extra_cflags,
    # CFLAGS passed to the link step intentionally — mirrors mk/rules.mk
    # policy; flags like -fsanitize and -fvisibility have link semantics.
    extra_link_args=["-lz"] + extra_cflags + extra_ldflags,
    libraries=["crypto"],
)


# --- setup() -- metadata comes from pyproject.toml --------------------

setup(
    ext_modules=cythonize([mercury_ext]),
    cmdclass={"build_ext": LinkAgainstStaticLib},
)
