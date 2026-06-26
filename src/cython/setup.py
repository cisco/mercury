# setup.py -- Cython build that links against a prebuilt libmerc.a
#
# Used by the mercury build system.  This script only compiles the
# Cython wrapper and links it against a prebuilt libmerc.a; libmerc
# itself is built by the top-level Makefile.
#
# mk/cython.mk copies this file (and the other sources listed in
# _cython_srcs) into a per-variant build tree, where the PEP 517 build
# backend (setuptools.build_meta) finds it.  All project metadata
# lives in pyproject.toml (PEP 621).
#
# Optional environment variables:
#   MERCURY_DIR  -- root of the mercury source tree (defaults to the
#                   directory containing setup.py).
#   LIBMERC_A    -- absolute path to the prebuilt libmerc.a
#                   (defaults to MERCURY_DIR/build/RelWithDebInfo/lib/libmerc.a,
#                   which is where the top-level Makefile builds it).
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
#
# Inputs come from environment variables (see header comment); we resolve
# them here.

# MERCURY_DIR and LIBMERC_A get inferred defaults so that libmerc.a is
# found under all three supported invocations:
#   - `make cython`                  (mk/cython.mk sets MERCURY_DIR explicitly)
#   - cibuildwheel from CI           (workflow stages sources at repo root)
#   - `cd src/cython && pip wheel .` (manual build by a developer)
# The walk-up looks for src/libmerc/libmerc.h to identify the repo root.

def _find_mercury_root(start: str) -> str:
    d = start
    while True:
        if os.path.isfile(os.path.join(d, "src", "libmerc", "libmerc.h")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return start  # not found; fall back to setup.py's directory
        d = parent

_setup_dir = os.path.dirname(os.path.abspath(__file__))
mercury_dir = os.getenv("MERCURY_DIR") or _find_mercury_root(_setup_dir)
libmerc_a = os.getenv("LIBMERC_A") or os.path.join(
    mercury_dir, "build", "RelWithDebInfo", "lib", "libmerc.a"
)
if not os.path.isfile(libmerc_a):
    raise SystemExit(
        f"error: libmerc.a not found at {libmerc_a}; "
        "build it first (e.g. './configure && make -j libmerc') or set LIBMERC_A"
    )

# ENV_CFLAGS and ENV_LDFLAGS are taken verbatim, with one exception:
# -fvisibility=hidden must be stripped, because Python < 3.9 doesn't
# annotate PyMODINIT_FUNC with visibility("default") -- so PyInit_mercury
# would be hidden and dlopen couldn't find the module init symbol.
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
