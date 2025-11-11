from setuptools import Extension, setup

# from distutils.core import setup, Extension
from Cython.Distutils import build_ext
from Cython.Build import cythonize

# from distutils.extension import Extension
import os
import re
import shlex
import shutil
import platform

###
## to build: CC=g++ CXX=g++ python setup.py build_ext --inplace
#

###
## Notes:
#
# "-Wno-narrowing" was needed because of the OID char conversions on my platform
# "../parser.c" is needed to include parser functions
# "-std=c++17" is needed due to c++17 dependency


def readme():
    with open("README.md") as f:
        return f.read()


###
## get version string
#
VERSIONFILE = "_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    version_str = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

mercury_dir = ""
if "MERCURY_DIR" in os.environ:
    mercury_dir = os.getenv("MERCURY_DIR")
else:
    mercury_dir = "../../"

sources = [
    "mercury.pyx",
    "{mercury_dir}/src/libmerc/asn1/oid.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/utils.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/libmerc.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/addr.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/http.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/pkt_proc.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/smb2.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/config_generator.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/bencode.cc".format(mercury_dir=mercury_dir),
]

arch = platform.machine()
simd_sources = []

# SIMD-specific sources and flags
if arch in ["x86_64", "i386"]:
    simd_sources = [
        (f"{mercury_dir}/src/libmerc/softmax_sse2.cc", ["-msse2"]),
        (f"{mercury_dir}/src/libmerc/softmax_avx.cc", ["-mavx"]),
        (f"{mercury_dir}/src/libmerc/softmax_avx2.cc", ["-mavx2"]),
    ]
elif arch in ["aarch64", "arm64"]:
    simd_sources = [
        (f"{mercury_dir}/src/libmerc/softmax_neon.cc", [])
    ]

def get_additional_flags():
    env_cflags = os.getenv("ENV_CFLAGS")
    if env_cflags is None:
        return []
    else:
        return shlex.split(env_cflags)


additional_flags = get_additional_flags()
print("additional_flags =", repr(additional_flags))

class CustomBuildExt(build_ext):
    def build_extension(self, ext):
        """
        Override build_extension so that we compile each source file with
        the appropriate extra flags (either normal flags, or SIMD‐specific).
        """
        compiler = self.compiler
        compiler.linker_so[0] = shutil.which("g++")

        # 4.1) Prepare a list to hold all object filenames we generate
        objects = []

        # 4.2) Base flags that apply to "non‐SIMD" files
        base_compile_args = list(ext.extra_compile_args)

        # 4.3) For each source file in ext.sources, decide which flags to pass
        for src in ext.sources:
            # Determine per‐source flags
            per_file_flags = base_compile_args[:]  # start with the common flags
            for simd_src, simd_flags in simd_sources:
                if os.path.normpath(src) == os.path.normpath(simd_src):
                    # Replace flags with (common) + (that source's SIMD flags)
                    per_file_flags = base_compile_args + simd_flags
                    break

            # Compile this single source file into an object
            # `compiler.compile` returns a list with exactly one object filename
            obj = compiler.compile(
                [src],
                output_dir=self.build_temp,
                include_dirs=ext.include_dirs,
                extra_preargs=per_file_flags,
                debug=self.debug,
            )
            # obj is a list of length 1
            objects.extend(obj)

        compiler.link_shared_object(
            objects,
            self.get_ext_fullpath(ext.name),
            libraries=ext.libraries + ["stdc++"],
            library_dirs=ext.library_dirs,
            runtime_library_dirs=ext.runtime_library_dirs,
            extra_preargs=ext.extra_link_args,
            debug=self.debug,
        )

# ------------------------------------------------------------------------------
# 5) Build the Extension object (all sources just go into one Extension)
# ------------------------------------------------------------------------------
ext = Extension(
    "mercury",
    sources=sources + [s[0] for s in simd_sources],
    include_dirs=[os.path.join(mercury_dir, "src/libmerc")],
    language="c++",
    # These flags apply to *all* sources by default.  In build_ext we adjust them per‐source.
    extra_compile_args=[
        "-std=c++17",
        "-Wno-narrowing",
        "-Wno-deprecated-declarations",
    ] + additional_flags,
    extra_link_args=["-std=c++17", "-lz"] + additional_flags,
    libraries=["crypto"],
    runtime_library_dirs=[os.path.join(mercury_dir, "src/")],
)

# ------------------------------------------------------------------------------
# 6) Call setup(...) using our CustomBuildExt handler
# ------------------------------------------------------------------------------
setup(
    name="mercury-python",
    version=version_str,
    description="Python interface into mercury's network protocol fingerprinting and analysis functionality",
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.6.0",
    keywords="tls fingerprinting network traffic analysis",
    url="https://github.com/cisco/mercury-python/",
    author="Blake Anderson",
    author_email="blake.anderson@cisco.com",
    ext_modules=cythonize([ext]),
    cmdclass={"build_ext": CustomBuildExt},
)
