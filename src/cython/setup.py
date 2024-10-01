from setuptools import Extension, setup

# from distutils.core import setup, Extension
from Cython.Distutils import build_ext

# from distutils.extension import Extension
import os
import re
import shlex

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
    "{mercury_dir}/src/libmerc/dns.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/utils.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/analysis.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/libmerc.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/addr.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/wireguard.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/ssh.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/match.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/http.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/pkt_proc.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/tls.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/asn1.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/smb2.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/config_generator.cc".format(mercury_dir=mercury_dir),
    "{mercury_dir}/src/libmerc/bencode.cc".format(mercury_dir=mercury_dir),
]


def get_additional_flags():
    env_cflags = os.getenv("ENV_CFLAGS")
    if env_cflags is None:
        return []
    else:
        return shlex.split(env_cflags)


additional_flags = get_additional_flags()
print("additional_flags =", repr(additional_flags))


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
    ext_modules=[
        Extension(
            "mercury",
            sources=sources,
            include_dirs=["{mercury_dir}/src/libmerc".format(mercury_dir=mercury_dir)],
            language="c++",
            extra_compile_args=[
                "-std=c++17",
                "-Wno-narrowing",
                "-Wno-deprecated-declarations",
            ]
            + additional_flags,
            extra_link_args=["-std=c++17", "-lz"] + additional_flags,
            libraries=["crypto"],
            runtime_library_dirs=["{mercury_dir}/src/".format(mercury_dir=mercury_dir)],
        )
    ],
    cmdclass={"build_ext": build_ext},
)
