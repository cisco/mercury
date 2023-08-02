from setuptools import Extension, setup
#from distutils.core import setup, Extension
from Cython.Distutils import build_ext
#from distutils.extension import Extension
import os
import re

###
## to build: CC=g++ python setup.py build_ext --inplace
#

###
## Notes:
#
# "-Wno-narrowing" was needed because of the OID char conversions on my platform
# "../parser.c" is needed to include parser functions
# "-std=c++11" is needed due to c++11 dependency

def readme():
    with open('README.md') as f:
        return f.read()

###
## get version string
#
VERSIONFILE = "_version.py"
verstrline  = open(VERSIONFILE, "rt").read()
VSRE        = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo          = re.search(VSRE, verstrline, re.M)
if mo:
    version_str = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

sources = ['mercury.pyx',
           '../libmerc/asn1/oid.cc',
           '../libmerc/dns.cc',
           '../libmerc/utils.cc',
           '../libmerc/analysis.cc',
           '../libmerc/libmerc.cc',
           '../libmerc/addr.cc',
           '../libmerc/wireguard.cc',
           '../libmerc/ssh.cc',
           '../libmerc/match.cc',
           '../libmerc/http.cc',
           '../libmerc/pkt_proc.cc',
           '../libmerc/tls.cc',
           '../libmerc/asn1.cc',
           '../libmerc/smb2.cc',
           '../libmerc/config_generator.cc',
           '../libmerc/bencode.cc',
]

additional_flags = os.getenv('ENV_CFLAGS').encode('latin1').decode('unicode_escape').replace("'","",2)

setup(name='mercury-python',
      version=version_str,
      description="Python interface into mercury's network protocol fingerprinting and analysis functionality",
      long_description=readme(),
      long_description_content_type="text/markdown",
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Programming Language :: Python :: 3 :: Only',
          'Topic :: System :: Networking :: Monitoring',
          'Topic :: Security',
      ],
      python_requires='>=3.6.0',
      keywords='tls fingerprinting network traffic analysis',
      url='https://github.com/cisco/mercury/src/cython/',
      author='Blake Anderson',
      author_email='blake.anderson@cisco.com',
      ext_modules=[Extension("mercury",
                             sources=sources,
                             include_dirs=['../libmerc'],
                             language="c++",
                             extra_compile_args=["-std=c++17","-Wno-narrowing","-Wno-deprecated-declarations",additional_flags],
                             extra_link_args=["-std=c++17","-lz"],
                             libraries = ['crypto'],
                             runtime_library_dirs=['../'])
                  ],
      cmdclass={'build_ext':build_ext})




