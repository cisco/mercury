from distutils.core import setup, Extension
from Cython.Distutils import build_ext
from distutils.extension import Extension

###
## to build: CC=g++ python setup.py build_ext --inplace
#

###
## Notes:
#
# "-Wno-narrowing" was needed because of the OID char conversions on my platform
# "../parser.c" is needed to include parser functions
# "-std=c++11" is needed due to c++11 dependency

sources = ['mercury.pyx',
           '../libmerc/asn1/oid.cc',
           '../libmerc/dns.cc',
           '../libmerc/utils.cc',
           '../libmerc/analysis.cc',
           '../libmerc/libmerc.cc',
           '../libmerc/addr.cc',
           '../libmerc/wireguard.cc',
           '../libmerc/ssh.cc',
           '../libmerc/packet.cc',
           '../libmerc/match.cc',
           '../libmerc/http.cc',
           '../libmerc/pkt_proc.cc',
           '../libmerc/tls.cc',
           '../libmerc/asn1.cc',
           '../libmerc/smb2.cc',
           '../libmerc/config_generator.cc',
]

setup(ext_modules=[Extension("mercury",
                             sources=sources,
                             language="c++",
                             extra_compile_args=["-std=c++17","-Wno-narrowing","-Wno-deprecated-declarations","-DSSLNEW"],
                             extra_link_args=["-std=c++17","-lz"],
                             libraries = ['crypto'],
                             runtime_library_dirs=['../'])
                  ],
      cmdclass={'build_ext':build_ext})




