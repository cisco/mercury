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
           '../libmerc/dns.cc',
           '../libmerc/utils.cc',
           '../libmerc/datum.cc',
           '../libmerc/analysis.cc',
           '../libmerc/libmerc.cc',
           '../libmerc/extractor.cc',
           '../libmerc/udp.cc',
           '../libmerc/addr.cc',
           '../libmerc/wireguard.cc',
           '../libmerc/ssh.cc',
           '../libmerc/packet.cc',
           '../libmerc/match.cc',
           '../libmerc/http.cc',
           '../libmerc/pkt_proc.cc',
           '../libmerc/tls.cc',
]

setup(ext_modules=[Extension("mercury",
                             sources=sources,
                             language="c++",
                             extra_compile_args=["-std=c++17","-Wno-narrowing"],
                             extra_link_args=["-std=c++17",],
                             libraries = ['crypto'],
                             runtime_library_dirs=['../'])
                  ],
      cmdclass={'build_ext':build_ext})




