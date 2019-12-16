"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import sys
import setuptools
from distutils.extension import Extension

def readme():
    with open('README.md') as f:
        return f.read()


ext_libs = []
if sys.platform[0:3] == "win":
    ext_libs.append("Ws2_32")


ext_modules = [
    Extension("pmercury.utils.packet_proc", ["pmercury/utils/packet_proc.c"], libraries=ext_libs),
    Extension("pmercury.utils.tls_utils", ["pmercury/utils/tls_utils.c"]),
    Extension("pmercury.protocols.tcp", ["pmercury/protocols/tcp.c"]),
    Extension("pmercury.protocols.tls", ["pmercury/protocols/tls.c"], libraries=ext_libs),
    Extension("pmercury.protocols.tls_server", ["pmercury/protocols/tls_server.c"], libraries=ext_libs),
    Extension("pmercury.protocols.dtls", ["pmercury/protocols/dtls.c"], libraries=ext_libs),
    Extension("pmercury.protocols.dtls_server", ["pmercury/protocols/dtls_server.c"], libraries=ext_libs),
    Extension("pmercury.protocols.http", ["pmercury/protocols/http.c"]),
    Extension("pmercury.protocols.http_server", ["pmercury/protocols/http_server.c"]),
]

setuptools.setup(
    name='pmercury',
    version='0.4.0.11',
    description='Python tool for network (TLS, etc.) fingerprinting',
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
    url='https://github.com/cisco/mercury/',
    author='Blake Anderson',
    author_email='blake.anderson@cisco.com',
    packages=setuptools.find_packages(),
    install_requires=[
        'cryptography',
        'hpack',
        'pyasn',
        'pypcap',
    ],
    scripts=['pmercury/pmercury'],
    data_files=[('pmercury', ['../LICENSE','README.md','requirements.txt','MANIFEST.in']),
                ('pmercury/resources', ['../resources/fingerprint_db.json.gz',
                                         '../resources/app_families.txt',
                                         '../resources/transition_probs.csv.gz',
                                         '../resources/asn_info.db.gz',
                                         '../resources/implementation_date_cs.json.gz',
                                         '../resources/public_suffix_list.dat.gz',
                                         '../resources/implementation_date_ext.json.gz',
                                         '../resources/pyasn.db.gz']
    )],
    ext_modules=ext_modules,
    include_package_data=True,
    zip_safe=False
)
