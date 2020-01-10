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
    Extension("pmercury.utils.packet_proc", ["pmercury/utils/packet_proc.pyx"], libraries=ext_libs),
    Extension("pmercury.utils.tls_utils", ["pmercury/utils/tls_utils.pyx"]),
    Extension("pmercury.protocols.tcp", ["pmercury/protocols/tcp.pyx"]),
    Extension("pmercury.protocols.tls", ["pmercury/protocols/tls.pyx"], libraries=ext_libs),
    Extension("pmercury.protocols.tls_server", ["pmercury/protocols/tls_server.pyx"], libraries=ext_libs),
    Extension("pmercury.protocols.dtls", ["pmercury/protocols/dtls.pyx"], libraries=ext_libs),
    Extension("pmercury.protocols.dtls_server", ["pmercury/protocols/dtls_server.pyx"], libraries=ext_libs),
    Extension("pmercury.protocols.http", ["pmercury/protocols/http.pyx"]),
    Extension("pmercury.protocols.http_server", ["pmercury/protocols/http_server.pyx"]),
]

setuptools.setup(
    name='pmercury',
    version='0.4.1.14',
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
    data_files=[('pmercury', ['../LICENSE','README.md','requirements.txt','MANIFEST.in','config.txt']),
                ('pmercury/resources', ['../resources/fingerprint_db.json.gz',
                                        '../resources/app_families.txt',
                                        '../resources/transition_probs.csv.gz',
                                        '../resources/implementation_date_cs.json.gz',
                                        '../resources/public_suffix_list.dat.gz',
                                        '../resources/implementation_date_ext.json.gz',
                                        '../resources/pyasn.db']
    )],
    ext_modules=ext_modules,
    include_package_data=True,
    zip_safe=False
)
