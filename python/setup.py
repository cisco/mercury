"""
65;5802;1c Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import sys
import setuptools
from distutils.extension import Extension

def readme():
    with open('README.md') as f:
        return f.read()


setuptools.setup(
    name='pmercury',
    version='0.5.2.37',
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
        'pyyaml',
    ],
    scripts=['pmercury/pmercury'],
    data_files=[('/pmercury', ['../LICENSE','README.md','requirements.txt','MANIFEST.in','config.yaml']),
                ('/pmercury/resources', ['../resources/fingerprint_db.json.gz',
                                        '../resources/app_families.txt',
                                        '../resources/app_families_strict.txt',
                                        '../resources/transition_probs.csv.gz',
                                        '../resources/implementation_date_cs.json.gz',
                                        '../resources/public_suffix_list.dat.gz',
                                        '../resources/implementation_date_ext.json.gz',
                                        '../resources/pyasn.db',
                                        '../resources/domain_indicators.json.gz',
                                        '../resources/fingerprint_db_tcp.json.gz']),
                ('/pmercury/resources/equivalence-classes', ['../resources/equivalence-classes/eqv_class_ip_as.json.gz',
                                                            '../resources/equivalence-classes/eqv_class_ip.json.gz',
                                                            '../resources/equivalence-classes/eqv_class_port_applications.json.gz',
                                                            '../resources/equivalence-classes/eqv_class_port.json.gz',
                                                            '../resources/equivalence-classes/eqv_class_sni.json.gz']
    )],
    include_package_data=True,
    zip_safe=False
)
