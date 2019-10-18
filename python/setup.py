"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import setuptools


def readme():
    with open('README.md') as f:
        return f.read()


setuptools.setup(
    name='pmercury',
    version='0.2.1.002',
    description='Python tool for network (TLS, etc.) fingerprinting',
    long_description=readme(),
    long_description_content_type="text/markdown",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
    ],
    keywords='tls fingerprinting network traffic analysis',
    url='https://github.com/cisco/mercury/',
    author='Blake Anderson',
    author_email='blake.anderson@cisco.com',
    license_files=['../LICENSE'],
    packages=setuptools.find_packages(),
    install_requires=[
        'cryptography',
        'hpack',
        'pyasn',
        'pypcap',
        'ujson',
    ],
    scripts=['pmercury/pmercury'],
    data_files=[('pmercury', ['../LICENSE','README.md','requirements.txt','MANIFEST.in']),
                ('pmercury/resources', ['../resources/fingerprint_db.json.gz',
                                         '../resources/app_families.txt',
                                         '../resources/asn_info.db.gz',
                                         '../resources/implementation_date_cs.json.gz',
                                         '../resources/public_suffix_list.dat.gz',
                                         '../resources/implementation_date_ext.json.gz',
                                         '../resources/pyasn.db.gz']
    )],
    include_package_data=True,
    zip_safe=False
)
