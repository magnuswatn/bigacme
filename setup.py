from setuptools import setup, find_packages

setup(
    name='bigacme',
    author='Magnus Watn',
    description='An ACME client for F5 Big-IP',
    long_description='Command-line program for installing and renewing certificates from an ACME CA on a F5 Big-IP',
    version='0.2',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'bigsuds',
        'acme',
        'cryptography',
        'PyOpenSSL',
        ],
    entry_points={
        'console_scripts': [
            'bigacme = bigacme.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        ],
)
