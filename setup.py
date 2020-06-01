#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['Click>=7.0', 'cryptography', 'python-dotenv', 'pyarrow',
                'pandas<=1.0.3']

setup_requirements = []

test_requirements = []

setup(
    author="Fabian Bergermann",
    author_email='fabian@hellogetsafe.com',
    python_requires='>=3.5',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Encrypt data Python objects using state-of-the-art cryptography, using both a secret key from an environment variable and a user password as second factor.",
    entry_points={
        'console_scripts': [
            'encryption2fa=encryption2fa.cli:main',
        ],
    },
    install_requires=requirements,
    license="MIT license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='encryption2fa',
    name='encryption2fa',
    packages=find_packages('src', include=['encryption2fa', 'encryption2fa.*']),
    package_dir={'': 'src'},
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/fabianbergermann/encryption2fa',
    version='0.1.0',
    zip_safe=False,
)
