from setuptools import setup, find_packages

setup(
    name='binGraph',
    version='3.3',
    description='CAPE\'s version of binGraph',
    license='GNU Affero General Public License v3.0',
    packages=find_packages(),
    url='https://github.com/CAPESandbox/binGraph',
    author='https://github.com/geekscrapy',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    entry_points={
        'console_scripts': [
            'binGraph = binGraph:__main__.main',
        ],
    },
    install_requires=[
        "matplotlib==3.3.0",
        "numpy==1.21.1",
        "pefile>=2021.9.3",
    ],
)
