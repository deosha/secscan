#!/usr/bin/env python3
"""
Setup script for SecScan - Multi-language dependency vulnerability scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="secscan-cli",
    version="1.4.0",
    author="Deo Shankar",
    author_email="deoshankar89@gmail.com",
    description="A multi-language dependency vulnerability scanner supporting JavaScript, Python, and Go",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/deosha/secscan",
    project_urls={
        "Bug Tracker": "https://github.com/deosha/secscan/issues",
        "Documentation": "https://github.com/deosha/secscan#readme",
        "Source Code": "https://github.com/deosha/secscan",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    py_modules=["secscan", "config", "policy", "cache"],
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.4.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "secscan=secscan:main",
        ],
    },
    keywords="security vulnerability scanner dependencies npm pip go osv",
    include_package_data=True,
    data_files=[
        ('share/man/man1', ['secscan.1']),
    ],
)