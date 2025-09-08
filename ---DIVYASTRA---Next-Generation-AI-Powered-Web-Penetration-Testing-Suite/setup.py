#!/usr/bin/env python3
"""
DIVYASTRA - Next-Generation AI-Powered Web Penetration Testing Suite
Setup script for package installation
"""

from setuptools import setup, find_packages
from pathlib import Path
import re

# Read version from __init__.py
def get_version():
    version_file = Path(__file__).parent / "divyastra" / "src" / "divyastra" / "__init__.py"
    version_content = version_file.read_text()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_content, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

# Read long description from README
def get_long_description():
    readme_file = Path(__file__).parent / "divyastra" / "README.md"
    if readme_file.exists():
        return readme_file.read_text(encoding="utf-8")
    return "Next-Generation AI-Powered Web Penetration Testing Suite"

# Read requirements
def get_requirements():
    req_file = Path(__file__).parent / "requirements.txt"
    if req_file.exists():
        return req_file.read_text().strip().split('\n')
    return []

def get_dev_requirements():
    req_file = Path(__file__).parent / "requirements-dev.txt"
    if req_file.exists():
        return req_file.read_text().strip().split('\n')
    return []

setup(
    name="divyastra",
    version=get_version(),
    author="DSCYBERS Team",
    author_email="security@dscybers.org",
    description="Next-Generation AI-Powered Web Penetration Testing Suite",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/DSCYBERS/divyastra",
    download_url="https://github.com/DSCYBERS/divyastra/releases",
    project_urls={
        "Homepage": "https://github.com/DSCYBERS/divyastra",
        "Documentation": "https://docs.dscybers.org/divyastra",
        "Bug Tracker": "https://github.com/DSCYBERS/divyastra/issues",
        "Source Code": "https://github.com/DSCYBERS/divyastra",
        "Community": "https://discord.gg/dscybers-security",
    },
    packages=find_packages(where="divyastra/src"),
    package_dir={"": "divyastra/src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Internet :: WWW/HTTP :: Browsers",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.9",
    install_requires=get_requirements(),
    extras_require={
        "dev": get_dev_requirements(),
        "ai": ["openai", "transformers", "torch"],
        "browser": ["playwright", "selenium"],
        "full": ["openai", "transformers", "torch", "playwright", "selenium"],
    },
    entry_points={
        "console_scripts": [
            "divyastra=divyastra.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "divyastra": [
            "config/*.json",
            "config/payloads/*.json",
            "config/wordlists/*.txt",
            "templates/*.html",
            "templates/*.md",
        ],
    },
    keywords=[
        "security", "penetration-testing", "web-security", "vulnerability-scanner",
        "ai-powered", "zero-day", "api-security", "graphql-security", 
        "business-logic", "spa-security", "framework-security"
    ],
    license="Enterprise/Academic/Government License",
    zip_safe=False,
)
