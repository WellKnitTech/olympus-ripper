"""
Olympus Ripper - Hybrid Forensic Artifact Parser
© 2026 Olympus Cyber. All rights reserved.
"""
from setuptools import setup, find_packages

setup(
    name="olympus-ripper",
    version="1.0.0",
    description="Hybrid Windows Registry & macOS forensic artifact parser — by Olympus Cyber",
    author="Olympus Cyber",
    author_email="olympuscybersec@gmail.com",
    url="https://github.com/olympuscyber/olympus-ripper",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "regipy>=4.0.0",
        "python-registry>=1.3.1",
    ],
    extras_require={
        "dev": ["pytest", "black", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "oripper=olympus_ripper.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ],
)
