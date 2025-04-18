from setuptools import setup, find_packages
import os

# Safely load README if it exists
long_description = ""
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()

# Load dependencies from requirements.txt
requirements = []
if os.path.exists("requirements.txt"):
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        requirements = fh.read().splitlines()

setup(
    name="ossv-testing",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Scientific testing framework for OSS Vulnerability Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ossv-testing",
    packages=find_packages(),
    include_package_data=True,  # Makes sure extra files (like configs/scripts) are included
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ossv-test=ossv_testing.cli:main",  # 👈 Make sure this function exists
        ],
    },
)
