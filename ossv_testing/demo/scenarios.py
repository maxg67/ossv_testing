"""
Predefined demonstration scenarios for ossv-scanner.

This module provides structured demonstration scenarios that showcase 
various features and capabilities of the ossv-scanner in different contexts.
"""

import os
import time
import logging
import tempfile
import json
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Callable
from pathlib import Path
import random
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.markdown import Markdown

logger = logging.getLogger(__name__)
console = Console()

# Define demonstration scenarios
DEMO_SCENARIOS = {
    "basic": {
        "name": "Basic Vulnerability Scanning",
        "description": "Demonstrates basic functionality of ossv-scanner on a simple project",
        "estimated_time": "5 minutes",
        "setup_function": "setup_basic_scenario",
        "demo_function": "run_basic_scenario"
    },
    "ci-cd": {
        "name": "CI/CD Integration",
        "description": "Shows how to integrate ossv-scanner in CI/CD pipelines",
        "estimated_time": "10 minutes",
        "setup_function": "setup_cicd_scenario",
        "demo_function": "run_cicd_scenario"
    },
    "sbom": {
        "name": "SBOM Generation",
        "description": "Demonstrates Software Bill of Materials (SBOM) generation",
        "estimated_time": "7 minutes",
        "setup_function": "setup_sbom_scenario",
        "demo_function": "run_sbom_scenario"
    },
    "polyglot": {
        "name": "Multi-Ecosystem Projects",
        "description": "Shows scanner capabilities on projects with multiple dependency ecosystems",
        "estimated_time": "8 minutes",
        "setup_function": "setup_polyglot_scenario",
        "demo_function": "run_polyglot_scenario"
    },
    "remediation": {
        "name": "Vulnerability Remediation",
        "description": "Demonstrates how to remediate detected vulnerabilities",
        "estimated_time": "12 minutes",
        "setup_function": "setup_remediation_scenario",
        "demo_function": "run_remediation_scenario"
    }
}

# Demo scripts with detailed steps and explanations
DEMO_SCRIPTS = {
    "basic": [
        {
            "title": "Introduction to ossv-scanner",
            "content": """
# Introduction to ossv-scanner

The ossv-scanner is a tool designed to identify vulnerabilities in open-source dependencies.
Key features include:

* Scanning multiple dependency ecosystems (npm, PyPI, Maven, etc.)
* Identifying known vulnerabilities in dependencies
* Generating detailed reports and remediation advice
* Creating Software Bill of Materials (SBOM)

In this demonstration, we'll show a basic scan of a simple project.
            """
        },
        {
            "title": "Project Overview",
            "content": """
# Project Overview

Our sample project contains several dependencies with known vulnerabilities:

* lodash 4.17.15 - Prototype pollution vulnerability (CVE-2019-10744)
* jquery 3.4.0 - Prototype pollution vulnerability (CVE-2019-11358)
* minimist 1.2.0 - Prototype pollution vulnerability (CVE-2020-7598)

Let's examine the project structure before scanning.
            """
        },
        {
            "title": "Running the Scanner",
            "content": """
# Running the Scanner

To scan the project, we use the ossv-scan command:

ossv-scan --output-format json --output-path results.json project_dir

The scanner will:
1. Identify dependency files in the project
2. Parse dependencies and their versions
3. Check for known vulnerabilities
4. Generate a detailed report
            """
        },
        {
            "title": "Understanding Results",
            "content": """
# Understanding the Results

The scanner produces a detailed report with:

* List of dependencies found
* Vulnerabilities detected for each dependency
* Severity ratings (Critical, High, Medium, Low)
* Remediation advice (fixed versions)
* References to CVE and other vulnerability databases

Let's examine the results of our scan.
            """
        },
        {
            "title": "Next Steps",
            "content": """
# Next Steps

After identifying vulnerabilities, you should:

1. Prioritize fixes based on severity
2. Update dependencies to patched versions
3. Implement regular scanning in your development workflow
4. Consider integrating scanning into your CI/CD pipeline

ossv-scanner can be customized with various options:
* Filter by severity with `--min-severity`
* Generate SBOM with `--sbom-only`
* Customize output formats with `--output-format`
            """
        }
    ],
    "ci-cd": [
        {
            "title": "CI/CD Integration Overview",
            "content": """
# CI/CD Integration

Integrating ossv-scanner into CI/CD pipelines provides continuous vulnerability monitoring.
This ensures that new dependencies or updates are automatically checked for security issues.

Key benefits:
* Early detection of vulnerabilities
* Automated security checks
* Consistent security standards across projects
* Preventing vulnerable dependencies from reaching production
            """
        },
        {
            "title": "CI Configuration Examples",
            "content": """
# CI Configuration Examples

## GitHub Actions Example

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install ossv-scanner
      run: pip install ossv-scanner
    - name: Run vulnerability scan
      run: ossv-scan --ci --fail-on-severity high .