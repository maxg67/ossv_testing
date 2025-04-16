"""
Predefined demonstration scenarios for ossv-scanner.

This module provides structured demonstration scenarios that showcase 
various features and capabilities of the ossv-scanner in different contexts.
"""

import os
import sys
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
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.markdown import Markdown
from rich.layout import Layout
from rich.live import Live

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
```

## GitLab CI Example

```yaml
stages:
  - test

security_scan:
  stage: test
  image: python:3.9
  script:
    - pip install ossv-scanner
    - ossv-scan --ci --fail-on-severity high .
  artifacts:
    paths:
      - ossv-scan-results.json
```

## Jenkins Pipeline Example

```groovy
pipeline {
    agent {
        docker {
            image 'python:3.9'
        }
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install ossv-scanner'
                sh 'ossv-scan --ci --fail-on-severity high .'
            }
        }
    }
}
```
            """
        },
        {
            "title": "CI/CD Best Practices",
            "content": """
# CI/CD Best Practices

When integrating vulnerability scanning in CI/CD:

1. **Define Severity Thresholds**: Use `--fail-on-severity` to establish when builds should fail
2. **Create Exemptions**: Use `--ignore-file` for false positives or accepted risks
3. **Artifact Results**: Save scan results as build artifacts for auditing
4. **Separate Stages**: Run scans in dedicated pipeline stages
5. **Customized Reporting**: Use `--output-format` for integration with other tools
6. **Regular Updates**: Keep the scanner itself updated regularly
            """
        },
        {
            "title": "Demo: CI Failure Simulation",
            "content": """
# Demo: CI Failure Simulation

We'll now demonstrate how ossv-scanner can fail a build based on vulnerability severity:

1. Set up a project with known high severity vulnerabilities
2. Configure a CI job with `--fail-on-severity high`
3. Run the job and observe the build failure
4. Review the generated report for remediation guidance
5. Fix the vulnerability and run again to see a successful build
            """
        },
        {
            "title": "Automated Remediation",
            "content": """
# Automated Remediation

Advanced CI/CD integration can include automated remediation:

* Auto-create pull requests for version updates
* Integrate with dependency update tools like Dependabot
* Notify developers through messaging integrations
* Track vulnerability metrics over time

This creates a continuous security improvement process.
            """
        }
    ],
    "sbom": [
        {
            "title": "SBOM Introduction",
            "content": """
# Software Bill of Materials (SBOM)

An SBOM is a formal record that contains the details and supply chain relationships
of components used in building software. SBOMs are increasingly important for:

* Supply chain security
* Regulatory compliance
* Risk management
* Vulnerability tracking over time
* Software composition transparency
            """
        },
        {
            "title": "SBOM Formats",
            "content": """
# SBOM Formats

ossv-scanner can generate SBOMs in industry-standard formats:

* **CycloneDX**: Rich metadata and vulnerability information
* **SPDX**: License compliance focused
* **SWID**: Software identification tags

Each format has specific strengths and is suitable for different use cases.
            """
        },
        {
            "title": "Generating SBOMs",
            "content": """
# Generating SBOMs with ossv-scanner

To generate an SBOM, use the following command:

```
ossv-scan --sbom-only --sbom-format cyclonedx --output-format json --output-path sbom.json .
```

Options to customize SBOM generation:
* `--sbom-format`: cyclonedx, spdx, or swid
* `--sbom-version`: Format specification version
* `--sbom-author`: Author information
* `--sbom-supplier`: Supplier information
            """
        },
        {
            "title": "SBOM Analysis",
            "content": """
# Analyzing an SBOM

An SBOM provides valuable insights into your software:

* Complete inventory of components
* Origin of each component
* License information
* Component relationships and dependencies
* Known vulnerabilities in components

Tools can analyze SBOMs to identify security or compliance issues.
            """
        },
        {
            "title": "SBOM Integration",
            "content": """
# Integrating SBOMs in Development

Best practices for SBOM integration:

1. Generate SBOMs at build time
2. Store SBOMs with releases
3. Update SBOMs when dependencies change
4. Share SBOMs with security teams and customers
5. Use SBOMs to track component drift over time

SBOMs are becoming essential for compliance with security frameworks and regulations.
            """
        }
    ],
    "polyglot": [
        {
            "title": "Multi-Ecosystem Overview",
            "content": """
# Multi-Ecosystem Scanning

Modern applications often combine multiple programming languages and frameworks.
ossv-scanner supports multiple dependency ecosystems, including:

* JavaScript/NPM
* Python/PyPI
* Java/Maven
* Ruby/Gems
* PHP/Composer
* .NET/NuGet
* Go/Modules

This eliminates the need for multiple scanning tools for different ecosystems.
            """
        },
        {
            "title": "Project Structure",
            "content": """
# Polyglot Project Structure

Our demonstration project contains dependencies from multiple ecosystems:

```
polyglot-app/
├── package.json          # NPM dependencies
├── requirements.txt      # Python dependencies
├── pom.xml               # Maven dependencies
├── Gemfile               # Ruby dependencies
├── composer.json         # PHP dependencies
└── src/
    ├── main.js
    ├── app.py
    ├── Service.java
    └── app.rb
```

This represents a typical microservice architecture with multiple components.
            """
        },
        {
            "title": "Scanning Multiple Ecosystems",
            "content": """
# Scanning Multiple Ecosystems

When scanning a polyglot project, ossv-scanner:

1. Automatically detects all dependency manifest files
2. Parses each file according to its ecosystem's format
3. Uses ecosystem-specific vulnerability databases
4. Consolidates results into a unified report

This provides a comprehensive view of security across all project components.
            """
        },
        {
            "title": "Ecosystem-Specific Features",
            "content": """
# Ecosystem-Specific Features

ossv-scanner provides specialized capabilities for each ecosystem:

* **NPM**: Detects nested dependencies in node_modules
* **Python**: Handles both requirements.txt and Pipfile
* **Maven**: Resolves transitive dependencies
* **Ruby**: Supports Gemfile.lock analysis
* **PHP**: Parses composer.lock for exact versions

These specialized features ensure accurate results for each ecosystem.
            """
        },
        {
            "title": "Unified Reporting",
            "content": """
# Unified Vulnerability Reporting

The value of a multi-ecosystem scanner is evident in the unified reporting:

* Consistent severity ratings across ecosystems
* Aggregated risk assessment
* Prioritized remediation across all components
* Comprehensive SBOM covering all ecosystems

This allows security teams to address the most critical issues first, regardless of ecosystem.
            """
        }
    ],
    "remediation": [
        {
            "title": "Vulnerability Remediation Process",
            "content": """
# Vulnerability Remediation Process

Addressing vulnerabilities involves multiple steps:

1. **Identification**: Running the scanner to discover issues
2. **Assessment**: Evaluating impact, exploitability, and risk
3. **Prioritization**: Determining which issues to fix first
4. **Remediation**: Updating dependencies or implementing mitigations
5. **Verification**: Re-scanning to confirm fixes

We'll demonstrate this full process with a sample project.
            """
        },
        {
            "title": "Understanding Remediation Advice",
            "content": """
# Understanding Remediation Advice

ossv-scanner provides detailed remediation guidance:

* Fixed versions for each vulnerability
* Breaking change warnings for major version jumps
* Alternative packages when appropriate
* Temporary mitigation strategies

This information helps developers make informed update decisions.
            """
        },
        {
            "title": "Demo: Dependency Updates",
            "content": """
# Demo: Dependency Updates

Let's demonstrate the update process for vulnerable dependencies:

1. First scan: Identify vulnerabilities
2. Review the recommended fixed versions
3. Update the dependencies in manifest files
4. Resolve any compatibility issues
5. Second scan: Verify the vulnerabilities are resolved

This workflow ensures security without breaking functionality.
            """
        },
        {
            "title": "Handling Update Challenges",
            "content": """
# Handling Update Challenges

Common challenges when updating dependencies:

* **Breaking Changes**: Major version updates may require code changes
* **Dependency Conflicts**: Updated package may conflict with others
* **Test Coverage**: Ensuring changes don't introduce bugs
* **Legacy Dependencies**: Packages no longer maintained

Strategies to address these challenges:
* Incremental updates
* Comprehensive testing
* Temporary mitigations
* Consider alternative packages
            """
        },
        {
            "title": "Continuous Vulnerability Management",
            "content": """
# Continuous Vulnerability Management

Best practices for ongoing vulnerability management:

1. Establish regular scanning schedule
2. Automate dependency updates where possible
3. Maintain an inventory of accepted risks
4. Document exceptions and their rationale
5. Monitor vulnerability databases for new issues
6. Keep the scanner itself updated

This creates a sustainable process for maintaining security over time.
            """
        }
    ]
}

# Sample project templates for demos
SAMPLE_PROJECTS = {
    "basic": {
        "package.json": {
            "name": "basic-demo-project",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15",
                "jquery": "3.4.0",
                "minimist": "1.2.0"
            }
        }
    },
    "ci-cd": {
        "package.json": {
            "name": "ci-cd-demo-project",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15",
                "axios": "0.19.0",
                "express": "4.17.1"
            }
        },
        ".github/workflows/security.yml": """name: Security Scan

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
"""
    },
    "sbom": {
        "package.json": {
            "name": "sbom-demo-project",
            "version": "1.0.0",
            "dependencies": {
                "react": "16.13.1",
                "express": "4.17.1",
                "lodash": "4.17.20"
            }
        }
    },
    "polyglot": {
        "package.json": {
            "name": "polyglot-frontend",
            "version": "1.0.0",
            "dependencies": {
                "react": "17.0.2",
                "axios": "0.21.1",
                "lodash": "4.17.21"
            }
        },
        "requirements.txt": """
Django==2.2.24
requests==2.25.1
Flask==1.1.2
""",
        "pom.xml": """<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo-service</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>2.5.2</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.12.3</version>
        </dependency>
    </dependencies>
</project>"""
    },
    "remediation": {
        "package.json": {
            "name": "remediation-demo",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15",
                "jquery": "3.4.0",
                "react": "16.13.1",
                "express": "4.17.1"
            }
        },
        "fixed-package.json": {
            "name": "remediation-demo",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.21",
                "jquery": "3.6.0",
                "react": "17.0.2",
                "express": "4.17.3"
            }
        }
    }
}


def create_project_files(template: Dict[str, Any], base_dir: Path) -> None:
    """
    Create project files from a template.
    
    Args:
        template: Template containing file contents.
        base_dir: Base directory to create files in.
    """
    for file_path, content in template.items():
        full_path = base_dir / file_path
        
        # Create parent directories if needed
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file content
        if isinstance(content, dict):
            with open(full_path, "w") as f:
                json.dump(content, f, indent=2)
        else:
            with open(full_path, "w") as f:
                f.write(content)


def setup_basic_scenario(base_dir: Path) -> Path:
    """
    Set up files for the basic vulnerability scanning scenario.
    
    Args:
        base_dir: Base directory for scenario files.
        
    Returns:
        Path to the project directory.
    """
    scenario_dir = base_dir / "basic-demo"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    
    # Create project files
    create_project_files(SAMPLE_PROJECTS["basic"], scenario_dir)
    
    # Create a simple application file that uses the dependencies
    app_js = """// Simple demo application with vulnerable dependencies
const _ = require('lodash');
const $ = require('jquery');
const minimist = require('minimist');

// Parse command line arguments (example usage of minimist)
const args = minimist(process.argv.slice(2));
console.log('Command arguments:', args);

// Example usage of lodash (with vulnerable merge)
const defaultConfig = { 'settings': { 'defaultTheme': 'light' } };
const userConfig = JSON.parse('{"__proto__": {"polluted": true}}');
const config = _.merge({}, defaultConfig, userConfig);

// Example usage of jQuery
$(document).ready(function() {
    $('body').html('<h1>Welcome to Demo App</h1>');
    
    // Process user input (potentially vulnerable to XSS)
    const userInput = new URLSearchParams(window.location.search).get('name');
    if (userInput) {
        $('#greeting').html('Hello, ' + userInput);
    }
});

console.log('Application initialized with config:', config);
"""
    
    with open(scenario_dir / "app.js", "w") as f:
        f.write(app_js)
    
    return scenario_dir


def setup_cicd_scenario(base_dir: Path) -> Path:
    """
    Set up files for the CI/CD integration scenario.
    
    Args:
        base_dir: Base directory for scenario files.
        
    Returns:
        Path to the project directory.
    """
    scenario_dir = base_dir / "cicd-demo"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    
    # Create project files
    create_project_files(SAMPLE_PROJECTS["ci-cd"], scenario_dir)
    
    # Create additional CI configuration examples
    gitlab_ci = """stages:
  - test

security_scan:
  stage: test
  image: python:3.9
  script:
    - pip install ossv-scanner
    - ossv-scan --ci --fail-on-severity high .
  artifacts:
    paths:
      - ossv-scan-results.json
"""
    
    jenkins_file = """pipeline {
    agent {
        docker {
            image 'python:3.9'
        }
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install ossv-scanner'
                sh 'ossv-scan --ci --fail-on-severity high .'
            }
        }
    }
}
"""
    
    # Create the CI config files
    ci_dir = scenario_dir / ".gitlab"
    ci_dir.mkdir(parents=True, exist_ok=True)
    with open(ci_dir / "gitlab-ci.yml", "w") as f:
        f.write(gitlab_ci)
    
    with open(scenario_dir / "Jenkinsfile", "w") as f:
        f.write(jenkins_file)
    
    # Create a README with setup instructions
    readme = """# CI/CD Demo for ossv-scanner

This project demonstrates how to integrate ossv-scanner into various CI/CD platforms.

## Available CI Configurations:
- GitHub Actions: `.github/workflows/security.yml`
- GitLab CI: `.gitlab/gitlab-ci.yml`
- Jenkins: `Jenkinsfile`

## Setup Instructions

### For GitHub Actions:
1. Push this repository to GitHub
2. CI will automatically run on push to main branch or on pull requests

### For GitLab CI:
1. Push this repository to GitLab
2. CI will automatically run on push events

### For Jenkins:
1. Create a new Pipeline job
2. Configure it to use the Jenkinsfile from SCM
3. Run the pipeline

## Failure Thresholds
The demo is configured to fail builds when HIGH or CRITICAL severity vulnerabilities are found.
Modify `--fail-on-severity` to adjust this threshold.
"""
    
    with open(scenario_dir / "README.md", "w") as f:
        f.write(readme)
    
    return scenario_dir


def setup_sbom_scenario(base_dir: Path) -> Path:
    """
    Set up files for the SBOM generation scenario.
    
    Args:
        base_dir: Base directory for scenario files.
        
    Returns:
        Path to the project directory.
    """
    scenario_dir = base_dir / "sbom-demo"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    
    # Create project files
    create_project_files(SAMPLE_PROJECTS["sbom"], scenario_dir)
    
    # Create example SBOM generation script
    sbom_script = """#!/bin/bash
# SBOM Generation Script

# Generate CycloneDX SBOM in JSON format
echo "Generating CycloneDX SBOM in JSON format..."
ossv-scan --sbom-only --sbom-format cyclonedx --output-format json --output-path cyclonedx-sbom.json .

# Generate SPDX SBOM in JSON format
echo "Generating SPDX SBOM in JSON format..."
ossv-scan --sbom-only --sbom-format spdx --output-format json --output-path spdx-sbom.json .

# Generate CycloneDX SBOM in XML format
echo "Generating CycloneDX SBOM in XML format..."
ossv-scan --sbom-only --sbom-format cyclonedx --output-format xml --output-path cyclonedx-sbom.xml .

echo "SBOM generation complete!"
"""
    
    with open(scenario_dir / "generate-sboms.sh", "w") as f:
        f.write(sbom_script)
    
    # Make the script executable
    os.chmod(scenario_dir / "generate-sboms.sh", 0o755)
    
    # Add an example of SBOM usage document
    sbom_usage = """# SBOM Usage Guide

This document explains how to use Software Bill of Materials (SBOM) in your organization.

## What is an SBOM?

An SBOM is a formal record that contains the details and supply chain relationships
of components used in building software.

## Use Cases

### Security Monitoring

* Match SBOMs against new vulnerability announcements
* Automate alerts when new vulnerabilities affect your components
* Prioritize patching based on component usage across applications

### License Compliance

* Track all licenses used in your software
* Ensure compliance with organizational licensing policies
* Prepare for audits with comprehensive license information

### Supplier Transparency

* Understand the origin of all software components
* Assess supplier security practices
* Evaluate risk based on component origins

## SBOM Formats Supported

| Format | Strengths | Best For |
|--------|-----------|----------|
| **CycloneDX** | Security-focused, vulnerability tracking | Security teams |
| **SPDX** | License compliance, legal documentation | Legal & compliance |
| **SWID** | Asset management, inventory | IT operations |

## Integration Examples

### DevSecOps Pipeline

```
[Code Repository] → [Build] → [Generate SBOM] → [Store SBOM] → [Deploy]
                                     ↓
                               [Scan SBOM] → [Security Dashboard]
```

### Vulnerability Management

```
[SBOM Repository] ← → [Vulnerability Database]
       ↓
[Match & Alert] → [Prioritize] → [Remediate]
```

## Best Practices

1. Generate SBOMs with each build
2. Version SBOMs alongside software releases
3. Store SBOMs in a searchable repository
4. Automate SBOM analysis
5. Share SBOMs with customers and security teams
"""
    
    with open(scenario_dir / "SBOM-USAGE.md", "w") as f:
        f.write(sbom_usage)
    
    return scenario_dir


def setup_polyglot_scenario(base_dir: Path) -> Path:
    """
    Set up files for the multi-ecosystem scanning scenario.
    
    Args:
        base_dir: Base directory for scenario files.
        
    Returns:
        Path to the project directory.
    """
    scenario_dir = base_dir / "polyglot-demo"
    scenario_dir.mkdir(parents=True, exist_ok=True)
    
    # Create project files from template
    create_project_files(SAMPLE_PROJECTS["polyglot"], scenario_dir)
    
    # Add some additional files to make it more realistic
    
    # Ruby Gemfile
    gemfile = """source 'https://rubygems.org'

gem 'rake', '13.0.3'
gem 'rails', '6.1.3'
gem 'nokogiri', '1.11.2'
gem 'puma', '5.2.2'
"""
    
    # PHP composer.json
    composer_json = {
        "name": "demo/polyglot-php",
        "description": "PHP component of polyglot demo",
        "type": "project",
        "require": {
            "php": ">=7.4",
            "symfony/http-foundation": "5.2.3",
            "laravel/framework": "8.34.0",
            "guzzlehttp/guzzle": "7.2.0"
        }
    }
    
    # .NET project file
    csproj = """<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net5.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="5.0.4" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Swashbuckle.AspNetCore" Version="6.1.0" />
  </ItemGroup>

</Project>
"""
    
    # Create source directories
    src_dir = scenario_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    
    # JavaScript source file
    js_src = """// Frontend component
import React from 'react';
import axios from 'axios';
import _ from 'lodash';

function App() {
  const [data, setData] = React.useState(null);
  
  React.useEffect(() => {
    axios.get('/api/data')
      .then(response => {
        setData(_.get(response, 'data', []));
      })
      .catch(error => console.error('Error fetching data:', error));
  }, []);
  
  return (
    <div className="App">
      <h1>Polyglot Demo Application</h1>
      <div>{data ? JSON.stringify(data) : 'Loading...'}</div>
    </div>
  );
}

export default App;
"""
    
    # Python source file
    python_src = """# API Gateway Service
from flask import Flask, jsonify, request
import requests
from datetime import datetime

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    # Get data from Java backend service
    try:
        response = requests.get('http://backend-service:8080/data')
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/user', methods=['POST'])
def create_user():
    # Forward user creation request to backend
    user_data = request.get_json()
    response = requests.post('http://backend-service:8080/user', json=user_data)
    return jsonify(response.json()), response.status_code

if __name__ == '__main
"""

# API Gateway Service
from flask import Flask, jsonify, request
import requests
from datetime import datetime

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    # Get data from Java backend service
    try:
        response = requests.get('http://backend-service:8080/data')
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/user', methods=['POST'])
def create_user():
    # Forward user creation request to backend
    user_data = request.get_json()
    response = requests.post('http://backend-service:8080/user', json=user_data)
    return jsonify(response.json()), response.status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
