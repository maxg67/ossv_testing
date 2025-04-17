"""
Tool comparison matrix for ossv-scanner.

This module compares ossv-scanner with other vulnerability scanning tools
across a variety of metrics to provide a comprehensive comparison matrix.
"""

import os
import time
import logging
import tempfile
import json
import yaml
import subprocess
import shutil
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import statistics

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from ossv_testing.benchmark.nist import create_test_project as create_nist_project
from ossv_testing.controlled.test_suite import create_test_project as create_controlled_project

logger = logging.getLogger(__name__)
console = Console()

# Define other vulnerability scanning tools to compare against
COMPARISON_TOOLS = {
    "snyk": {
        "name": "Snyk",
        "description": "Developer security platform to find & fix vulnerabilities",
        "command": "snyk test",
        "result_parser": "parse_snyk_results",
        "website": "https://snyk.io/",
        "license": "Commercial",
        "install_command": "npm install -g snyk"
    },
    "dependabot": {
        "name": "Dependabot",
        "description": "GitHub's dependency scanning tool",
        "command": "simulate_dependabot",  # GitHub-hosted, we'll simulate it
        "result_parser": "parse_dependabot_results",
        "website": "https://github.com/dependabot",
        "license": "Free with GitHub",
        "install_command": "N/A - GitHub-hosted service"
    },
    "owasp-dependency-check": {
        "name": "OWASP Dependency-Check",
        "description": "Software composition analysis tool",
        "command": "dependency-check --scan {path} --out {output}",
        "result_parser": "parse_dependency_check_results",
        "website": "https://owasp.org/www-project-dependency-check/",
        "license": "Open Source",
        "install_command": "Varies by platform - see website"
    },
    "npm-audit": {
        "name": "NPM Audit",
        "description": "Built-in security audit for npm packages",
        "command": "cd {path} && npm audit --json > {output}",
        "result_parser": "parse_npm_audit_results", 
        "website": "https://docs.npmjs.com/cli/v8/commands/npm-audit",
        "license": "Free",
        "install_command": "Included with npm"
    },
    "safety": {
        "name": "Safety",
        "description": "Python vulnerability scanner",
        "command": "safety check -r {path}/requirements.txt --json > {output}",
        "result_parser": "parse_safety_results",
        "website": "https://pyup.io/safety/",
        "license": "Open Source / Commercial",
        "install_command": "pip install safety"
    }
}

COMPARISON_TOOLS["owasp-dc"] = COMPARISON_TOOLS["owasp-dependency-check"]

# Metrics for comparison
COMPARISON_METRICS = [
    # Detection Effectiveness
    "true_positive_rate",
    "false_positive_rate",
    "detection_latency",  # Days between vulnerability publication and detection
    "vulnerability_coverage",  # Percentage of known vulnerabilities detected
    
    # Feature Completeness
    "sbom_generation",   # Can generate SBOM
    "license_detection", # Can detect license issues
    "remediation_advice", # Provides fix advice
    "severity_accuracy",  # Accurate severity ratings
    
    # Performance
    "scan_time",         # Time to scan in seconds
    "memory_usage",      # Peak memory usage in MB
    "cpu_usage",         # Peak CPU usage in percent
    
    # Usability
    "setup_complexity",  # 1-10 scale (1 = easiest)
    "ci_cd_integration", # 1-10 scale (1 = easiest)
    "report_quality",    # 1-10 scale (1 = best)
    
    # Cost
    "license_cost",      # Annual cost for comparable license
    "maintenance_cost",  # Estimated annual maintenance cost
]

# Test projects for comparison
TEST_PROJECTS = [
    {
        "id": "npm-small",
        "name": "Small NPM Project",
        "description": "Small JavaScript project with npm dependencies",
        "creator": "create_npm_project",
        "known_vulns": 3
    },
    {
        "id": "python-small",
        "name": "Small Python Project",
        "description": "Small Python project with pip dependencies",
        "creator": "create_python_project",
        "known_vulns": 3
    },
    {
        "id": "mixed-medium",
        "name": "Medium Mixed Project",
        "description": "Medium-sized project with mixed dependencies",
        "creator": "create_mixed_project",
        "known_vulns": 5
    }
]


def create_npm_project(base_dir: Path) -> Tuple[Path, List[Dict[str, Any]]]:
    """
    Create a small NPM project with known vulnerabilities.
    
    Args:
        base_dir: Base directory for creating projects.
        
    Returns:
        Tuple of (project_path, known_vulnerabilities).
    """
    project_dir = base_dir / "npm-small"
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package.json with vulnerable dependencies
    package_json = {
        "name": "npm-small-test",
        "version": "1.0.0",
        "description": "Small NPM project for tool comparison",
        "dependencies": {
            "lodash": "4.17.15",  # CVE-2019-10744
            "jquery": "3.4.0",     # CVE-2019-11358
            "minimist": "1.2.0"    # CVE-2020-7598
        }
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create a basic index.js file
    with open(project_dir / "index.js", "w") as f:
        f.write("""
const _ = require('lodash');
const $ = require('jquery');
const minimist = require('minimist');

// Simple example using the libraries
const args = minimist(process.argv.slice(2));
console.log(_.upperCase('Hello World'));
console.log(`Using jQuery version: ${$.fn.jquery}`);
console.log('Arguments:', args);
""")
    
    # List of known vulnerabilities in this project
    known_vulns = [
        {
            "id": "CVE-2019-10744",
            "package": "lodash",
            "version": "4.17.15",
            "severity": "HIGH",
            "description": "Prototype pollution in lodash"
        },
        {
            "id": "CVE-2019-11358",
            "package": "jquery",
            "version": "3.4.0",
            "severity": "MEDIUM",
            "description": "Prototype pollution in jQuery"
        },
        {
            "id": "CVE-2020-7598",
            "package": "minimist",
            "version": "1.2.0",
            "severity": "MEDIUM",
            "description": "Prototype pollution in minimist"
        }
    ]
    
    return project_dir, known_vulns


def create_python_project(base_dir: Path) -> Tuple[Path, List[Dict[str, Any]]]:
    """
    Create a small Python project with known vulnerabilities.
    
    Args:
        base_dir: Base directory for creating projects.
        
    Returns:
        Tuple of (project_path, known_vulnerabilities).
    """
    project_dir = base_dir / "python-small"
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create requirements.txt with vulnerable dependencies
    requirements = [
        "Django==2.2.8",    # CVE-2019-19844
        "Flask==0.12.2",    # CVE-2018-1000656
        "Jinja2==2.10.1"    # CVE-2019-10906
    ]
    
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("\n".join(requirements))
    
    # Create a basic app.py file
    with open(project_dir / "app.py", "w") as f:
        f.write("""
from flask import Flask, render_template, request
import jinja2

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello World"

if __name__ == "__main__":
    app.run(debug=True)
""")
    
    # List of known vulnerabilities in this project
    known_vulns = [
        {
            "id": "CVE-2019-19844",
            "package": "Django",
            "version": "2.2.8",
            "severity": "HIGH",
            "description": "Account takeover vulnerability"
        },
        {
            "id": "CVE-2018-1000656",
            "package": "Flask",
            "version": "0.12.2",
            "severity": "HIGH",
            "description": "Denial of service vulnerability"
        },
        {
            "id": "CVE-2019-10906",
            "package": "Jinja2",
            "version": "2.10.1",
            "severity": "HIGH",
            "description": "Sandbox escape vulnerability"
        }
    ]
    
    return project_dir, known_vulns


def create_mixed_project(base_dir: Path) -> Tuple[Path, List[Dict[str, Any]]]:
    """
    Create a medium-sized project with mixed dependencies.
    
    Args:
        base_dir: Base directory for creating projects.
        
    Returns:
        Tuple of (project_path, known_vulnerabilities).
    """
    project_dir = base_dir / "mixed-medium"
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package.json with vulnerable dependencies
    package_json = {
        "name": "mixed-medium-test",
        "version": "1.0.0",
        "description": "Mixed project for tool comparison",
        "dependencies": {
            "lodash": "4.17.15",   # CVE-2019-10744
            "express": "4.17.1"     # Several CVEs in dependencies
        },
        "devDependencies": {
            "mocha": "6.2.2"        # CVE-2020-7598 in dependencies
        }
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create requirements.txt with vulnerable dependencies
    requirements = [
        "Django==2.2.8",    # CVE-2019-19844
        "requests==2.20.0"  # CVE-2018-18074
    ]
    
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("\n".join(requirements))
    
    # List of known vulnerabilities in this project
    known_vulns = [
        {
            "id": "CVE-2019-10744",
            "package": "lodash",
            "version": "4.17.15",
            "severity": "HIGH",
            "description": "Prototype pollution in lodash"
        },
        {
            "id": "CVE-2019-19844",
            "package": "Django",
            "version": "2.2.8",
            "severity": "HIGH",
            "description": "Account takeover vulnerability"
        },
        {
            "id": "CVE-2018-18074",
            "package": "requests",
            "version": "2.20.0",
            "severity": "MEDIUM",
            "description": "Information disclosure vulnerability"
        },
        # There could be more in express and mocha dependencies
        {
            "id": "CVE-2019-15605",
            "package": "express/glob-parent",
            "version": "transitive",
            "severity": "MEDIUM",
            "description": "Regular expression denial of service"
        },
        {
            "id": "CVE-2020-7598",
            "package": "mocha/minimist",
            "version": "transitive",
            "severity": "MEDIUM",
            "description": "Prototype pollution in minimist"
        }
    ]
    
    return project_dir, known_vulns


def create_test_projects(base_dir: Path) -> Dict[str, Tuple[Path, List[Dict[str, Any]]]]:
    """
    Create test projects for tool comparison.
    
    Args:
        base_dir: Base directory for projects.
        
    Returns:
        Dictionary mapping project IDs to tuples of (project_path, known_vulnerabilities).
    """
    projects = {}
    
    for project in TEST_PROJECTS:
        if project["creator"] == "create_npm_project":
            project_dir, known_vulns = create_npm_project(base_dir)
        elif project["creator"] == "create_python_project":
            project_dir, known_vulns = create_python_project(base_dir)
        elif project["creator"] == "create_mixed_project":
            project_dir, known_vulns = create_mixed_project(base_dir)
        else:
            logger.warning(f"Unknown project creator: {project['creator']}")
            continue
        
        projects[project["id"]] = (project_dir, known_vulns)
    
    return projects


def run_ossv_scanner(project_dir: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Run ossv-scanner on a project.
    
    Args:
        project_dir: Project directory.
        output_dir: Output directory for results.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-ossv-results.json"
    
    metrics = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "exit_code": None,
        "success": False,
        "error": None,
        "memory_usage": 0,
        "cpu_usage": 0
    }
    
    try:
        # Run the scanner
        logger.info(f"Running ossv-scanner on {project_dir}")
        
        scan_cmd = [
            "ossv-scan",
            "--output-format", "json",
            "--output-path", str(output_path),
            str(project_dir)
        ]
        
        # Monitor resource usage
        import psutil
        
        try:
            # Try to run as installed package
            process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Monitor process
            p = psutil.Process(process.pid)
            
            # Sample CPU and memory usage
            cpu_samples = []
            memory_samples = []
            
            while process.poll() is None:
                try:
                    cpu_samples.append(p.cpu_percent())
                    memory_info = p.memory_info()
                    memory_samples.append(memory_info.rss / (1024 * 1024))  # Convert to MB
                    time.sleep(0.1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
            
            stdout, stderr = process.communicate()
            metrics["exit_code"] = process.returncode
            
            # Calculate resource usage
            if cpu_samples:
                metrics["cpu_usage"] = max(cpu_samples)
            if memory_samples:
                metrics["memory_usage"] = max(memory_samples)
            
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            scan_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_dir)
            ]
            
            process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Monitor process
            p = psutil.Process(process.pid)
            
            # Sample CPU and memory usage
            cpu_samples = []
            memory_samples = []
            
            while process.poll() is None:
                try:
                    cpu_samples.append(p.cpu_percent())
                    memory_info = p.memory_info()
                    memory_samples.append(memory_info.rss / (1024 * 1024))
                    time.sleep(0.1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
            
            stdout, stderr = process.communicate()
            metrics["exit_code"] = process.returncode
            
            # Calculate resource usage
            if cpu_samples:
                metrics["cpu_usage"] = max(cpu_samples)
            if memory_samples:
                metrics["memory_usage"] = max(memory_samples)
        
        # Record end time and duration
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        
        # Check if scan was successful
        metrics["success"] = (metrics["exit_code"] == 0 and output_path.exists())
        
        logger.info(f"Scanner completed in {metrics['duration']:.2f} seconds. Results at {output_path}")
        
        return output_path, metrics
        
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        metrics["error"] = str(e)
        
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path, metrics


def simulate_snyk_results(project_dir: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Simulate running Snyk on a project.
    
    Args:
        project_dir: Project directory.
        output_dir: Output directory for results.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-snyk-results.json"
    
    metrics = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "exit_code": 0,
        "success": True,
        "error": None,
        "memory_usage": 120,  # Simulated value
        "cpu_usage": 25       # Simulated value
    }
    
    try:
        # Determine project type
        has_package_json = (project_dir / "package.json").exists()
        has_requirements_txt = (project_dir / "requirements.txt").exists()
        
        # Generate simulated results
        results = {
            "vulnerabilities": []
        }
        
        # Add simulated npm vulnerabilities
        if has_package_json:
            with open(project_dir / "package.json", "r") as f:
                package_data = json.load(f)
                deps = package_data.get("dependencies", {})
                
                if "lodash" in deps:
                    results["vulnerabilities"].append({
                        "id": "SNYK-JS-LODASH-567746",
                        "packageName": "lodash",
                        "version": deps["lodash"],
                        "title": "Prototype Pollution",
                        "severity": "high",
                        "cvssScore": 7.4,
                        "CVE": ["CVE-2019-10744"]
                    })
                
                if "jquery" in deps:
                    results["vulnerabilities"].append({
                        "id": "SNYK-JS-JQUERY-565129",
                        "packageName": "jquery",
                        "version": deps["jquery"],
                        "title": "Prototype Pollution",
                        "severity": "medium",
                        "cvssScore": 6.5,
                        "CVE": ["CVE-2019-11358"]
                    })
                
                if "minimist" in deps:
                    results["vulnerabilities"].append({
                        "id": "SNYK-JS-MINIMIST-559764",
                        "packageName": "minimist",
                        "version": deps["minimist"],
                        "title": "Prototype Pollution",
                        "severity": "medium",
                        "cvssScore": 5.6,
                        "CVE": ["CVE-2020-7598"]
                    })
                
                # Add simulated transitive vulnerabilities
                if "express" in deps:
                    results["vulnerabilities"].append({
                        "id": "SNYK-JS-GLOBPARENT-1016905",
                        "packageName": "glob-parent",
                        "version": "3.1.0",
                        "from": ["express@4.17.1", "glob-parent@3.1.0"],
                        "title": "Regular Expression Denial of Service",
                        "severity": "medium",
                        "cvssScore": 5.3,
                        "CVE": ["CVE-2019-15605"]
                    })
        
        # Add simulated Python vulnerabilities
        if has_requirements_txt:
            with open(project_dir / "requirements.txt", "r") as f:
                requirements = f.read().splitlines()
                
                for req in requirements:
                    if "==" not in req:
                        continue
                    
                    name, version = req.split("==")
                    name = name.strip()
                    version = version.strip()
                    
                    if name.lower() == "django" and version == "2.2.8":
                        results["vulnerabilities"].append({
                            "id": "SNYK-PYTHON-DJANGO-559326",
                            "packageName": "django",
                            "version": version,
                            "title": "Account Takeover",
                            "severity": "high",
                            "cvssScore": 8.8,
                            "CVE": ["CVE-2019-19844"]
                        })
                    
                    if name.lower() == "flask" and version == "0.12.2":
                        results["vulnerabilities"].append({
                            "id": "SNYK-PYTHON-FLASK-451637",
                            "packageName": "flask",
                            "version": version,
                            "title": "Denial of Service",
                            "severity": "high",
                            "cvssScore": 7.5,
                            "CVE": ["CVE-2018-1000656"]
                        })
                    
                    if name.lower() == "jinja2" and version.startswith("2.10"):
                        results["vulnerabilities"].append({
                            "id": "SNYK-PYTHON-JINJA2-174126",
                            "packageName": "jinja2",
                            "version": version,
                            "title": "Sandbox Escape",
                            "severity": "high",
                            "cvssScore": 7.7,
                            "CVE": ["CVE-2019-10906"]
                        })
                    
                    if name.lower() == "requests" and version == "2.20.0":
                        results["vulnerabilities"].append({
                            "id": "SNYK-PYTHON-REQUESTS-40217",
                            "packageName": "requests",
                            "version": version,
                            "title": "Information Disclosure",
                            "severity": "medium",
                            "cvssScore": 5.9,
                            "CVE": ["CVE-2018-18074"]
                        })
        
        # Write the results to file
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        # Add a small delay to simulate scanning time
        time.sleep(0.5 + (len(results["vulnerabilities"]) * 0.1))
        
        # Update metrics
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        
        return output_path, metrics
        
    except Exception as e:
        logger.error(f"Error simulating Snyk results: {str(e)}")
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        metrics["success"] = False
        metrics["error"] = str(e)
        
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path, metrics


def simulate_dependabot_results(project_dir: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Simulate Dependabot results for a project.
    
    Args:
        project_dir: Project directory.
        output_dir: Output directory for results.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-dependabot-results.json"
    
    metrics = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "exit_code": 0,
        "success": True,
        "error": None,
        "memory_usage": 90,   # Simulated value
        "cpu_usage": 20       # Simulated value
    }
    
    try:
        # Determine project type
        has_package_json = (project_dir / "package.json").exists()
        has_requirements_txt = (project_dir / "requirements.txt").exists()
        
        # Generate simulated results
        results = {
            "alerts": []
        }
        
        # Add simulated npm vulnerabilities
        if has_package_json:
            with open(project_dir / "package.json", "r") as f:
                package_data = json.load(f)
                deps = package_data.get("dependencies", {})
                
                if "lodash" in deps:
                    results["alerts"].append({
                        "dependency": "lodash",
                        "version": deps["lodash"],
                        "advisory": {
                            "cve_id": "CVE-2019-10744",
                            "summary": "Prototype Pollution in lodash",
                            "severity": "high"
                        },
                        "patched_versions": ">=4.17.19"
                    })
                
                if "jquery" in deps:
                    results["alerts"].append({
                        "dependency": "jquery",
                        "version": deps["jquery"],
                        "advisory": {
                            "cve_id": "CVE-2019-11358",
                            "summary": "Prototype Pollution in jQuery",
                            "severity": "medium"
                        },
                        "patched_versions": ">=3.4.1"
                    })
                
                if "minimist" in deps:
                    results["alerts"].append({
                        "dependency": "minimist",
                        "version": deps["minimist"],
                        "advisory": {
                            "cve_id": "CVE-2020-7598",
                            "summary": "Prototype Pollution in minimist",
                            "severity": "medium"
                        },
                        "patched_versions": ">=1.2.3"
                    })
        
        # Add simulated Python vulnerabilities
        if has_requirements_txt:
            with open(project_dir / "requirements.txt", "r") as f:
                requirements = f.read().splitlines()
                
                for req in requirements:
                    if "==" not in req:
                        continue
                    
                    name, version = req.split("==")
                    name = name.strip()
                    version = version.strip()
                    
                    if name.lower() == "django" and version == "2.2.8":
                        results["alerts"].append({
                            "dependency": "django",
                            "version": version,
                            "advisory": {
                                "cve_id": "CVE-2019-19844",
                                "summary": "Potential account takeover via password reset form",
                                "severity": "high"
                            },
                            "patched_versions": ">=2.2.9"
                        })
                    
                    if name.lower() == "flask" and version == "0.12.2":
                        results["alerts"].append({
                            "dependency": "flask",
                            "version": version,
                            "advisory": {
                                "cve_id": "CVE-2018-1000656",
                                "summary": "Denial of Service vulnerability",
                                "severity": "high" 
                            },
                            "patched_versions": ">=0.12.3"
                        })
                    
                    if name.lower() == "jinja2" and version.startswith("2.10"):
                        results["alerts"].append({
                            "dependency": "jinja2",
                            "version": version,
                            "advisory": {
                                "cve_id": "CVE-2019-10906",
                                "summary": "Sandbox Escape vulnerability",
                                "severity": "high"
                            },
                            "patched_versions": ">=2.10.1" 
                        })
                    
                    if name.lower() == "requests" and version == "2.20.0":
                        results["alerts"].append({
                            "dependency": "requests",
                            "version": version,
                            "advisory": {
                                "cve_id": "CVE-2018-18074",
                                "summary": "Information Disclosure vulnerability",
                                "severity": "medium"
                            },
                            "patched_versions": ">=2.20.1"
                        })
        
        # Write the results to file
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        # Add a small delay to simulate scanning time
        time.sleep(0.3 + (len(results["alerts"]) * 0.05))
        
        # Update metrics
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        
        return output_path, metrics
        
    except Exception as e:
        logger.error(f"Error simulating Dependabot results: {str(e)}")
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        metrics["success"] = False
        metrics["error"] = str(e)
        
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path, metrics


def simulate_dependency_check_results(project_dir: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Simulate OWASP Dependency-Check results for a project.
    
    Args:
        project_dir: Project directory.
        output_dir: Output directory for results.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-dependency-check-results.json"
    
    metrics = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "exit_code": 0,
        "success": True,
        "error": None,
        "memory_usage": 350,  # Simulated value - DC uses a lot of memory
        "cpu_usage": 35       # Simulated value
    }
    
    try:
        # Determine project type
        has_package_json = (project_dir / "package.json").exists()
        has_requirements_txt = (project_dir / "requirements.txt").exists()
        
        # Generate simulated results
        results = {
            "dependencies": []
        }
        
        # Add simulated npm vulnerabilities
        if has_package_json:
            with open(project_dir / "package.json", "r") as f:
                package_data = json.load(f)
                deps = package_data.get("dependencies", {})
                
                for dep_name, version in deps.items():
                    dependency = {
                        "fileName": f"node_modules/{dep_name}",
                        "filePath": f"node_modules/{dep_name}",
                        "projectReferences": ["package.json"],
                        "evidenceCollected": {
                            "vendorEvidence": [{"name": "name", "value": dep_name}],
                            "productEvidence": [{"name": "name", "value": dep_name}],
                            "versionEvidence": [{"name": "version", "value": version}]
                        },
                        "packages": [{
                            "id": f"pkg:npm/{dep_name}@{version}",
                            "vulnerabilities": []
                        }]
                    }
                    
                    # Add specific vulnerabilities
                    if dep_name == "lodash" and version == "4.17.15":
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2019-10744",
                            "severity": "HIGH",
                            "cvssScore": 7.4,
                            "description": "Prototype Pollution in lodash"
                        })
                    
                    if dep_name == "jquery" and version == "3.4.0":
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2019-11358",
                            "severity": "MEDIUM",
                            "cvssScore": 6.1,
                            "description": "Prototype Pollution in jQuery"
                        })
                    
                    if dep_name == "minimist" and version == "1.2.0":
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2020-7598",
                            "severity": "MEDIUM",
                            "cvssScore": 5.6,
                            "description": "Prototype Pollution in minimist"
                        })
                    
                    results["dependencies"].append(dependency)
        
        # Add simulated Python vulnerabilities
        if has_requirements_txt:
            with open(project_dir / "requirements.txt", "r") as f:
                requirements = f.read().splitlines()
                
                for req in requirements:
                    if "==" not in req:
                        continue
                    
                    name, version = req.split("==")
                    name = name.strip()
                    version = version.strip()
                    
                    dependency = {
                        "fileName": f"site-packages/{name.lower()}",
                        "filePath": f"site-packages/{name.lower()}",
                        "projectReferences": ["requirements.txt"],
                        "evidenceCollected": {
                            "vendorEvidence": [{"name": "name", "value": name}],
                            "productEvidence": [{"name": "name", "value": name}],
                            "versionEvidence": [{"name": "version", "value": version}]
                        },
                        "packages": [{
                            "id": f"pkg:pypi/{name.lower()}@{version}",
                            "vulnerabilities": []
                        }]
                    }
                    
                    # Add specific vulnerabilities
                    if name.lower() == "django" and version == "2.2.8":
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2019-19844",
                            "severity": "HIGH",
                            "cvssScore": 8.8,
                            "description": "Account Takeover vulnerability in Django"
                        })
                    
                    if name.lower() == "flask" and version == "0.12.2":
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2018-1000656",
                            "severity": "HIGH",
                            "cvssScore": 7.5,
                            "description": "Denial of Service vulnerability in Flask"
                        })
                    
                    if name.lower() == "jinja2" and version.startswith("2.10"):
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2019-10906",
                            "severity": "HIGH",
                            "cvssScore": 7.7,
                            "description": "Sandbox Escape vulnerability in Jinja2"
                        })
                    
                    if name.lower() == "requests" and version == "2.20.0":
                        dependency["packages"][0]["vulnerabilities"].append({
                            "name": "CVE-2018-18074",
                            "severity": "MEDIUM",
                            "cvssScore": 5.9,
                            "description": "Information Disclosure vulnerability in Requests"
                        })
                    
                    results["dependencies"].append(dependency)
        
        # Write the results to file
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        
        # Dependency Check is slow, simulate longer scan time
        time.sleep(2.0 + (len(results["dependencies"]) * 0.2))
        
        # Update metrics
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        
        return output_path, metrics
        
    except Exception as e:
        logger.error(f"Error simulating Dependency-Check results: {str(e)}")
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        metrics["success"] = False
        metrics["error"] = str(e)
        
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path, metrics


def run_comparative_test(tool_id: str, project_dir: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Run a comparison test with a specific tool.
    
    Args:
        tool_id: Tool identifier.
        project_dir: Project directory.
        output_dir: Output directory for results.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    if tool_id == "ossv-scanner":
        return run_ossv_scanner(project_dir, output_dir)
    elif tool_id == "snyk":
        # In a real implementation, we would run the actual tool if available
        # For this simulation, we'll generate synthetic results
        return simulate_snyk_results(project_dir, output_dir)
    elif tool_id == "dependabot":
        return simulate_dependabot_results(project_dir, output_dir)
    elif tool_id == "owasp-dependency-check" or tool_id == "owasp-dc":
        return simulate_dependency_check_results(project_dir, output_dir)
    else:
        raise ValueError(f"Unknown tool ID: {tool_id}")


def parse_results(tool_id: str, result_path: Path, known_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse and analyze results from a specific tool.
    
    Args:
        tool_id: Tool identifier.
        result_path: Path to result file.
        known_vulns: List of known vulnerabilities for comparison.
        
    Returns:
        Analysis result.
    """
    if not result_path.exists():
        return {
            "true_positives": 0,
            "false_negatives": len(known_vulns),
            "false_positives": 0,
            "true_positive_rate": 0.0,
            "false_positive_rate": 0.0,
            "f1_score": 0.0,
            "sbom_generated": False,
            "license_detected": False,
            "remediation_advised": False,
            "detected_vulnerabilities": [],
            "missed_vulnerabilities": known_vulns.copy(),
            "extra_vulnerabilities": []
        }
    
    try:
        # Load results file
        with open(result_path, "r") as f:
            results = json.load(f)
        
        # Initialize analysis
        analysis = {
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
            "true_positive_rate": 0.0,
            "false_positive_rate": 0.0,
            "f1_score": 0.0,
            "sbom_generated": False,
            "license_detected": False,
            "remediation_advised": False,
            "detected_vulnerabilities": [],
            "missed_vulnerabilities": [],
            "extra_vulnerabilities": []
        }
        
        # Parse based on tool
        if tool_id == "ossv-scanner":
            return parse_ossv_results(results, known_vulns)
        elif tool_id == "snyk":
            return parse_snyk_results(results, known_vulns)
        elif tool_id == "dependabot":
            return parse_dependabot_results(results, known_vulns)
        elif tool_id == "owasp-dependency-check":
            return parse_dependency_check_results(results, known_vulns)
        else:
            return analysis
    
    except Exception as e:
        logger.error(f"Error parsing {tool_id} results: {str(e)}")
        return {
            "true_positives": 0,
            "false_negatives": len(known_vulns),
            "false_positives": 0,
            "true_positive_rate": 0.0,
            "false_positive_rate": 0.0,
            "f1_score": 0.0,
            "sbom_generated": False,
            "license_detected": False,
            "remediation_advised": False,
            "detected_vulnerabilities": [],
            "missed_vulnerabilities": known_vulns.copy(),
            "extra_vulnerabilities": [],
            "error": str(e)
        }


def parse_ossv_results(results: Dict[str, Any], known_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse and analyze results from ossv-scanner.
    
    Args:
        results: Parsed results from ossv-scanner.
        known_vulns: List of known vulnerabilities for comparison.
        
    Returns:
        Analysis result.
    """
    analysis = {
        "true_positives": 0,
        "false_negatives": 0,
        "false_positives": 0,
        "true_positive_rate": 0.0,
        "false_positive_rate": 0.0,
        "f1_score": 0.0,
        "sbom_generated": "sbom" in results,
        "license_detected": False,
        "remediation_advised": False,
        "detected_vulnerabilities": [],
        "missed_vulnerabilities": [],
        "extra_vulnerabilities": []
    }
    
    # Check for vulnerabilities
    detected_vulns = []
    if "vulnerabilities" in results:
        for dep_id, vulns in results["vulnerabilities"].items():
            package_name = dep_id.split("@")[0] if "@" in dep_id else dep_id
            package_version = dep_id.split("@")[1] if "@" in dep_id else None
            
            for vuln in vulns:
                detected_vulns.append({
                    "id": vuln.get("cve_id", ""),
                    "package": package_name,
                    "version": package_version,
                    "severity": vuln.get("severity", "UNKNOWN"),
                })
                
                # Check for remediation advice
                if "fixed_version" in vuln and vuln["fixed_version"]:
                    analysis["remediation_advised"] = True
    
    # Check if SBOM includes license info
    if "sbom" in results and "json" in results["sbom"]:
        try:
            sbom_json = json.loads(results["sbom"]["json"])
            if "components" in sbom_json:
                for component in sbom_json["components"]:
                    if "licenses" in component and component["licenses"]:
                        analysis["license_detected"] = True
                        break
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Match against known vulnerabilities
    for known in known_vulns:
        found = False
        for detected in detected_vulns:
            # Match by CVE ID
            if known["id"] == detected["id"]:
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
            
            # Try matching by package name and severity if no CVE ID match
            if (not found and known["package"] == detected["package"] and 
                known["severity"] == detected["severity"]):
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
        
        if not found:
            analysis["false_negatives"] += 1
            analysis["missed_vulnerabilities"].append(known)
    
    # Check for false positives
    for detected in detected_vulns:
        if not any(known["id"] == detected["id"] for known in known_vulns):
            if not any(known["package"] == detected["package"] and 
                       known["severity"] == detected["severity"] for known in known_vulns):
                analysis["false_positives"] += 1
                analysis["extra_vulnerabilities"].append(detected)
    
    # Calculate metrics
    total_known = len(known_vulns)
    if total_known > 0:
        analysis["true_positive_rate"] = analysis["true_positives"] / total_known
    
    total_detected = analysis["true_positives"] + analysis["false_positives"]
    if total_detected > 0:
        precision = analysis["true_positives"] / total_detected
    else:
        precision = 0.0
    
    if precision + analysis["true_positive_rate"] > 0:
        analysis["f1_score"] = 2 * (precision * analysis["true_positive_rate"]) / (precision + analysis["true_positive_rate"])
    
    return analysis


def parse_snyk_results(results: Dict[str, Any], known_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse and analyze results from Snyk.
    
    Args:
        results: Parsed results from Snyk.
        known_vulns: List of known vulnerabilities for comparison.
        
    Returns:
        Analysis result.
    """
    analysis = {
        "true_positives": 0,
        "false_negatives": 0,
        "false_positives": 0,
        "true_positive_rate": 0.0,
        "false_positive_rate": 0.0,
        "f1_score": 0.0,
        "sbom_generated": False,  # Snyk doesn't generate SBOMs by default
        "license_detected": True,  # Snyk typically detects licenses
        "remediation_advised": True,  # Snyk always provides remediation advice
        "detected_vulnerabilities": [],
        "missed_vulnerabilities": [],
        "extra_vulnerabilities": []
    }
    
    # Extract detected vulnerabilities
    detected_vulns = []
    if "vulnerabilities" in results:
        for vuln in results["vulnerabilities"]:
            cve_ids = vuln.get("CVE", [])
            cve_id = cve_ids[0] if cve_ids else ""
            
            detected_vulns.append({
                "id": cve_id,
                "package": vuln.get("packageName", ""),
                "version": vuln.get("version", ""),
                "severity": vuln.get("severity", "unknown").upper(),
            })
    
    # Match against known vulnerabilities
    for known in known_vulns:
        found = False
        for detected in detected_vulns:
            # Match by CVE ID
            if known["id"] == detected["id"]:
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
            
            # Try matching by package name and severity if no CVE ID match
            if (not found and known["package"].lower() == detected["package"].lower() and 
                known["severity"].upper() == detected["severity"].upper()):
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
        
        if not found:
            analysis["false_negatives"] += 1
            analysis["missed_vulnerabilities"].append(known)
    
    # Check for false positives
    for detected in detected_vulns:
        if detected["id"] and not any(known["id"] == detected["id"] for known in known_vulns):
            if not any(known["package"].lower() == detected["package"].lower() and 
                       known["severity"].upper() == detected["severity"].upper() for known in known_vulns):
                analysis["false_positives"] += 1
                analysis["extra_vulnerabilities"].append(detected)
    
    # Calculate metrics
    total_known = len(known_vulns)
    if total_known > 0:
        analysis["true_positive_rate"] = analysis["true_positives"] / total_known
    
    total_detected = analysis["true_positives"] + analysis["false_positives"]
    if total_detected > 0:
        precision = analysis["true_positives"] / total_detected
    else:
        precision = 0.0
    
    if precision + analysis["true_positive_rate"] > 0:
        analysis["f1_score"] = 2 * (precision * analysis["true_positive_rate"]) / (precision + analysis["true_positive_rate"])
    
    return analysis


def parse_dependabot_results(results: Dict[str, Any], known_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse and analyze results from Dependabot.
    
    Args:
        results: Parsed results from Dependabot.
        known_vulns: List of known vulnerabilities for comparison.
        
    Returns:
        Analysis result.
    """
    analysis = {
        "true_positives": 0,
        "false_negatives": 0,
        "false_positives": 0,
        "true_positive_rate": 0.0,
        "false_positive_rate": 0.0,
        "f1_score": 0.0,
        "sbom_generated": False,  # Dependabot doesn't generate SBOMs
        "license_detected": True,  # Dependabot can detect licenses but doesn't always report them
        "remediation_advised": True,  # Dependabot always provides remediation advice
        "detected_vulnerabilities": [],
        "missed_vulnerabilities": [],
        "extra_vulnerabilities": []
    }
    
    # Extract detected vulnerabilities
    detected_vulns = []
    if "alerts" in results:
        for alert in results["alerts"]:
            detected_vulns.append({
                "id": alert.get("advisory", {}).get("cve_id", ""),
                "package": alert.get("dependency", ""),
                "version": alert.get("version", ""),
                "severity": alert.get("advisory", {}).get("severity", "unknown").upper(),
            })
    
    # Match against known vulnerabilities
    for known in known_vulns:
        found = False
        for detected in detected_vulns:
            # Match by CVE ID
            if known["id"] == detected["id"]:
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
            
            # Try matching by package name and severity if no CVE ID match
            if (not found and known["package"].lower() == detected["package"].lower() and 
                known["severity"].upper() == detected["severity"].upper()):
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
        
        if not found:
            analysis["false_negatives"] += 1
            analysis["missed_vulnerabilities"].append(known)
    
    # Check for false positives
    for detected in detected_vulns:
        if detected["id"] and not any(known["id"] == detected["id"] for known in known_vulns):
            if not any(known["package"].lower() == detected["package"].lower() and 
                       known["severity"].upper() == detected["severity"].upper() for known in known_vulns):
                analysis["false_positives"] += 1
                analysis["extra_vulnerabilities"].append(detected)
    
    # Calculate metrics
    total_known = len(known_vulns)
    if total_known > 0:
        analysis["true_positive_rate"] = analysis["true_positives"] / total_known
    
    total_detected = analysis["true_positives"] + analysis["false_positives"]
    if total_detected > 0:
        precision = analysis["true_positives"] / total_detected
    else:
        precision = 0.0
    
    if precision + analysis["true_positive_rate"] > 0:
        analysis["f1_score"] = 2 * (precision * analysis["true_positive_rate"]) / (precision + analysis["true_positive_rate"])
    
    return analysis


def parse_dependency_check_results(results: Dict[str, Any], known_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse and analyze results from OWASP Dependency-Check.
    
    Args:
        results: Parsed results from Dependency-Check.
        known_vulns: List of known vulnerabilities for comparison.
        
    Returns:
        Analysis result.
    """
    analysis = {
        "true_positives": 0,
        "false_negatives": 0,
        "false_positives": 0,
        "true_positive_rate": 0.0,
        "false_positive_rate": 0.0,
        "f1_score": 0.0,
        "sbom_generated": True,  # Dependency-Check can output CycloneDX
        "license_detected": True,  # Dependency-Check detects licenses
        "remediation_advised": False,  # Dependency-Check doesn't typically provide remediation
        "detected_vulnerabilities": [],
        "missed_vulnerabilities": [],
        "extra_vulnerabilities": []
    }
    
    # Extract detected vulnerabilities
    detected_vulns = []
    if "dependencies" in results:
        for dependency in results["dependencies"]:
            packages = dependency.get("packages", [])
            for package in packages:
                vulns = package.get("vulnerabilities", [])
                for vuln in vulns:
                    detected_vulns.append({
                        "id": vuln.get("name", ""),
                        "package": dependency.get("fileName", "").split("/")[-1],
                        "version": next((e.get("value", "") for e in dependency.get("evidenceCollected", {}).get("versionEvidence", []) if e.get("name") == "version"), ""),
                        "severity": vuln.get("severity", "UNKNOWN"),
                    })
    
    # Match against known vulnerabilities
    for known in known_vulns:
        found = False
        for detected in detected_vulns:
            # Match by CVE ID
            if known["id"] == detected["id"]:
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
            
            # Try matching by package name and severity if no CVE ID match
            if (not found and 
                (known["package"].lower() in detected["package"].lower() or 
                 detected["package"].lower() in known["package"].lower()) and 
                known["severity"] == detected["severity"]):
                analysis["true_positives"] += 1
                analysis["detected_vulnerabilities"].append({
                    "known": known,
                    "detected": detected
                })
                found = True
                break
        
        if not found:
            analysis["false_negatives"] += 1
            analysis["missed_vulnerabilities"].append(known)
    
    # Check for false positives (Dependency-Check has many)
    for detected in detected_vulns:
        if detected["id"] and not any(known["id"] == detected["id"] for known in known_vulns):
            if not any((known["package"].lower() in detected["package"].lower() or 
                        detected["package"].lower() in known["package"].lower()) and 
                       known["severity"] == detected["severity"] for known in known_vulns):
                analysis["false_positives"] += 1
                analysis["extra_vulnerabilities"].append(detected)
    
    # Calculate metrics
    total_known = len(known_vulns)
    if total_known > 0:
        analysis["true_positive_rate"] = analysis["true_positives"] / total_known
    
    total_detected = analysis["true_positives"] + analysis["false_positives"]
    if total_detected > 0:
        precision = analysis["true_positives"] / total_detected
    else:
        precision = 0.0
    
    if precision + analysis["true_positive_rate"] > 0:
        analysis["f1_score"] = 2 * (precision * analysis["true_positive_rate"]) / (precision + analysis["true_positive_rate"])
    
    return analysis


def generate_comparison_matrix(tool_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a comparison matrix from tool results.
    
    Args:
        tool_results: Dictionary mapping tool IDs to result dictionaries.
        
    Returns:
        Comparison matrix.
    """
    # Define comparison matrix
    matrix = {
        "tools": {},
        "metrics": COMPARISON_METRICS,
        "scores": {}
    }
    
    # Add tool information
    tools_info = {
        "ossv-scanner": {
            "name": "OSSV Scanner",
            "description": "Open Source Software Vulnerability Scanner",
            "website": "",
            "license": "Open Source"
        }
    }
    tools_info.update({tool_id: COMPARISON_TOOLS[tool_id] for tool_id in tool_results if tool_id != "ossv-scanner"})
    
    matrix["tools"] = tools_info
    
    # Add scores for each tool
    for tool_id, results in tool_results.items():
        tool_scores = {}
        
        # Detection Effectiveness metrics
        projects_count = len(results)
        if projects_count > 0:
            # Calculate averages across projects
            avg_tpr = sum(p["analysis"]["true_positive_rate"] for p in results.values()) / projects_count
            total_fp = sum(p["analysis"]["false_positives"] for p in results.values())
            total_detections = sum(p["analysis"]["true_positives"] + p["analysis"]["false_positives"] for p in results.values())
            fp_rate = total_fp / total_detections if total_detections > 0 else 0
            
            tool_scores["true_positive_rate"] = avg_tpr
            tool_scores["false_positive_rate"] = fp_rate
            
            # Set simulated values for other metrics
            if tool_id == "ossv-scanner":
                tool_scores["detection_latency"] = 3.5  # Days
                tool_scores["vulnerability_coverage"] = 0.82  # 82%
                tool_scores["sbom_generation"] = 1.0  # Yes
                tool_scores["license_detection"] = 0.7  # Partial
                tool_scores["remediation_advice"] = 0.8  # Good
                tool_scores["severity_accuracy"] = 0.9  # Very good
                
                # Performance
                tool_scores["scan_time"] = sum(p["metrics"]["duration"] for p in results.values()) / projects_count
                tool_scores["memory_usage"] = sum(p["metrics"].get("memory_usage", 150) for p in results.values()) / projects_count
                tool_scores["cpu_usage"] = sum(p["metrics"].get("cpu_usage", 25) for p in results.values()) / projects_count
                
                # Usability
                tool_scores["setup_complexity"] = 3.0  # 1-10 scale (1 = easiest)
                tool_scores["ci_cd_integration"] = 2.0  # 1-10 scale (1 = easiest)
                tool_scores["report_quality"] = 7.0  # 1-10 scale (1 = best)
                
                # Cost
                tool_scores["license_cost"] = 0  # Free
                tool_scores["maintenance_cost"] = 2000  # Estimated annual cost
                
            elif tool_id == "snyk":
                tool_scores["detection_latency"] = 1.5  # Days
                tool_scores["vulnerability_coverage"] = 0.95  # 95%
                tool_scores["sbom_generation"] = 0.5  # Partial
                tool_scores["license_detection"] = 1.0  # Yes
                tool_scores["remediation_advice"] = 1.0  # Excellent
                tool_scores["severity_accuracy"] = 0.85  # Good
                
                # Performance
                tool_scores["scan_time"] = sum(p["metrics"]["duration"] for p in results.values()) / projects_count
                tool_scores["memory_usage"] = sum(p["metrics"].get("memory_usage", 120) for p in results.values()) / projects_count
                tool_scores["cpu_usage"] = sum(p["metrics"].get("cpu_usage", 25) for p in results.values()) / projects_count
                
                # Usability
                tool_scores["setup_complexity"] = 2.0  # 1-10 scale (1 = easiest)
                tool_scores["ci_cd_integration"] = 1.0  # 1-10 scale (1 = easiest)
                tool_scores["report_quality"] = 9.0  # 1-10 scale (1 = best)
                
                # Cost
                tool_scores["license_cost"] = 12000  # Enterprise plan
                tool_scores["maintenance_cost"] = 1000  # Estimated annual cost
                
            elif tool_id == "dependabot":
                tool_scores["detection_latency"] = 2.0  # Days
                tool_scores["vulnerability_coverage"] = 0.85  # 85%
                tool_scores["sbom_generation"] = 0.0  # No
                tool_scores["license_detection"] = 0.5  # Partial
                tool_scores["remediation_advice"] = 1.0  # Excellent
                tool_scores["severity_accuracy"] = 0.8  # Good
                
                # Performance
                tool_scores["scan_time"] = sum(p["metrics"]["duration"] for p in results.values()) / projects_count
                tool_scores["memory_usage"] = sum(p["metrics"].get("memory_usage", 90) for p in results.values()) / projects_count
                tool_scores["cpu_usage"] = sum(p["metrics"].get("cpu_usage", 20) for p in results.values()) / projects_count
                
                # Usability
                tool_scores["setup_complexity"] = 1.0  # 1-10 scale (1 = easiest)
                tool_scores["ci_cd_integration"] = 1.0  # 1-10 scale (1 = easiest)
                tool_scores["report_quality"] = 8.0  # 1-10 scale (1 = best)
                
                # Cost
                tool_scores["license_cost"] = 0  # Free with GitHub
                tool_scores["maintenance_cost"] = 500  # Estimated annual cost
                
            elif tool_id == "owasp-dependency-check":
                tool_scores["detection_latency"] = 7.0  # Days
                tool_scores["vulnerability_coverage"] = 0.75  # 75%
                tool_scores["sbom_generation"] = 1.0  # Yes
                tool_scores["license_detection"] = 0.9  # Good
                tool_scores["remediation_advice"] = 0.2  # Poor
                tool_scores["severity_accuracy"] = 0.7  # Moderate
                
                # Performance
                tool_scores["scan_time"] = sum(p["metrics"]["duration"] for p in results.values()) / projects_count
                tool_scores["memory_usage"] = sum(p["metrics"].get("memory_usage", 350) for p in results.values()) / projects_count
                tool_scores["cpu_usage"] = sum(p["metrics"].get("cpu_usage", 35) for p in results.values()) / projects_count
                
                # Usability
                tool_scores["setup_complexity"] = 5.0  # 1-10 scale (1 = easiest)
                tool_scores["ci_cd_integration"] = 4.0  # 1-10 scale (1 = easiest)
                tool_scores["report_quality"] = 6.0  # 1-10 scale (1 = best)
                
                # Cost
                tool_scores["license_cost"] = 0  # Free
                tool_scores["maintenance_cost"] = 3000  # Estimated annual cost
        
        matrix["scores"][tool_id] = tool_scores
    
    return matrix


def generate_plots(comparison_matrix: Dict[str, Any], output_dir: Path) -> Dict[str, Path]:
    """
    Generate comparison plots from the matrix.
    
    Args:
        comparison_matrix: Comparison matrix.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # 1. Detection effectiveness (TPR vs FPR)
    plt.figure(figsize=(10, 8))
    
    # Prepare data
    tools = []
    tpr_values = []
    fpr_values = []
    vuln_coverage = []
    
    for tool_id, scores in comparison_matrix["scores"].items():
        tools.append(comparison_matrix["tools"][tool_id]["name"])
        tpr_values.append(scores.get("true_positive_rate", 0))
        fpr_values.append(scores.get("false_positive_rate", 0))
        vuln_coverage.append(scores.get("vulnerability_coverage", 0))
    
    # Plot TPR vs FPR as scatter plot
    plt.figure(figsize=(10, 8))
    plt.scatter(fpr_values, tpr_values, s=100)
    
    # Add tool labels
    for i, tool in enumerate(tools):
        plt.annotate(tool, (fpr_values[i], tpr_values[i]), 
                    textcoords="offset points", xytext=(0,10), ha='center')
    
    # Add diagonal line representing random guessing
    plt.plot([0, 1], [0, 1], 'k--', alpha=0.3)
    
    plt.title('Vulnerability Detection Performance')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.xlim(-0.05, 1.05)
    plt.ylim(-0.05, 1.05)
    plt.grid(True)
    
    detection_plot_path = output_dir / "detection_performance.png"
    plt.savefig(detection_plot_path)
    plt.close()
    plots["detection_performance"] = detection_plot_path
    
    # 2. Feature Completeness Radar Chart
    plt.figure(figsize=(10, 8))
    
    # Prepare data
    feature_metrics = [
        "sbom_generation", "license_detection", "remediation_advice", 
        "severity_accuracy", "vulnerability_coverage"
    ]
    feature_labels = [
        "SBOM Generation", "License Detection", "Remediation Advice", 
        "Severity Accuracy", "Vulnerability Coverage"
    ]
    
    # Create radar chart
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, polar=True)
    
    # Number of variables
    N = len(feature_metrics)
    
    # Compute angle for each metric
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # Close the loop
    
    # Draw each tool
    for tool_id, scores in comparison_matrix["scores"].items():
        values = [scores.get(metric, 0) for metric in feature_metrics]
        values += values[:1]  # Close the loop
        
        ax.plot(angles, values, label=comparison_matrix["tools"][tool_id]["name"])
        ax.fill(angles, values, alpha=0.1)
    
    # Set labels and legend
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(feature_labels)
    ax.set_yticklabels([])
    ax.set_ylim(0, 1)
    plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    
    plt.title('Feature Completeness Comparison')
    
    feature_plot_path = output_dir / "feature_completeness.png"
    plt.savefig(feature_plot_path)
    plt.close()
    plots["feature_completeness"] = feature_plot_path
    
    # 3. Performance Comparison
    plt.figure(figsize=(12, 8))
    
    # Prepare data
    scan_times = []
    memory_usages = []
    cpu_usages = []
    
    for tool_id, scores in comparison_matrix["scores"].items():
        scan_times.append(scores.get("scan_time", 0))
        memory_usages.append(scores.get("memory_usage", 0))
        cpu_usages.append(scores.get("cpu_usage", 0))
    
    # Create grouped bar chart
    x = np.arange(len(tools))
    width = 0.2
    
    fig, ax = plt.subplots(figsize=(12, 8))
    rects1 = ax.bar(x - width, scan_times, width, label='Scan Time (s)')
    rects2 = ax.bar(x, memory_usages, width, label='Memory Usage (MB)')
    rects3 = ax.bar(x + width, cpu_usages, width, label='CPU Usage (%)')
    
    # Add labels and legend
    ax.set_xlabel('Tool')
    ax.set_ylabel('Value')
    ax.set_title('Performance Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    
    # Add value labels on top of bars
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.1f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom')
    
    autolabel(rects1)
    autolabel(rects2)
    autolabel(rects3)
    
    plt.tight_layout()
    
    performance_plot_path = output_dir / "performance_comparison.png"
    plt.savefig(performance_plot_path)
    plt.close()
    plots["performance_comparison"] = performance_plot_path
    
    # 4. Total Cost of Ownership
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    license_costs = []
    maintenance_costs = []
    
    for tool_id, scores in comparison_matrix["scores"].items():
        license_costs.append(scores.get("license_cost", 0))
        maintenance_costs.append(scores.get("maintenance_cost", 0))
    
    # Create stacked bar chart
    x = np.arange(len(tools))
    width = 0.6
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x, license_costs, width, label='License Cost ($)')
    ax.bar(x, maintenance_costs, width, bottom=license_costs, label='Maintenance Cost ($)')
    
    # Add labels and legend
    ax.set_xlabel('Tool')
    ax.set_ylabel('Annual Cost ($)')
    ax.set_title('Total Cost of Ownership (Annual)')
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    
    # Add total cost labels
    for i, (l, m) in enumerate(zip(license_costs, maintenance_costs)):
        total = l + m
        ax.annotate(f'${total:,}',
                    xy=(i, total),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    plt.tight_layout()
    
    cost_plot_path = output_dir / "cost_comparison.png"
    plt.savefig(cost_plot_path)
    plt.close()
    plots["cost_comparison"] = cost_plot_path
    
    # 5. Overall Scoring Radar Chart
    plt.figure(figsize=(12, 10))
    
    # Define categories and weights for overall scoring
    categories = {
        "detection": ["true_positive_rate", "false_positive_rate", "vulnerability_coverage"],
        "features": ["sbom_generation", "license_detection", "remediation_advice", "severity_accuracy"],
        "performance": ["scan_time", "memory_usage", "cpu_usage"],
        "usability": ["setup_complexity", "ci_cd_integration", "report_quality"],
        "cost": ["license_cost", "maintenance_cost"]
    }
    
    category_labels = ["Detection", "Features", "Performance", "Usability", "Cost-Efficiency"]
    
    # Normalize scores for each category
    normalized_scores = {}
    
    for tool_id, scores in comparison_matrix["scores"].items():
        tool_scores = []
        
        # Detection score (higher TPR, lower FPR, higher coverage = better)
        tpr = scores.get("true_positive_rate", 0)
        fpr = scores.get("false_positive_rate", 0)
        coverage = scores.get("vulnerability_coverage", 0)
        detection_score = (tpr * 0.4 + (1 - fpr) * 0.3 + coverage * 0.3)
        tool_scores.append(detection_score)
        
        # Features score
        sbom = scores.get("sbom_generation", 0)
        license = scores.get("license_detection", 0)
        remediation = scores.get("remediation_advice", 0)
        severity = scores.get("severity_accuracy", 0)
        features_score = (sbom * 0.25 + license * 0.25 + remediation * 0.25 + severity * 0.25)
        tool_scores.append(features_score)
        
        # Performance score (lower is better, so invert)
        scan_time = scores.get("scan_time", 0)
        memory = scores.get("memory_usage", 0)
        cpu = scores.get("cpu_usage", 0)
        
        # Normalize scan time (assuming 10s is excellent)
        scan_time_score = 1.0 - min(scan_time / 10.0, 1.0)
        
        # Normalize memory (assuming 100MB is excellent)
        memory_score = 1.0 - min(memory / 1000.0, 1.0)
        
        # Normalize CPU (assuming 20% is excellent)
        cpu_score = 1.0 - min(cpu / 100.0, 1.0)
        
        performance_score = (scan_time_score * 0.4 + memory_score * 0.3 + cpu_score * 0.3)
        tool_scores.append(performance_score)
        
        # Usability score (lower complexity = better, higher quality = better)
        setup = scores.get("setup_complexity", 5)
        ci_cd = scores.get("ci_cd_integration", 5)
        report = scores.get("report_quality", 5)
        
        # Invert complexity scores
        setup_score = (10 - setup) / 9.0
        ci_cd_score = (10 - ci_cd) / 9.0
        report_score = report / 10.0
        
        usability_score = (setup_score * 0.3 + ci_cd_score * 0.3 + report_score * 0.4)
        tool_scores.append(usability_score)
        
        # Cost score (lower = better)
        license_cost = scores.get("license_cost", 0)
        maintenance_cost = scores.get("maintenance_cost", 0)
        total_cost = license_cost + maintenance_cost
        
        # Normalize cost (assuming $15000 or more is worst case)
        cost_score = 1.0 - min(total_cost / 15000.0, 1.0)
        tool_scores.append(cost_score)
        
        normalized_scores[tool_id] = tool_scores
    
    # Create radar chart
    fig = plt.figure(figsize=(12, 10))
    ax = fig.add_subplot(111, polar=True)
    
    # Number of variables
    N = len(category_labels)
    
    # Compute angle for each metric
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # Close the loop
    
    # Draw each tool
    for tool_id, scores in normalized_scores.items():
        values = scores.copy()
        values += values[:1]  # Close the loop
        
        ax.plot(angles, values, label=comparison_matrix["tools"][tool_id]["name"], linewidth=2)
        ax.fill(angles, values, alpha=0.1)
    
    # Set labels and legend
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(category_labels)
    ax.set_yticklabels([])
    ax.set_ylim(0, 1)
    plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
    
    plt.title('Overall Tool Comparison')
    
    overall_plot_path = output_dir / "overall_comparison.png"
    plt.savefig(overall_plot_path)
    plt.close()
    plots["overall_comparison"] = overall_plot_path
    
    return plots


def compare_tools(tools: List[str] = None) -> Dict[str, Any]:
    """
    Compare ossv-scanner with other vulnerability scanning tools.
    
    Args:
        tools: List of tool IDs to compare. If None, uses a default set.
        
    Returns:
        Comparison results.
    """
    logger.info("Starting tool comparison tests")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-tool-comparison-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    plots_dir = base_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Select tools to compare
    if not tools or not any(t for t in tools if t != "ossv-scanner"):
        # Default to a smaller set if no tools specified
        tools = ["ossv-scanner", "snyk", "dependabot"]
    
    if "ossv-scanner" not in tools:
        tools.insert(0, "ossv-scanner")  # Always include ossv-scanner
    
    # Create test projects
    logger.info("Creating test projects")
    test_projects = create_test_projects(base_dir)
    
    # Run tests for each tool on each project
    tool_results = {}
    
    for tool_id in tools:
        tool_results[tool_id] = {}
        
        for project_id, (project_dir, known_vulns) in test_projects.items():
            logger.info(f"Testing {tool_id} on {project_id}")
            
            # Run the tool
            tool_output_dir = output_dir / tool_id / project_id
            tool_output_dir.mkdir(parents=True, exist_ok=True)
            
            result_path, metrics = run_comparative_test(tool_id, project_dir, tool_output_dir)
            
            # Parse and analyze results
            analysis = parse_results(tool_id, result_path, known_vulns)
            
            # Store results
            tool_results[tool_id][project_id] = {
                "project_dir": str(project_dir),
                "result_path": str(result_path),
                "metrics": metrics,
                "analysis": analysis,
                "known_vulns": known_vulns
            }
    
    # Generate comparison matrix
    comparison_matrix = generate_comparison_matrix(tool_results)
    
    # Generate plots
    plots = generate_plots(comparison_matrix, plots_dir)
    
    # Return comparison results
    return {
        "tool_results": tool_results,
        "comparison_matrix": comparison_matrix,
        "plots": {name: str(path) for name, path in plots.items()},
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir),
            "plots_dir": str(plots_dir)
        },
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tools_compared": tools
        }
    }


if __name__ == "__main__":
    import random  # Required for creating test projects
    logging.basicConfig(level=logging.INFO)
    results = compare_tools()
    print("Comparison completed")
