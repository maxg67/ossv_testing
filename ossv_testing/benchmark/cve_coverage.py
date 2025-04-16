"""
CVE coverage analysis for ossv-scanner.

Analyzes how well the scanner covers known CVEs by testing against a database of 
known vulnerabilities from multiple public sources.
"""

import os
import time
import logging
import tempfile
import json
import csv
import subprocess
import shutil
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import datetime
import random

import requests
from rich.console import Console
from rich.progress import Progress

logger = logging.getLogger(__name__)
console = Console()

# Sample CVE databases to check against
# In a real implementation, these would be larger and potentially downloaded from sources
# like NVD, GitHub Security Advisories, MITRE, etc.
CVE_DATABASES = {
    "nvd": {
        "name": "National Vulnerability Database",
        "url": "https://nvd.nist.gov/",
        "cves": [
            {"id": "CVE-2021-44228", "package": "log4j", "versions": ["2.0-2.15.0"], "severity": "CRITICAL", "ecosystem": "maven"},
            {"id": "CVE-2021-42574", "package": "ua-parser-js", "versions": ["0.7.0-0.7.30"], "severity": "CRITICAL", "ecosystem": "npm"},
            {"id": "CVE-2021-3749", "package": "axios", "versions": ["0.21.1"], "severity": "HIGH", "ecosystem": "npm"},
            {"id": "CVE-2020-8203", "package": "lodash", "versions": ["4.17.0-4.17.16"], "severity": "HIGH", "ecosystem": "npm"},
            {"id": "CVE-2020-7598", "package": "minimist", "versions": ["0.0.1-1.2.2"], "severity": "MEDIUM", "ecosystem": "npm"},
            {"id": "CVE-2019-11358", "package": "jquery", "versions": ["1.0.0-3.4.0"], "severity": "MEDIUM", "ecosystem": "npm"},
            {"id": "CVE-2019-10744", "package": "lodash", "versions": ["4.17.0-4.17.11"], "severity": "HIGH", "ecosystem": "npm"},
            {"id": "CVE-2020-26247", "package": "nokogiri", "versions": ["1.11.0.rc3"], "severity": "HIGH", "ecosystem": "gem"},
            {"id": "CVE-2020-15133", "package": "django", "versions": ["2.2-3.0.7"], "severity": "HIGH", "ecosystem": "pypi"},
            {"id": "CVE-2020-13254", "package": "jackson-databind", "versions": ["2.0.0-2.9.10.4"], "severity": "CRITICAL", "ecosystem": "maven"},
        ]
    },
    "github": {
        "name": "GitHub Security Advisories",
        "url": "https://github.com/advisories",
        "cves": [
            {"id": "GHSA-j7hp-h5jm-p243", "package": "lodash", "versions": ["4.17.0-4.17.19"], "severity": "HIGH", "ecosystem": "npm"},
            {"id": "GHSA-p6mc-m468-83gw", "package": "dot-prop", "versions": ["4.0.0-4.2.0"], "severity": "HIGH", "ecosystem": "npm"},
            {"id": "GHSA-93q8-gq69-wqmw", "package": "minimist", "versions": ["0.0.1-1.2.3"], "severity": "MEDIUM", "ecosystem": "npm"},
            {"id": "GHSA-g4vp-rgj4-83r5", "package": "activesupport", "versions": ["4.2.0-6.0.2.1"], "severity": "HIGH", "ecosystem": "gem"},
            {"id": "GHSA-8727-m6gj-mc37", "package": "django", "versions": ["1.11-3.0.3"], "severity": "HIGH", "ecosystem": "pypi"},
        ]
    }
}

# Package ecosystems to test
ECOSYSTEMS = ["npm", "pypi", "maven", "gem"]

def create_test_projects(cve_set: List[Dict[str, Any]], output_dir: Path) -> Dict[str, Path]:
    """
    Create test projects for each ecosystem containing vulnerable dependencies.
    
    Args:
        cve_set: List of CVEs to include in test projects.
        output_dir: Base directory for created projects.
        
    Returns:
        Dictionary mapping ecosystem to project directory.
    """
    # Group CVEs by ecosystem
    ecosystem_cves = {}
    for cve in cve_set:
        ecosystem = cve.get("ecosystem", "unknown")
        if ecosystem not in ecosystem_cves:
            ecosystem_cves[ecosystem] = []
        ecosystem_cves[ecosystem].append(cve)
    
    # Create projects for each ecosystem
    projects = {}
    
    # Create npm project
    if "npm" in ecosystem_cves and ecosystem_cves["npm"]:
        npm_dir = output_dir / "npm-test"
        npm_dir.mkdir(parents=True, exist_ok=True)
        
        # Create package.json with vulnerable dependencies
        package_json = {
            "name": "npm-vulnerability-test",
            "version": "1.0.0",
            "description": "Test project for CVE coverage analysis",
            "dependencies": {}
        }
        
        for cve in ecosystem_cves["npm"]:
            # Use the first version from the vulnerable range
            version = cve["versions"][0].split("-")[0] if "-" in cve["versions"][0] else cve["versions"][0]
            package_json["dependencies"][cve["package"]] = version
        
        with open(npm_dir / "package.json", "w") as f:
            json.dump(package_json, f, indent=2)
        
        projects["npm"] = npm_dir
    
    # Create Python project
    if "pypi" in ecosystem_cves and ecosystem_cves["pypi"]:
        python_dir = output_dir / "python-test"
        python_dir.mkdir(parents=True, exist_ok=True)
        
        # Create requirements.txt with vulnerable dependencies
        requirements = []
        for cve in ecosystem_cves["pypi"]:
            # Use the first version from the vulnerable range
            version = cve["versions"][0].split("-")[0] if "-" in cve["versions"][0] else cve["versions"][0]
            requirements.append(f"{cve['package']}=={version}")
        
        with open(python_dir / "requirements.txt", "w") as f:
            f.write("\n".join(requirements))
        
        projects["pypi"] = python_dir
    
    # Create Maven project
    if "maven" in ecosystem_cves and ecosystem_cves["maven"]:
        maven_dir = output_dir / "maven-test"
        maven_dir.mkdir(parents=True, exist_ok=True)
        
        # Create pom.xml with vulnerable dependencies
        pom_header = """<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>maven-vulnerability-test</artifactId>
  <version>1.0.0</version>
  <dependencies>
"""
        
        pom_footer = """  </dependencies>
</project>"""
        
        dependencies = []
        for cve in ecosystem_cves["maven"]:
            # Maven dependencies have different format, need to split package into groupId:artifactId
            package_parts = cve["package"].split(":")
            group_id = package_parts[0] if len(package_parts) > 1 else "org.apache." + cve["package"]
            artifact_id = package_parts[1] if len(package_parts) > 1 else cve["package"]
            
            # Use the first version from the vulnerable range
            version = cve["versions"][0].split("-")[0] if "-" in cve["versions"][0] else cve["versions"][0]
            
            dependency = f"""    <dependency>
      <groupId>{group_id}</groupId>
      <artifactId>{artifact_id}</artifactId>
      <version>{version}</version>
    </dependency>"""
            
            dependencies.append(dependency)
        
        with open(maven_dir / "pom.xml", "w") as f:
            f.write(pom_header + "\n".join(dependencies) + pom_footer)
        
        projects["maven"] = maven_dir
    
    # Create Ruby project
    if "gem" in ecosystem_cves and ecosystem_cves["gem"]:
        ruby_dir = output_dir / "ruby-test"
        ruby_dir.mkdir(parents=True, exist_ok=True)
        
        # Create Gemfile with vulnerable dependencies
        gemfile_content = "source 'https://rubygems.org'\n\n"
        
        for cve in ecosystem_cves["gem"]:
            # Use the first version from the vulnerable range
            version = cve["versions"][0].split("-")[0] if "-" in cve["versions"][0] else cve["versions"][0]
            gemfile_content += f"gem '{cve['package']}', '{version}'\n"
        
        with open(ruby_dir / "Gemfile", "w") as f:
            f.write(gemfile_content)
        
        projects["gem"] = ruby_dir
    
    return projects


def run_scanner_on_projects(projects: Dict[str, Path], output_dir: Path) -> Dict[str, Path]:
    """
    Run ossv-scanner on each test project.
    
    Args:
        projects: Dictionary of ecosystem to project directory.
        output_dir: Directory to save scanner output.
        
    Returns:
        Dictionary mapping ecosystem to results file path.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    
    for ecosystem, project_dir in projects.items():
        logger.info(f"Running scanner on {ecosystem} project at {project_dir}")
        
        output_path = output_dir / f"{ecosystem}-results.json"
        results[ecosystem] = output_path
        
        try:
            # Run the scanner
            scan_cmd = [
                "ossv-scan",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_dir)
            ]
            
            try:
                # Try to run as installed package
                subprocess.run(scan_cmd, check=True, capture_output=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                # If that fails, try running as a module
                scan_cmd = [
                    "python", "-m", "ossv_scanner.main",
                    "--output-format", "json",
                    "--output-path", str(output_path),
                    str(project_dir)
                ]
                subprocess.run(scan_cmd, check=True, capture_output=True)
            
            logger.info(f"Scanner completed successfully for {ecosystem}. Results at {output_path}")
            
        except Exception as e:
            logger.error(f"Error running ossv-scanner on {ecosystem} project: {str(e)}")
            # Create empty file to avoid file not found errors
            with open(output_path, "w") as f:
                json.dump({"error": str(e)}, f)
    
    return results


def analyze_coverage(scan_results: Dict[str, Path], expected_cves: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Analyze CVE coverage from scanner results.
    
    Args:
        scan_results: Dictionary mapping ecosystem to results file path.
        expected_cves: Dictionary mapping ecosystem to expected CVEs.
        
    Returns:
        Analysis results dictionary.
    """
    # Initialize coverage metrics
    coverage = {
        "overall": {
            "total_cves": 0,
            "detected_cves": 0,
            "missed_cves": 0,
            "coverage_rate": 0.0,
            "by_severity": {
                "CRITICAL": {"total": 0, "detected": 0, "rate": 0.0},
                "HIGH": {"total": 0, "detected": 0, "rate": 0.0},
                "MEDIUM": {"total": 0, "detected": 0, "rate": 0.0},
                "LOW": {"total": 0, "detected": 0, "rate": 0.0},
            }
        },
        "by_ecosystem": {},
        "by_source": {},
        "detected_cves": [],
        "missed_cves": []
    }
    
    # Initialize per-ecosystem metrics
    for ecosystem in ECOSYSTEMS:
        if ecosystem in expected_cves:
            coverage["by_ecosystem"][ecosystem] = {
                "total_cves": len(expected_cves[ecosystem]),
                "detected_cves": 0,
                "missed_cves": 0,
                "coverage_rate": 0.0
            }
            
            # Update overall total
            coverage["overall"]["total_cves"] += len(expected_cves[ecosystem])
            
            # Update severity counts
            for cve in expected_cves[ecosystem]:
                severity = cve.get("severity", "MEDIUM")
                if severity not in coverage["overall"]["by_severity"]:
                    coverage["overall"]["by_severity"][severity] = {"total": 0, "detected": 0, "rate": 0.0}
                coverage["overall"]["by_severity"][severity]["total"] += 1
    
    # Initialize per-source metrics
    for source, source_data in CVE_DATABASES.items():
        coverage["by_source"][source] = {
            "name": source_data["name"],
            "total_cves": 0,
            "detected_cves": 0,
            "missed_cves": 0,
            "coverage_rate": 0.0
        }
    
    # Count expected CVEs by source
    for ecosystem, cve_list in expected_cves.items():
        for cve in cve_list:
            # Determine source based on ID format
            source = "github" if cve["id"].startswith("GHSA") else "nvd"
            coverage["by_source"][source]["total_cves"] += 1
    
    # Analyze results for each ecosystem
    for ecosystem, result_path in scan_results.items():
        if ecosystem not in expected_cves:
            continue
            
        # Load scan results
        try:
            with open(result_path, "r") as f:
                scan_data = json.load(f)
        except Exception as e:
            logger.error(f"Error reading scan results for {ecosystem}: {str(e)}")
            continue
        
        # Extract detected vulnerabilities
        detected_cve_ids = set()
        
        if "vulnerabilities" in scan_data:
            for dep_id, vulns in scan_data["vulnerabilities"].items():
                for vuln in vulns:
                    vuln_id = vuln.get("cve_id", "")
                    if vuln_id:
                        detected_cve_ids.add(vuln_id)
        
        # Check which expected CVEs were detected
        for cve in expected_cves[ecosystem]:
            cve_id = cve["id"]
            
            if cve_id in detected_cve_ids:
                # CVE was detected
                coverage["by_ecosystem"][ecosystem]["detected_cves"] += 1
                coverage["overall"]["detected_cves"] += 1
                coverage["detected_cves"].append(cve)
                
                # Update severity counts
                severity = cve.get("severity", "MEDIUM")
                if severity in coverage["overall"]["by_severity"]:
                    coverage["overall"]["by_severity"][severity]["detected"] += 1
                
                # Update source counts
                source = "github" if cve_id.startswith("GHSA") else "nvd"
                coverage["by_source"][source]["detected_cves"] += 1
            else:
                # CVE was missed
                coverage["by_ecosystem"][ecosystem]["missed_cves"] += 1
                coverage["overall"]["missed_cves"] += 1
                coverage["missed_cves"].append(cve)
                
                # Update source counts
                source = "github" if cve_id.startswith("GHSA") else "nvd"
                coverage["by_source"][source]["missed_cves"] += 1
    
    # Calculate coverage rates
    if coverage["overall"]["total_cves"] > 0:
        coverage["overall"]["coverage_rate"] = coverage["overall"]["detected_cves"] / coverage["overall"]["total_cves"]
    
    for ecosystem in coverage["by_ecosystem"]:
        if coverage["by_ecosystem"][ecosystem]["total_cves"] > 0:
            coverage["by_ecosystem"][ecosystem]["coverage_rate"] = (
                coverage["by_ecosystem"][ecosystem]["detected_cves"] / 
                coverage["by_ecosystem"][ecosystem]["total_cves"]
            )
    
    for source in coverage["by_source"]:
        if coverage["by_source"][source]["total_cves"] > 0:
            coverage["by_source"][source]["coverage_rate"] = (
                coverage["by_source"][source]["detected_cves"] / 
                coverage["by_source"][source]["total_cves"]
            )
    
    # Calculate severity rates
    for severity in coverage["overall"]["by_severity"]:
        if coverage["overall"]["by_severity"][severity]["total"] > 0:
            coverage["overall"]["by_severity"][severity]["rate"] = (
                coverage["overall"]["by_severity"][severity]["detected"] /
                coverage["overall"]["by_severity"][severity]["total"]
            )
    
    return coverage


def select_test_cves(comprehensive: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """
    Select CVEs for testing.
    
    Args:
        comprehensive: Whether to use a comprehensive or basic set.
        
    Returns:
        Dictionary mapping ecosystem to list of CVEs.
    """
    # Combine all CVEs from different sources
    all_cves = []
    for source, source_data in CVE_DATABASES.items():
        all_cves.extend(source_data["cves"])
    
    # Group by ecosystem
    ecosystem_cves = {}
    for cve in all_cves:
        ecosystem = cve.get("ecosystem", "unknown")
        if ecosystem not in ecosystem_cves:
            ecosystem_cves[ecosystem] = []
        ecosystem_cves[ecosystem].append(cve)
    
    # If comprehensive, return all CVEs
    if comprehensive:
        return ecosystem_cves
    
    # For basic testing, select a subset
    basic_cves = {}
    for ecosystem, cves in ecosystem_cves.items():
        # Take 3 CVEs per ecosystem or all if fewer than 3
        count = min(3, len(cves))
        basic_cves[ecosystem] = random.sample(cves, count)
    
    return basic_cves


def analyze_coverage(comprehensive: bool = False) -> Dict[str, Any]:
    """
    Analyze CVE coverage for ossv-scanner.
    
    Args:
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Dictionary with analysis results.
    """
    logger.info("Starting CVE coverage analysis")
    
    # Create base directory for test projects
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-cve-coverage-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(exist_ok=True)
    
    # Select CVEs for testing
    test_cves = select_test_cves(comprehensive)
    
    # Create test projects
    all_cves = []
    for ecosystem_cves in test_cves.values():
        all_cves.extend(ecosystem_cves)
    
    with Progress() as progress:
        task1 = progress.add_task("[green]Creating test projects...", total=1)
        projects = create_test_projects(all_cves, base_dir)
        progress.update(task1, completed=1)
        
        # Run scanner on projects
        task2 = progress.add_task("[green]Running scanner...", total=len(projects))
        scan_results = {}
        
        for ecosystem, project_dir in projects.items():
            logger.info(f"Running scanner on {ecosystem} project")
            output_path = output_dir / f"{ecosystem}-results.json"
            
            try:
                # Run the scanner
                scan_cmd = [
                    "ossv-scan",
                    "--output-format", "json",
                    "--output-path", str(output_path),
                    str(project_dir)
                ]
                
                try:
                    # Try to run as installed package
                    subprocess.run(scan_cmd, check=True, capture_output=True)
                except (subprocess.SubprocessError, FileNotFoundError):
                    # If that fails, try running as a module
                    scan_cmd = [
                        "python", "-m", "ossv_scanner.main",
                        "--output-format", "json",
                        "--output-path", str(output_path),
                        str(project_dir)
                    ]
                    subprocess.run(scan_cmd, check=True, capture_output=True)
                
                scan_results[ecosystem] = output_path
                
            except Exception as e:
                logger.error(f"Error running scanner on {ecosystem} project: {str(e)}")
                with open(output_path, "w") as f:
                    json.dump({"error": str(e)}, f)
                scan_results[ecosystem] = output_path
            
            progress.update(task2, advance=1)
    
    # Analyze results
    logger.info("Analyzing scanner results")
    coverage_analysis = analyze_coverage(scan_results, test_cves)
    
    # Add metadata
    coverage_analysis["metadata"] = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_dir": str(base_dir),
        "output_dir": str(output_dir),
        "test_type": "comprehensive" if comprehensive else "basic",
        "total_cves_tested": sum(len(cves) for cves in test_cves.values()),
        "ecosystems_tested": list(projects.keys())
    }
    
    logger.info(f"CVE coverage analysis complete. Overall coverage rate: {coverage_analysis['overall']['coverage_rate']:.2%}")
    return coverage_analysis


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = analyze_coverage()
    print(json.dumps(results, indent=2))
