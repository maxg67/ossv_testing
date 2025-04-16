"""
Blind testing for ossv-scanner.

This module implements a blind testing approach where the testing framework doesn't
know in advance which vulnerabilities are present. It uses real projects with known
vulnerabilities but tests the scanner's ability to detect them without providing
expected outcomes in advance.
"""

import os
import time
import logging
import tempfile
import json
import yaml
import shutil
import subprocess
import requests
import random
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Repository of real open-source projects with known vulnerabilities
# In a real implementation, these would be cloned from their repositories
# with specific commits/tags that contain known vulnerabilities
BLIND_TEST_PROJECTS = [
    {
        "id": "bt-01",
        "name": "juice-shop",
        "description": "OWASP Juice Shop vulnerable web application",
        "source": "https://github.com/bkimminich/juice-shop",
        "version": "v12.6.1",  # Version with known vulnerabilities
        "ecosystem": "npm",
        "clone_dir": "juice-shop",
        "level": "moderate"
    },
    {
        "id": "bt-02",
        "name": "dvna",
        "description": "Damn Vulnerable NodeJS Application",
        "source": "https://github.com/appsecco/dvna",
        "version": "master",  # Main branch has vulnerabilities
        "ecosystem": "npm",
        "clone_dir": "dvna",
        "level": "high"
    },
    {
        "id": "bt-03",
        "name": "django-DefectDojo",
        "description": "Security vulnerability management tool",
        "source": "https://github.com/DefectDojo/django-DefectDojo",
        "version": "1.5.0",  # Older version with known vulnerabilities
        "ecosystem": "python",
        "clone_dir": "django-DefectDojo",
        "level": "moderate"
    },
    {
        "id": "bt-04",
        "name": "WebGoat",
        "description": "OWASP WebGoat vulnerable web application",
        "source": "https://github.com/WebGoat/WebGoat",
        "version": "v8.0.0.M21",  # Version with known vulnerabilities
        "ecosystem": "maven",
        "clone_dir": "WebGoat",
        "level": "high"
    },
    {
        "id": "bt-05",
        "name": "railsgoat",
        "description": "Vulnerable Ruby on Rails application",
        "source": "https://github.com/OWASP/railsgoat",
        "version": "v1.2.0",  # Version with known vulnerabilities
        "ecosystem": "gem",
        "clone_dir": "railsgoat",
        "level": "moderate"
    }
]


def fetch_vulnerability_db(ecosystem: str) -> List[Dict[str, Any]]:
    """
    Fetch known vulnerabilities for an ecosystem from a vulnerability database.
    In a real implementation, this would connect to NVD, GitHub Security Advisories, etc.
    
    Args:
        ecosystem: Package ecosystem.
        
    Returns:
        List of known vulnerabilities.
    """
    # This is a mock implementation - in a real system, you would fetch from actual databases
    # For example, using the NVD API or GitHub Security Advisory API
    mock_db = {
        "npm": [
            {"id": "CVE-2020-7598", "package": "minimist", "severity": "MEDIUM"},
            {"id": "CVE-2019-10744", "package": "lodash", "severity": "HIGH"},
            {"id": "CVE-2019-11358", "package": "jquery", "severity": "MEDIUM"},
            {"id": "CVE-2020-8203", "package": "lodash", "severity": "HIGH"},
            {"id": "CVE-2020-28469", "package": "socket.io", "severity": "HIGH"},
            {"id": "CVE-2021-23343", "package": "path-parse", "severity": "MEDIUM"},
            {"id": "CVE-2020-7720", "package": "node-forge", "severity": "HIGH"},
        ],
        "python": [
            {"id": "CVE-2019-19844", "package": "django", "severity": "HIGH"},
            {"id": "CVE-2020-13254", "package": "django", "severity": "HIGH"},
            {"id": "CVE-2020-9402", "package": "urllib3", "severity": "HIGH"},
            {"id": "CVE-2018-20060", "package": "requests", "severity": "MEDIUM"},
            {"id": "CVE-2019-11324", "package": "urllib3", "severity": "MEDIUM"},
            {"id": "CVE-2018-1000656", "package": "flask", "severity": "HIGH"},
        ],
        "maven": [
            {"id": "CVE-2020-13956", "package": "org.apache.httpcomponents:httpclient", "severity": "MEDIUM"},
            {"id": "CVE-2018-10054", "package": "org.springframework:spring-core", "severity": "HIGH"},
            {"id": "CVE-2020-13949", "package": "org.apache.ant:ant", "severity": "HIGH"},
            {"id": "CVE-2020-9484", "package": "org.apache.tomcat.embed:tomcat-embed-core", "severity": "HIGH"},
            {"id": "CVE-2019-17195", "package": "org.apache.commons:commons-compress", "severity": "HIGH"},
        ],
        "gem": [
            {"id": "CVE-2020-8164", "package": "actionpack", "severity": "HIGH"},
            {"id": "CVE-2020-8167", "package": "actionview", "severity": "HIGH"},
            {"id": "CVE-2020-8162", "package": "activestorage", "severity": "MEDIUM"},
            {"id": "CVE-2019-16782", "package": "rack", "severity": "MEDIUM"},
            {"id": "CVE-2020-8184", "package": "activesupport", "severity": "MEDIUM"},
        ]
    }
    
    return mock_db.get(ecosystem, [])


def clone_project(project: Dict[str, Any], base_dir: Path) -> Path:
    """
    Clone a project from its repository.
    In a real implementation, this would use git to clone the actual repository.
    
    Args:
        project: Project definition.
        base_dir: Base directory to clone into.
        
    Returns:
        Path to the cloned project.
    """
    project_dir = base_dir / project["clone_dir"]
    
    # In a real implementation, this would run:
    # subprocess.run(["git", "clone", project["source"], "--branch", project["version"], project_dir])
    
    # For testing purposes, we'll simulate a project with mock files
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create mock project files based on ecosystem
    if project["ecosystem"] == "npm":
        package_json = {
            "name": project["name"],
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15",
                "jquery": "3.4.0",
                "minimist": "1.2.0",
                "express": "4.17.1",
                "socket.io": "2.3.0",
                "moment": "2.24.0",
                "path-parse": "1.0.6",
                "node-forge": "0.9.0"
            }
        }
        
        with open(project_dir / "package.json", "w") as f:
            json.dump(package_json, f, indent=2)
            
    elif project["ecosystem"] == "python":
        requirements = [
            "Django==2.2.13",
            "requests==2.22.0",
            "urllib3==1.25.8",
            "Flask==1.0.2",
            "Jinja2==2.10.1",
            "Werkzeug==1.0.0",
            "SQLAlchemy==1.3.15"
        ]
        
        with open(project_dir / "requirements.txt", "w") as f:
            f.write("\n".join(requirements))
            
    elif project["ecosystem"] == "maven":
        pom_xml = """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>vulnerable-java-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.2.3.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>org.apache.tomcat.embed</groupId>
            <artifactId>tomcat-embed-core</artifactId>
            <version>9.0.30</version>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-compress</artifactId>
            <version>1.19</version>
        </dependency>
        <dependency>
            <groupId>org.apache.httpcomponents</groupId>
            <artifactId>httpclient</artifactId>
            <version>4.5.11</version>
        </dependency>
    </dependencies>
</project>"""
        
        with open(project_dir / "pom.xml", "w") as f:
            f.write(pom_xml)
            
    elif project["ecosystem"] == "gem":
        gemfile = """source 'https://rubygems.org'

gem 'rails', '6.0.2.1'
gem 'rack', '2.0.8'
gem 'actionpack', '6.0.2.1'
gem 'actionview', '6.0.2.1'
gem 'activesupport', '6.0.2.1'
gem 'activestorage', '6.0.2.1'
"""
        
        with open(project_dir / "Gemfile", "w") as f:
            f.write(gemfile)
    
    return project_dir


def run_scanner(project_path: Path, output_dir: Path) -> Path:
    """
    Run ossv-scanner on a project.
    
    Args:
        project_path: Path to project.
        output_dir: Directory to save results.
        
    Returns:
        Path to results file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_path.name}-results.json"
    
    try:
        # Run the scanner
        logger.info(f"Running ossv-scanner on {project_path}")
        
        scan_cmd = [
            "ossv-scan",
            "--output-format", "json",
            "--output-path", str(output_path),
            str(project_path)
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
                str(project_path)
            ]
            subprocess.run(scan_cmd, check=True, capture_output=True)
        
        logger.info(f"Scanner completed successfully. Results at {output_path}")
        
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
    
    return output_path


def analyze_blind_results(result_path: Path, ecosystem: str) -> Dict[str, Any]:
    """
    Analyze blind test results by comparing against vulnerability database.
    
    Args:
        result_path: Path to result file.
        ecosystem: Package ecosystem.
        
    Returns:
        Analysis results.
    """
    analysis = {
        "detected_vulns": [],
        "detected_with_different_id": [],
        "packages_with_vulns": 0,
        "total_vulns_detected": 0,
        "known_vulnerabilities": []
    }
    
    # Fetch known vulnerabilities
    known_vulns = fetch_vulnerability_db(ecosystem)
    analysis["known_vulnerabilities"] = known_vulns
    
    # Check if results file exists
    if not result_path.exists():
        logger.warning(f"Results file not found: {result_path}")
        return analysis
    
    try:
        # Load scanner results
        with open(result_path, "r") as f:
            scan_results = json.load(f)
        
        # Extract detected vulnerabilities
        detected_vulns = []
        packages_with_vulns = set()
        
        if "vulnerabilities" in scan_results:
            for dep_id, vulns in scan_results["vulnerabilities"].items():
                if vulns:  # If vulnerabilities exist for this package
                    packages_with_vulns.add(dep_id.split("@")[0] if "@" in dep_id else dep_id)
                
                for vuln in vulns:
                    detected_vulns.append({
                        "id": vuln.get("cve_id", "unknown"),
                        "package": dep_id.split("@")[0] if "@" in dep_id else dep_id,
                        "version": dep_id.split("@")[1] if "@" in dep_id else "unknown",
                        "severity": vuln.get("severity", "UNKNOWN"),
                        "details": vuln
                    })
        
        # Update analysis
        analysis["total_vulns_detected"] = len(detected_vulns)
        analysis["packages_with_vulns"] = len(packages_with_vulns)
        analysis["detected_vulns"] = detected_vulns
        
        # Compare with known vulnerabilities
        for known in known_vulns:
            for detected in detected_vulns:
                # Check if the vulnerability is detected with the same ID
                if known["id"].lower() == detected["id"].lower() and known["package"].lower() == detected["package"].lower():
                    analysis["detected_with_different_id"].append({
                        "known": known,
                        "detected": detected
                    })
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing results: {str(e)}")
        return analysis


def run_tests(basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run blind tests.
    
    Args:
        basic: Whether to run a basic subset of tests.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting blind vulnerability tests")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-blind-tests-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Select test projects
    if basic:
        # Use a minimal set of test projects for basic testing
        selected_projects = [BLIND_TEST_PROJECTS[0], BLIND_TEST_PROJECTS[2]]  # One NPM, one Python
    elif comprehensive:
        # Use all test projects
        selected_projects = BLIND_TEST_PROJECTS
    else:
        # Default to all standard test projects
        selected_projects = BLIND_TEST_PROJECTS
    
    # Run tests for each project
    test_results = {}
    summary = {
        "total_projects": len(selected_projects),
        "total_vulns_detected": 0,
        "projects_with_vulns": 0,
        "avg_vulns_per_project": 0.0,
        "by_ecosystem": {},
        "by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }
    }
    
    # Initialize ecosystem summaries
    ecosystems = set(project["ecosystem"] for project in selected_projects)
    for ecosystem in ecosystems:
        summary["by_ecosystem"][ecosystem] = {
            "projects": 0,
            "vulns_detected": 0,
            "avg_vulns_per_project": 0.0
        }
    
    with Progress() as progress:
        # Create and test each project
        task = progress.add_task("[green]Running blind tests...", total=len(selected_projects))
        
        for project in selected_projects:
            logger.info(f"Testing project: {project['name']} ({project['id']})")
            
            # Clone/create project
            project_dir = clone_project(project, base_dir)
            
            # Run scanner
            result_path = run_scanner(project_dir, output_dir)
            
            # Analyze results
            analysis = analyze_blind_results(result_path, project["ecosystem"])
            
            # Store results
            test_results[project["id"]] = {
                "name": project["name"],
                "description": project["description"],
                "ecosystem": project["ecosystem"],
                "project_path": str(project_dir),
                "result_path": str(result_path),
                "analysis": analysis
            }
            
            # Update summary
            ecosystem = project["ecosystem"]
            vulns_detected = analysis["total_vulns_detected"]
            
            summary["total_vulns_detected"] += vulns_detected
            if vulns_detected > 0:
                summary["projects_with_vulns"] += 1
            
            # Update ecosystem summary
            summary["by_ecosystem"][ecosystem]["projects"] += 1
            summary["by_ecosystem"][ecosystem]["vulns_detected"] += vulns_detected
            
            # Update severity counts
            for vuln in analysis["detected_vulns"]:
                severity = vuln["severity"]
                summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            
            progress.update(task, advance=1)
    
    # Calculate averages
    if len(selected_projects) > 0:
        summary["avg_vulns_per_project"] = summary["total_vulns_detected"] / len(selected_projects)
    
    for ecosystem in summary["by_ecosystem"]:
        if summary["by_ecosystem"][ecosystem]["projects"] > 0:
            summary["by_ecosystem"][ecosystem]["avg_vulns_per_project"] = (
                summary["by_ecosystem"][ecosystem]["vulns_detected"] / 
                summary["by_ecosystem"][ecosystem]["projects"]
            )
    
    # Generate final results
    final_results = {
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir)
        },
        "test_projects": test_results,
        "summary": summary,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "num_projects": len(selected_projects)
        }
    }
    
    # Display summary
    display_summary(summary)
    
    logger.info("Blind vulnerability tests completed")
    return final_results


def display_summary(summary: Dict[str, Any]) -> None:
    """
    Display a summary of blind test results.
    
    Args:
        summary: Summary metrics dictionary.
    """
    console.print("\n[bold cyan]Blind Test Summary[/]")
    
    # Create a summary table
    table = Table(title="Blind Testing Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Projects", str(summary["total_projects"]))
    table.add_row("Projects with Vulnerabilities", str(summary["projects_with_vulns"]))
    table.add_row("Total Vulnerabilities Detected", str(summary["total_vulns_detected"]))
    table.add_row("Average Vulnerabilities per Project", f"{summary['avg_vulns_per_project']:.2f}")
    
    console.print(table)
    
    # Create ecosystem breakdown table
    console.print("\n[bold cyan]Results by Ecosystem[/]")
    eco_table = Table()
    eco_table.add_column("Ecosystem", style="cyan")
    eco_table.add_column("Projects", style="green")
    eco_table.add_column("Vulnerabilities", style="yellow")
    eco_table.add_column("Avg. Vulns/Project", style="green")
    
    for ecosystem, metrics in summary["by_ecosystem"].items():
        eco_table.add_row(
            ecosystem,
            str(metrics["projects"]),
            str(metrics["vulns_detected"]),
            f"{metrics['avg_vulns_per_project']:.2f}"
        )
    
    console.print(eco_table)
    
    # Create severity breakdown table
    console.print("\n[bold cyan]Vulnerabilities by Severity[/]")
    sev_table = Table()
    sev_table.add_column("Severity", style="cyan")
    sev_table.add_column("Count", style="green")
    sev_table.add_column("Percentage", style="yellow")
    
    # Order by severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    for severity in severity_order:
        if severity in summary["by_severity"] and summary["by_severity"][severity] > 0:
            count = summary["by_severity"][severity]
            percentage = count / summary["total_vulns_detected"] if summary["total_vulns_detected"] > 0 else 0
            
            sev_table.add_row(
                severity,
                str(count),
                f"{percentage:.1%}"
            )
    
    console.print(sev_table)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_tests()
    print(json.dumps(results, indent=2))
