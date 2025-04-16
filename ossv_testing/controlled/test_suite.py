"""
Test suite for known vulnerabilities.

This module implements a comprehensive test suite of known vulnerabilities across
various package ecosystems, versions, and severity levels.
"""

import os
import time
import logging
import tempfile
import json
import yaml
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Definition of test cases with known vulnerabilities
TEST_CASES = [
    # JavaScript/NPM vulnerabilities
    {
        "id": "ts-npm-01",
        "name": "NPM Prototype Pollution",
        "description": "Test for detection of prototype pollution vulnerabilities in NPM packages",
        "ecosystem": "npm",
        "dependencies": {
            "package.json": {
                "name": "prototype-pollution-test",
                "version": "1.0.0",
                "description": "Test for prototype pollution vulnerabilities",
                "dependencies": {
                    "lodash": "4.17.15",  # CVE-2019-10744
                    "minimist": "1.2.0",  # CVE-2020-7598
                    "jquery": "3.4.0"     # CVE-2019-11358
                }
            }
        },
        "expected_vulns": [
            {"id": "CVE-2019-10744", "package": "lodash", "severity": "HIGH", "description": "Prototype pollution"},
            {"id": "CVE-2020-7598", "package": "minimist", "severity": "MEDIUM", "description": "Prototype pollution"},
            {"id": "CVE-2019-11358", "package": "jquery", "severity": "MEDIUM", "description": "Prototype pollution"}
        ]
    },
    {
        "id": "ts-npm-02",
        "name": "NPM Command Injection",
        "description": "Test for detection of command injection vulnerabilities in NPM packages",
        "ecosystem": "npm",
        "dependencies": {
            "package.json": {
                "name": "command-injection-test",
                "version": "1.0.0",
                "description": "Test for command injection vulnerabilities",
                "dependencies": {
                    "node-ssh": "5.1.1",   # CVE-2019-13173
                    "event-stream": "3.3.6" # Malicious package incident
                }
            }
        },
        "expected_vulns": [
            {"id": "CVE-2019-13173", "package": "node-ssh", "severity": "HIGH", "description": "Command injection"},
            {"id": "NONCVE-2018-1002222", "package": "event-stream", "severity": "CRITICAL", "description": "Malicious package"}
        ]
    },
    
    # Python vulnerabilities
    {
        "id": "ts-python-01",
        "name": "Python Web Framework Vulnerabilities",
        "description": "Test for detection of vulnerabilities in popular Python web frameworks",
        "ecosystem": "pypi",
        "dependencies": {
            "requirements.txt": "\n".join([
                "Django==2.2.8",  # CVE-2019-19844
                "Flask==0.12.2",  # CVE-2018-1000656
                "Jinja2==2.10"    # CVE-2019-10906
            ])
        },
        "expected_vulns": [
            {"id": "CVE-2019-19844", "package": "Django", "severity": "HIGH", "description": "Account hijack"},
            {"id": "CVE-2018-1000656", "package": "Flask", "severity": "HIGH", "description": "DoS"},
            {"id": "CVE-2019-10906", "package": "Jinja2", "severity": "HIGH", "description": "Sandbox escape"}
        ]
    },
    {
        "id": "ts-python-02",
        "name": "Python Cryptography Vulnerabilities",
        "description": "Test for detection of cryptographic vulnerabilities in Python packages",
        "ecosystem": "pypi",
        "dependencies": {
            "requirements.txt": "\n".join([
                "cryptography==2.3",  # CVE-2018-10903
                "pycrypto==2.6.1",    # CVE-2018-6594
                "PyJWT==1.6.1"        # CVE-2018-1000531
            ])
        },
        "expected_vulns": [
            {"id": "CVE-2018-10903", "package": "cryptography", "severity": "MEDIUM", "description": "Timing attack"},
            {"id": "CVE-2018-6594", "package": "pycrypto", "severity": "HIGH", "description": "Integer overflow"},
            {"id": "CVE-2018-1000531", "package": "PyJWT", "severity": "HIGH", "description": "Signature verification bypass"}
        ]
    },
    
    # Java vulnerabilities
    {
        "id": "ts-java-01",
        "name": "Java Framework Vulnerabilities",
        "description": "Test for detection of vulnerabilities in Java frameworks",
        "ecosystem": "maven",
        "dependencies": {
            "pom.xml": """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>java-framework-test</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
            <version>2.5.16</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>5.0.7.RELEASE</version>
        </dependency>
    </dependencies>
</project>"""
        },
        "expected_vulns": [
            {"id": "CVE-2019-0233", "package": "org.apache.struts:struts2-core", "severity": "HIGH", "description": "DoS"},
            {"id": "CVE-2018-15756", "package": "org.springframework:spring-webmvc", "severity": "MEDIUM", "description": "Path traversal"}
        ]
    },
    
    # Mixed ecosystem project
    {
        "id": "ts-mixed-01",
        "name": "Mixed Ecosystem Project",
        "description": "Test for detection of vulnerabilities in projects with multiple ecosystems",
        "ecosystem": "mixed",
        "dependencies": {
            "package.json": {
                "name": "mixed-project",
                "version": "1.0.0",
                "description": "Project with multiple ecosystem dependencies",
                "dependencies": {
                    "lodash": "4.17.15",  # CVE-2019-10744
                    "jquery": "3.4.0"     # CVE-2019-11358
                }
            },
            "requirements.txt": "\n".join([
                "Django==2.2.8",  # CVE-2019-19844
                "Flask==0.12.2"   # CVE-2018-1000656
            ]),
            "pom.xml": """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>mixed-project</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
            <version>2.5.16</version>
        </dependency>
    </dependencies>
</project>"""
        },
        "expected_vulns": [
            {"id": "CVE-2019-10744", "package": "lodash", "severity": "HIGH", "description": "Prototype pollution"},
            {"id": "CVE-2019-11358", "package": "jquery", "severity": "MEDIUM", "description": "Prototype pollution"},
            {"id": "CVE-2019-19844", "package": "Django", "severity": "HIGH", "description": "Account hijack"},
            {"id": "CVE-2018-1000656", "package": "Flask", "severity": "HIGH", "description": "DoS"},
            {"id": "CVE-2019-0233", "package": "org.apache.struts:struts2-core", "severity": "HIGH", "description": "DoS"}
        ]
    }
]


def create_test_project(test_case: Dict[str, Any], base_dir: Path) -> Path:
    """
    Create a test project from a test case definition.
    
    Args:
        test_case: Test case definition.
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created test project.
    """
    # Create project directory
    project_dir = base_dir / test_case["id"]
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create dependency files
    for filename, content in test_case["dependencies"].items():
        file_path = project_dir / filename
        
        # Create parent directories if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file content
        if isinstance(content, dict):
            with open(file_path, "w") as f:
                json.dump(content, f, indent=2)
        else:
            with open(file_path, "w") as f:
                f.write(content)
    
    return project_dir


def run_scanner(project_path: Path, output_dir: Path) -> Path:
    """
    Run ossv-scanner on a test project.
    
    Args:
        project_path: Path to the test project.
        output_dir: Directory to save scanner output.
        
    Returns:
        Path to the scanner output file.
    """
    # Create output directory
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
        return output_path
        
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path


def analyze_result(result_path: Path, expected_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze scanner results against expected vulnerabilities.
    
    Args:
        result_path: Path to the scanner result file.
        expected_vulns: List of expected vulnerabilities.
        
    Returns:
        Analysis results.
    """
    analysis = {
        "detected_vulns": [],
        "missed_vulns": [],
        "extra_vulns": [],
        "metrics": {
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0
        }
    }
    
    # Check if results file exists
    if not result_path.exists():
        logger.warning(f"Results file not found: {result_path}")
        analysis["missed_vulns"] = expected_vulns
        analysis["metrics"]["false_negatives"] = len(expected_vulns)
        return analysis
    
    try:
        # Load scanner results
        with open(result_path, "r") as f:
            scan_results = json.load(f)
        
        # Extract detected vulnerabilities
        detected_vulns = []
        if "vulnerabilities" in scan_results:
            for dep_id, vulns in scan_results["vulnerabilities"].items():
                for vuln in vulns:
                    detected_vulns.append({
                        "id": vuln.get("cve_id", "unknown"),
                        "package": dep_id.split("@")[0] if "@" in dep_id else dep_id,
                        "version": dep_id.split("@")[1] if "@" in dep_id else "unknown",
                        "severity": vuln.get("severity", "UNKNOWN"),
                        "details": vuln
                    })
        
        # Check for detected and missed vulnerabilities
        for expected in expected_vulns:
            found = False
            for detected in detected_vulns:
                if expected["id"].lower() == detected["id"].lower():
                    analysis["detected_vulns"].append({
                        "expected": expected,
                        "detected": detected
                    })
                    found = True
                    break
            
            if not found:
                analysis["missed_vulns"].append(expected)
        
        # Check for extra (potentially false positive) detections
        for detected in detected_vulns:
            if not any(detected["id"].lower() == exp["id"].lower() for exp in expected_vulns):
                analysis["extra_vulns"].append(detected)
        
        # Calculate metrics
        tp = len(analysis["detected_vulns"])
        fn = len(analysis["missed_vulns"])
        fp = len(analysis["extra_vulns"])
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        analysis["metrics"] = {
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "precision": precision,
            "recall": recall,
            "f1_score": f1
        }
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing results: {str(e)}")
        analysis["missed_vulns"] = expected_vulns
        analysis["metrics"]["false_negatives"] = len(expected_vulns)
        return analysis


def run_tests(basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run the test suite with known vulnerabilities.
    
    Args:
        basic: Whether to run a basic subset of tests.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting controlled vulnerability test suite")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-test-suite-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Select test cases
    if basic:
        # Use a minimal set of test cases for basic testing
        selected_cases = [TEST_CASES[0], TEST_CASES[2]]  # One NPM, one Python
    elif comprehensive:
        # Use all test cases plus any additional comprehensive ones
        selected_cases = TEST_CASES
        # TODO: Add more complex test cases for comprehensive testing
    else:
        # Default to all standard test cases
        selected_cases = TEST_CASES
    
    test_results = {}
    summary_metrics = {
        "total_vulns": 0,
        "detected_vulns": 0,
        "missed_vulns": 0,
        "extra_vulns": 0,
        "overall_precision": 0.0,
        "overall_recall": 0.0,
        "overall_f1": 0.0,
        "by_ecosystem": {},
        "by_severity": {}
    }
    
    # Initialize ecosystem metrics
    ecosystems = set(tc["ecosystem"] for tc in selected_cases)
    for ecosystem in ecosystems:
        summary_metrics["by_ecosystem"][ecosystem] = {
            "total": 0,
            "detected": 0,
            "missed": 0,
            "recall": 0.0
        }
    
    # Initialize severity metrics
    severities = set()
    for tc in selected_cases:
        for vuln in tc["expected_vulns"]:
            severities.add(vuln["severity"])
    
    for severity in severities:
        summary_metrics["by_severity"][severity] = {
            "total": 0,
            "detected": 0,
            "missed": 0,
            "recall": 0.0
        }
    
    with Progress() as progress:
        # Create and test each project
        task = progress.add_task("[green]Running test cases...", total=len(selected_cases))
        
        for test_case in selected_cases:
            logger.info(f"Testing {test_case['name']} ({test_case['id']})")
            
            # Create test project
            project_dir = create_test_project(test_case, base_dir)
            
            # Run scanner
            result_path = run_scanner(project_dir, output_dir)
            
            # Analyze results
            analysis = analyze_result(result_path, test_case["expected_vulns"])
            
            # Store results
            test_results[test_case["id"]] = {
                "name": test_case["name"],
                "description": test_case["description"],
                "ecosystem": test_case["ecosystem"],
                "project_path": str(project_dir),
                "result_path": str(result_path),
                "analysis": analysis
            }
            
            # Update summary metrics
            ecosystem = test_case["ecosystem"]
            expected_count = len(test_case["expected_vulns"])
            detected_count = len(analysis["detected_vulns"])
            missed_count = len(analysis["missed_vulns"])
            extra_count = len(analysis["extra_vulns"])
            
            summary_metrics["total_vulns"] += expected_count
            summary_metrics["detected_vulns"] += detected_count
            summary_metrics["missed_vulns"] += missed_count
            summary_metrics["extra_vulns"] += extra_count
            
            # Update ecosystem metrics
            summary_metrics["by_ecosystem"][ecosystem]["total"] += expected_count
            summary_metrics["by_ecosystem"][ecosystem]["detected"] += detected_count
            summary_metrics["by_ecosystem"][ecosystem]["missed"] += missed_count
            
            # Update severity metrics
            for vuln in test_case["expected_vulns"]:
                severity = vuln["severity"]
                summary_metrics["by_severity"][severity]["total"] += 1
                
                # Check if detected
                if any(d["expected"]["id"] == vuln["id"] for d in analysis["detected_vulns"]):
                    summary_metrics["by_severity"][severity]["detected"] += 1
                else:
                    summary_metrics["by_severity"][severity]["missed"] += 1
            
            progress.update(task, advance=1)
    
    # Calculate overall metrics
    if summary_metrics["total_vulns"] > 0:
        summary_metrics["overall_recall"] = summary_metrics["detected_vulns"] / summary_metrics["total_vulns"]
    
    if (summary_metrics["detected_vulns"] + summary_metrics["extra_vulns"]) > 0:
        summary_metrics["overall_precision"] = summary_metrics["detected_vulns"] / (summary_metrics["detected_vulns"] + summary_metrics["extra_vulns"])
    
    if (summary_metrics["overall_precision"] + summary_metrics["overall_recall"]) > 0:
        summary_metrics["overall_f1"] = 2 * (summary_metrics["overall_precision"] * summary_metrics["overall_recall"]) / (summary_metrics["overall_precision"] + summary_metrics["overall_recall"])
    
    # Calculate ecosystem recall rates
    for ecosystem in summary_metrics["by_ecosystem"]:
        if summary_metrics["by_ecosystem"][ecosystem]["total"] > 0:
            summary_metrics["by_ecosystem"][ecosystem]["recall"] = (
                summary_metrics["by_ecosystem"][ecosystem]["detected"] / 
                summary_metrics["by_ecosystem"][ecosystem]["total"]
            )
    
    # Calculate severity recall rates
    for severity in summary_metrics["by_severity"]:
        if summary_metrics["by_severity"][severity]["total"] > 0:
            summary_metrics["by_severity"][severity]["recall"] = (
                summary_metrics["by_severity"][severity]["detected"] / 
                summary_metrics["by_severity"][severity]["total"]
            )
    
    # Generate final results
    final_results = {
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir)
        },
        "test_cases": test_results,
        "summary": summary_metrics,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "num_test_cases": len(selected_cases),
            "num_expected_vulns": summary_metrics["total_vulns"]
        }
    }
    
    # Display summary
    display_summary(summary_metrics)
    
    logger.info("Controlled vulnerability test suite completed")
    return final_results


def display_summary(summary: Dict[str, Any]) -> None:
    """
    Display a summary of test results.
    
    Args:
        summary: Summary metrics dictionary.
    """
    console.print("\n[bold cyan]Test Suite Summary[/]")
    
    # Create a summary table
    table = Table(title="Vulnerability Detection Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Rate", style="yellow")
    
    table.add_row("Total Vulnerabilities", str(summary["total_vulns"]), "")
    table.add_row("Detected (True Positives)", str(summary["detected_vulns"]), f"{summary['overall_recall']:.1%}")
    table.add_row("Missed (False Negatives)", str(summary["missed_vulns"]), f"{1 - summary['overall_recall']:.1%}")
    table.add_row("Extra Detections (Potential False Positives)", str(summary["extra_vulns"]), "")
    table.add_row("Precision", "", f"{summary['overall_precision']:.1%}")
    table.add_row("Recall", "", f"{summary['overall_recall']:.1%}")
    table.add_row("F1 Score", "", f"{summary['overall_f1']:.3f}")
    
    console.print(table)
    
    # Create ecosystem breakdown table
    console.print("\n[bold cyan]Results by Ecosystem[/]")
    eco_table = Table()
    eco_table.add_column("Ecosystem", style="cyan")
    eco_table.add_column("Total", style="green")
    eco_table.add_column("Detected", style="green")
    eco_table.add_column("Missed", style="red")
    eco_table.add_column("Recall", style="yellow")
    
    for ecosystem, metrics in summary["by_ecosystem"].items():
        eco_table.add_row(
            ecosystem,
            str(metrics["total"]),
            str(metrics["detected"]),
            str(metrics["missed"]),
            f"{metrics['recall']:.1%}"
        )
    
    console.print(eco_table)
    
    # Create severity breakdown table
    console.print("\n[bold cyan]Results by Severity[/]")
    sev_table = Table()
    sev_table.add_column("Severity", style="cyan")
    sev_table.add_column("Total", style="green")
    sev_table.add_column("Detected", style="green")
    sev_table.add_column("Missed", style="red")
    sev_table.add_column("Recall", style="yellow")
    
    # Order by severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    for severity in severity_order:
        if severity in summary["by_severity"]:
            metrics = summary["by_severity"][severity]
            sev_table.add_row(
                severity,
                str(metrics["total"]),
                str(metrics["detected"]),
                str(metrics["missed"]),
                f"{metrics['recall']:.1%}"
            )
    
    console.print(sev_table)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_tests()
    print(json.dumps(results, indent=2))
