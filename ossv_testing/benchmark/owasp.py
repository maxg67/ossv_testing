"""
OWASP benchmark testing for ossv-scanner.

Tests the scanner against the OWASP Benchmark Project methodology, modified for
vulnerability scanning rather than application security testing.
"""

import os
import time
import logging
import tempfile
import json
import subprocess
import shutil
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import requests
from rich.console import Console
from rich.progress import Progress

logger = logging.getLogger(__name__)
console = Console()

# OWASP benchmark categories relevant to dependency scanning
OWASP_CATEGORIES = [
    "A5:2017-Broken Access Control",  # Includes insecure dependencies
    "A6:2017-Security Misconfiguration",  # Includes misconfigured dependencies
    "A9:2017-Using Components with Known Vulnerabilities",  # Direct match for our tool
]

# Test projects with known vulnerabilities by category
TEST_PROJECTS = {
    "A9:2017": [
        {
            "name": "vulnerable-javascript",
            "description": "JavaScript project with known vulnerabilities",
            "dependencies": {
                "package.json": {
                    "name": "vulnerable-js-project",
                    "version": "1.0.0",
                    "dependencies": {
                        "lodash": "4.17.15",  # Prototype pollution
                        "jquery": "1.12.4",   # XSS vulnerabilities
                        "express": "4.16.0",  # Various issues
                        "minimist": "1.2.0",  # Prototype pollution
                    }
                }
            },
            "expected_vulns": [
                {"id": "CVE-2019-10744", "package": "lodash", "severity": "HIGH"},
                {"id": "CVE-2019-11358", "package": "jquery", "severity": "MEDIUM"},
                {"id": "CVE-2019-8331", "package": "jquery", "severity": "MEDIUM"},
                {"id": "CVE-2020-7598", "package": "minimist", "severity": "MEDIUM"},
                {"id": "CVE-2019-16138", "package": "express", "severity": "HIGH"}
            ]
        },
        {
            "name": "vulnerable-python",
            "description": "Python project with known vulnerabilities",
            "dependencies": {
                "requirements.txt": "\n".join([
                    "Django==2.2.8",  # Multiple vulns
                    "Jinja2==2.10",   # XSS vulnerability
                    "Flask==0.12.2",  # Various issues
                    "requests==2.19.1" # Security issues
                ])
            },
            "expected_vulns": [
                {"id": "CVE-2019-19844", "package": "Django", "severity": "HIGH"},
                {"id": "CVE-2019-8341", "package": "Django", "severity": "MEDIUM"},
                {"id": "CVE-2019-10906", "package": "Jinja2", "severity": "HIGH"},
                {"id": "CVE-2018-1000656", "package": "Flask", "severity": "HIGH"},
                {"id": "CVE-2018-18074", "package": "requests", "severity": "MEDIUM"}
            ]
        },
        {
            "name": "vulnerable-java",
            "description": "Java project with known vulnerabilities",
            "dependencies": {
                "pom.xml": """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>vulnerable-java</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
            <version>2.5.16</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.9.8</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>5.0.7.RELEASE</version>
        </dependency>
    </dependencies>
</project>"""
            },
            "expected_vulns": [
                {"id": "CVE-2019-0233", "package": "org.apache.struts:struts2-core", "severity": "HIGH"},
                {"id": "CVE-2019-12086", "package": "com.fasterxml.jackson.core:jackson-databind", "severity": "HIGH"},
                {"id": "CVE-2018-15756", "package": "org.springframework:spring-web", "severity": "MEDIUM"}
            ]
        }
    ],
    "A6:2017": [
        {
            "name": "misconfigured-js",
            "description": "JavaScript project with misconfigured dependencies",
            "dependencies": {
                "package.json": {
                    "name": "misconfigured-js",
                    "version": "1.0.0",
                    "dependencies": {
                        "dotenv": "6.0.0",  # Older version with issues
                        "config": "1.30.0"   # Older version with configuration issues
                    }
                },
                ".env": "API_KEY=test_key\nSECRET=test_secret"
            },
            "expected_vulns": [
                {"id": "CVE-2019-0000", "package": "dotenv", "severity": "LOW"}  # Not a real CVE, misconfiguration issue
            ]
        }
    ]
}


def create_test_project(project_config: Dict[str, Any], base_dir: Optional[Path] = None) -> Path:
    """
    Create a test project with specified configurations.
    
    Args:
        project_config: Project configuration dictionary.
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created project.
    """
    # Create temp directory for project
    if base_dir:
        base_dir.mkdir(parents=True, exist_ok=True)
        project_dir = base_dir / project_config["name"]
    else:
        project_dir = Path(tempfile.mkdtemp(prefix=f"ossv-owasp-{project_config['name']}-"))
    
    # Create project directory if it doesn't exist
    project_dir.mkdir(exist_ok=True)
    
    # Create dependency files
    for filename, content in project_config["dependencies"].items():
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


def run_scanner_on_project(project_path: Path, output_dir: Path) -> Path:
    """
    Run ossv-scanner on a test project.
    
    Args:
        project_path: Path to the test project.
        output_dir: Directory to save output.
        
    Returns:
        Path to the scan result file.
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


def analyze_results(results_path: Path, expected_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze scanner results against expected vulnerabilities.
    
    Args:
        results_path: Path to the scan results file.
        expected_vulns: List of expected vulnerabilities.
        
    Returns:
        Analysis results dictionary.
    """
    analysis = {
        "true_positives": [],
        "false_negatives": [],
        "false_positives": [],
        "unknown": [],
        "metrics": {
            "true_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "false_positive_count": 0,
            "f1_score": 0.0,
            "precision": 0.0,
            "recall": 0.0
        }
    }
    
    # Check if results file exists
    if not results_path.exists():
        logger.warning(f"Results file not found: {results_path}")
        analysis["false_negatives"] = expected_vulns
        analysis["metrics"] = {
            "true_positive_rate": 0.0,
            "false_negative_rate": 1.0,
            "false_positive_count": 0,
            "f1_score": 0.0,
            "precision": 0.0,
            "recall": 0.0
        }
        return analysis
    
    try:
        # Load scan results
        with open(results_path, "r") as f:
            scan_results = json.load(f)
        
        # Extract detected vulnerabilities
        detected_vulns = []
        if "vulnerabilities" in scan_results:
            for dep_id, vulns in scan_results["vulnerabilities"].items():
                for vuln in vulns:
                    detected_vulns.append({
                        "id": vuln.get("cve_id", "unknown"),
                        "package": dep_id.split("@")[0] if "@" in dep_id else dep_id,
                        "severity": vuln.get("severity", "UNKNOWN"),
                        "details": vuln
                    })
        
        # Check for true positives and false negatives
        true_positives = []
        false_negatives = []
        
        for expected in expected_vulns:
            found = False
            for detected in detected_vulns:
                if expected["id"] == detected["id"]:
                    true_positives.append({
                        "expected": expected,
                        "detected": detected
                    })
                    found = True
                    break
            
            if not found:
                false_negatives.append(expected)
        
        # Check for false positives
        false_positives = []
        for detected in detected_vulns:
            if not any(detected["id"] == expected["id"] for expected in expected_vulns):
                false_positives.append(detected)
        
        # Calculate metrics
        true_positive_count = len(true_positives)
        false_negative_count = len(false_negatives)
        false_positive_count = len(false_positives)
        
        # True positive rate (recall)
        recall = true_positive_count / (true_positive_count + false_negative_count) if (true_positive_count + false_negative_count) > 0 else 0
        
        # Precision
        precision = true_positive_count / (true_positive_count + false_positive_count) if (true_positive_count + false_positive_count) > 0 else 0
        
        # F1 score
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # False negative rate
        false_negative_rate = false_negative_count / (true_positive_count + false_negative_count) if (true_positive_count + false_negative_count) > 0 else 1
        
        # Update analysis
        analysis["true_positives"] = true_positives
        analysis["false_negatives"] = false_negatives
        analysis["false_positives"] = false_positives
        analysis["metrics"] = {
            "true_positive_rate": recall,
            "false_negative_rate": false_negative_rate,
            "false_positive_count": false_positive_count,
            "f1_score": f1_score,
            "precision": precision,
            "recall": recall
        }
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing results: {str(e)}")
        analysis["false_negatives"] = expected_vulns
        analysis["metrics"] = {
            "true_positive_rate": 0.0,
            "false_negative_rate": 1.0,
            "false_positive_count": 0,
            "f1_score": 0.0,
            "precision": 0.0,
            "recall": 0.0
        }
        return analysis


def calculate_benchmark_score(category_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate the OWASP benchmark score.
    
    Args:
        category_results: Results for each OWASP category.
        
    Returns:
        Dictionary with benchmark scores.
    """
    # Aggregate metrics across all categories and projects
    overall_metrics = {
        "true_positives": 0,
        "false_negatives": 0,
        "false_positives": 0,
        "expected_vulns": 0,
        "detected_vulns": 0
    }
    
    category_scores = {}
    
    for category, projects in category_results.items():
        category_metrics = {
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
            "expected_vulns": 0,
            "detected_vulns": 0
        }
        
        for project_name, analysis in projects.items():
            category_metrics["true_positives"] += len(analysis["true_positives"])
            category_metrics["false_negatives"] += len(analysis["false_negatives"])
            category_metrics["false_positives"] += len(analysis["false_positives"])
            category_metrics["expected_vulns"] += len(analysis["true_positives"]) + len(analysis["false_negatives"])
            category_metrics["detected_vulns"] += len(analysis["true_positives"]) + len(analysis["false_positives"])
        
        # Calculate category scores
        true_positive_rate = category_metrics["true_positives"] / category_metrics["expected_vulns"] if category_metrics["expected_vulns"] > 0 else 0
        false_positive_rate = category_metrics["false_positives"] / (category_metrics["false_positives"] + category_metrics["true_positives"]) if (category_metrics["false_positives"] + category_metrics["true_positives"]) > 0 else 0
        
        # Youden Index (J = TPR - FPR)
        youden_index = true_positive_rate - false_positive_rate
        
        # OWASP Score (0-100)
        owasp_score = 100 * (true_positive_rate - false_positive_rate + 1) / 2
        
        category_scores[category] = {
            "metrics": category_metrics,
            "true_positive_rate": true_positive_rate,
            "false_positive_rate": false_positive_rate,
            "youden_index": youden_index,
            "owasp_score": owasp_score
        }
        
        # Add to overall metrics
        for key in overall_metrics:
            overall_metrics[key] += category_metrics[key]
    
    # Calculate overall scores
    true_positive_rate = overall_metrics["true_positives"] / overall_metrics["expected_vulns"] if overall_metrics["expected_vulns"] > 0 else 0
    false_positive_rate = overall_metrics["false_positives"] / (overall_metrics["false_positives"] + overall_metrics["true_positives"]) if (overall_metrics["false_positives"] + overall_metrics["true_positives"]) > 0 else 0
    
    # Youden Index
    youden_index = true_positive_rate - false_positive_rate
    
    # OWASP Score
    owasp_score = 100 * (true_positive_rate - false_positive_rate + 1) / 2
    
    # Create benchmark score object
    benchmark_score = {
        "overall": {
            "metrics": overall_metrics,
            "true_positive_rate": true_positive_rate,
            "false_positive_rate": false_positive_rate,
            "youden_index": youden_index,
            "owasp_score": owasp_score
        },
        "categories": category_scores
    }
    
    return benchmark_score


def run_benchmark(basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run the OWASP benchmark tests.
    
    Args:
        basic: Whether to run a basic test with fewer projects.
        comprehensive: Whether to run comprehensive tests with more projects.
        
    Returns:
        Dictionary with benchmark results.
    """
    logger.info("Starting OWASP benchmark tests")
    
    # Create base directory for test projects
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-owasp-benchmark-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(exist_ok=True)
    
    # Select which tests to run
    test_categories = ["A9:2017"]  # Always test A9
    
    if comprehensive:
        test_categories.extend(["A6:2017"])  # Add more categories for comprehensive testing
    
    # Track results for each category and project
    category_results = {}
    
    with Progress() as progress:
        # Count total number of projects
        total_projects = sum(len(TEST_PROJECTS.get(category, [])) for category in test_categories)
        task = progress.add_task("[green]Running OWASP benchmarks...", total=total_projects)
        
        # Run tests for each category
        for category in test_categories:
            if category not in TEST_PROJECTS:
                logger.warning(f"No test projects defined for category {category}")
                continue
            
            category_results[category] = {}
            
            # Create and test each project in the category
            for project_config in TEST_PROJECTS[category]:
                project_name = project_config["name"]
                logger.info(f"Testing project: {project_name}")
                
                # Create the test project
                project_dir = create_test_project(project_config, base_dir)
                
                # Run scanner on the project
                result_path = run_scanner_on_project(project_dir, output_dir)
                
                # Analyze results
                analysis = analyze_results(result_path, project_config["expected_vulns"])
                
                # Store results
                category_results[category][project_name] = analysis
                
                # Update progress
                progress.update(task, advance=1)
    
    # Calculate benchmark score
    benchmark_score = calculate_benchmark_score(category_results)
    
    # Combine all results
    benchmark_results = {
        "base_dir": str(base_dir),
        "output_dir": str(output_dir),
        "category_results": category_results,
        "benchmark_score": benchmark_score,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "benchmark_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "categories_tested": test_categories
        }
    }
    
    logger.info(f"OWASP benchmark complete. Overall score: {benchmark_score['overall']['owasp_score']:.2f}%")
    return benchmark_results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_benchmark()
    print(json.dumps(results, indent=2))
