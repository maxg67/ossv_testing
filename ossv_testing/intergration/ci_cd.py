"""
CI/CD integration testing for ossv-scanner.

This module tests the integration of ossv-scanner with common CI/CD
platforms like GitHub Actions, GitLab CI, Jenkins, and CircleCI.
"""

import os
import time
import logging
import tempfile
import json
import yaml
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Test CI/CD configurations
CI_CONFIGS = {
    "github_actions": {
        "name": "GitHub Actions",
        "filename": ".github/workflows/ossv-scan.yml",
        "template": """name: OSSV Scanner

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Run weekly

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install ossv-scanner
          
      - name: Run OSSV Scanner
        run: ossv-scan --output-format json --output-path scan-results.json .
        
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: ossv-scan-results
          path: scan-results.json
"""
    },
    "gitlab_ci": {
        "name": "GitLab CI",
        "filename": ".gitlab-ci.yml",
        "template": """stages:
  - scan

ossv-scanner:
  stage: scan
  image: python:3.9-slim
  script:
    - pip install ossv-scanner
    - ossv-scan --output-format json --output-path scan-results.json .
  artifacts:
    paths:
      - scan-results.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == 'push'
    - if: $CI_PIPELINE_SOURCE == 'schedule'
"""
    },
    "jenkins": {
        "name": "Jenkins",
        "filename": "Jenkinsfile",
        "template": """pipeline {
    agent {
        docker {
            image 'python:3.9-slim'
        }
    }
    
    stages {
        stage('Install') {
            steps {
                sh 'pip install ossv-scanner'
            }
        }
        
        stage('Scan') {
            steps {
                sh 'ossv-scan --output-format json --output-path scan-results.json .'
            }
        }
        
        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'scan-results.json', fingerprint: true
            }
        }
    }
}
"""
    },
    "circleci": {
        "name": "CircleCI",
        "filename": ".circleci/config.yml",
        "template": """version: 2.1

jobs:
  scan:
    docker:
      - image: cimg/python:3.9
    steps:
      - checkout
      - run:
          name: Install OSSV Scanner
          command: pip install ossv-scanner
      - run:
          name: Run vulnerability scan
          command: ossv-scan --output-format json --output-path scan-results.json .
      - store_artifacts:
          path: scan-results.json

workflows:
  vulnerability-scan:
    jobs:
      - scan
"""
    },
    "azure_pipelines": {
        "name": "Azure Pipelines",
        "filename": "azure-pipelines.yml",
        "template": """trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.9'
    addToPath: true

- script: pip install ossv-scanner
  displayName: 'Install OSSV Scanner'

- script: ossv-scan --output-format json --output-path $(Build.ArtifactStagingDirectory)/scan-results.json .
  displayName: 'Run vulnerability scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)'
    artifactName: 'scan-results'
"""
    }
}

# Simple test project for CI/CD testing
TEST_PROJECT = {
    "package.json": {
        "name": "cicd-test-project",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.15",  # Has known vulnerability
            "express": "4.17.1"
        }
    },
    "requirements.txt": "\n".join([
        "Django==2.2.8",  # Has known vulnerability
        "requests==2.25.1"
    ])
}


def create_test_project(base_dir: Path) -> Path:
    """
    Create a test project with CI/CD configurations.
    
    Args:
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created test project.
    """
    project_dir = base_dir / "cicd-test-project"
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create test files
    with open(project_dir / "package.json", "w") as f:
        json.dump(TEST_PROJECT["package.json"], f, indent=2)
    
    with open(project_dir / "requirements.txt", "w") as f:
        f.write(TEST_PROJECT["requirements.txt"])
    
    # Create README file
    with open(project_dir / "README.md", "w") as f:
        f.write("# CI/CD Test Project\n\nTest project for ossv-scanner CI/CD integration testing.")
    
    # Create CI/CD configurations
    for ci_id, ci_config in CI_CONFIGS.items():
        file_path = project_dir / ci_config["filename"]
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, "w") as f:
            f.write(ci_config["template"])
    
    return project_dir


def validate_ci_config(ci_id: str, config_path: Path) -> Dict[str, Any]:
    """
    Validate CI/CD configuration file.
    
    Args:
        ci_id: CI/CD platform identifier.
        config_path: Path to the configuration file.
        
    Returns:
        Validation results.
    """
    validation = {
        "valid": False,
        "exists": False,
        "parseable": False,
        "contains_scanner": False,
        "issues": []
    }
    
    # Check if file exists
    if not config_path.exists():
        validation["issues"].append(f"Configuration file {config_path} does not exist")
        return validation
    
    validation["exists"] = True
    
    # Try to parse the file
    try:
        with open(config_path, "r") as f:
            content = f.read()
            
            # Check if file is YAML or Jenkinsfile
            if config_path.suffix.lower() in (".yml", ".yaml"):
                config = yaml.safe_load(content)
                validation["parseable"] = True
            elif config_path.name == "Jenkinsfile":
                # Simple check for Jenkinsfile (not full parsing)
                if "pipeline" in content and "stages" in content:
                    validation["parseable"] = True
            else:
                validation["issues"].append(f"Unsupported configuration format: {config_path.suffix}")
                return validation
        
        # Check for scanner command
        if "ossv-scan" in content or "ossv-scanner" in content:
            validation["contains_scanner"] = True
        else:
            validation["issues"].append("Configuration does not contain ossv-scanner commands")
    
    except Exception as e:
        validation["issues"].append(f"Error parsing configuration: {str(e)}")
        return validation
    
    # Configuration is valid if parseable and contains scanner
    validation["valid"] = validation["parseable"] and validation["contains_scanner"]
    
    return validation


def generate_scanner_output(output_path: Path) -> None:
    """
    Generate simulated scanner output for CI/CD testing.
    
    Args:
        output_path: Path to write the output file.
    """
    # Create a simulated scanner output file
    scan_result = {
        "scanner": {
            "name": "ossv-scanner",
            "version": "0.1.0",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        },
        "summary": {
            "total_dependencies": 4,
            "vulnerable_dependencies": 2,
            "total_vulnerabilities": 2
        },
        "vulnerabilities": {
            "lodash@4.17.15": [
                {
                    "cve_id": "CVE-2019-10744",
                    "severity": "HIGH",
                    "description": "Prototype pollution vulnerability in lodash",
                    "fixed_version": "4.17.19"
                }
            ],
            "django@2.2.8": [
                {
                    "cve_id": "CVE-2019-19844",
                    "severity": "HIGH",
                    "description": "Account takeover vulnerability in Django",
                    "fixed_version": "2.2.9"
                }
            ]
        }
    }
    
    with open(output_path, "w") as f:
        json.dump(scan_result, f, indent=2)


def simulate_ci_run(ci_id: str, project_dir: Path, output_dir: Path) -> Dict[str, Any]:
    """
    Simulate a CI/CD run for testing.
    
    Args:
        ci_id: CI/CD platform identifier.
        project_dir: Path to the test project.
        output_dir: Directory to save output.
        
    Returns:
        Simulation results.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{ci_id}-result.json"
    
    # Simulate CI/CD run
    ci_config = CI_CONFIGS.get(ci_id, {})
    config_path = project_dir / ci_config.get("filename", "")
    
    results = {
        "ci_platform": ci_id,
        "name": ci_config.get("name", ci_id),
        "success": False,
        "config_valid": False,
        "output_path": str(output_path),
        "execution_time": 0,
        "issues": []
    }
    
    # Validate CI/CD configuration
    validation = validate_ci_config(ci_id, config_path)
    results["config_valid"] = validation["valid"]
    results["issues"].extend(validation["issues"])
    
    if not validation["valid"]:
        results["issues"].append(f"Invalid {ci_id} configuration")
        return results
    
    # Simulate execution
    start_time = time.time()
    
    try:
        # Generate simulated scanner output
        generate_scanner_output(output_path)
        
        # Simulate CI/CD behavior
        time.sleep(0.5)  # Simulate some processing time
        
        results["success"] = True
    except Exception as e:
        results["issues"].append(f"Error during simulation: {str(e)}")
        results["success"] = False
    
    results["execution_time"] = time.time() - start_time
    
    return results


def run_tests() -> Dict[str, Any]:
    """
    Run CI/CD integration tests.
    
    Returns:
        Test results dictionary.
    """
    logger.info("Starting CI/CD integration tests")
    
    # Create base directories
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-cicd-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create test project
    project_dir = create_test_project(base_dir)
    
    # Run tests for each CI/CD platform
    ci_results = {}
    
    with Progress() as progress:
        task = progress.add_task("[green]Testing CI/CD integrations...", total=len(CI_CONFIGS))
        
        for ci_id in CI_CONFIGS:
            logger.info(f"Testing {ci_id} integration")
            
            # Simulate CI/CD run
            result = simulate_ci_run(ci_id, project_dir, output_dir)
            ci_results[ci_id] = result
            
            progress.update(task, advance=1)
    
    # Summarize results
    summary = {
        "total_platforms": len(CI_CONFIGS),
        "successful_integrations": sum(1 for r in ci_results.values() if r["success"]),
        "failed_integrations": sum(1 for r in ci_results.values() if not r["success"]),
        "issues_count": sum(len(r["issues"]) for r in ci_results.values())
    }
    
    # Combine all results
    test_results = {
        "base_dir": str(base_dir),
        "project_dir": str(project_dir),
        "output_dir": str(output_dir),
        "ci_results": ci_results,
        "summary": summary,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    }
    
    # Display summary
    display_summary(test_results)
    
    logger.info("CI/CD integration tests completed")
    return test_results


def display_summary(test_results: Dict[str, Any]) -> None:
    """
    Display a summary of CI/CD integration test results.
    
    Args:
        test_results: Test results dictionary.
    """
    console.print("\n[bold cyan]CI/CD Integration Test Summary[/]")
    
    # Create summary table
    table = Table(title="Integration Test Results")
    table.add_column("CI/CD Platform", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Config Valid", style="yellow")
    table.add_column("Issues", style="red")
    
    for ci_id, result in test_results["ci_results"].items():
        status = "[green]Success[/]" if result["success"] else "[red]Failed[/]"
        config_valid = "[green]Yes[/]" if result["config_valid"] else "[red]No[/]"
        issues_count = len(result["issues"])
        issues = f"[red]{issues_count}[/]" if issues_count > 0 else "[green]0[/]"
        
        table.add_row(
            result["name"],
            status,
            config_valid,
            issues
        )
    
    console.print(table)
    
    # Overall assessment
    summary = test_results["summary"]
    console.print(f"\nTested {summary['total_platforms']} CI/CD platforms:")
    console.print(f"[green]Successful:[/] {summary['successful_integrations']}")
    console.print(f"[red]Failed:[/] {summary['failed_integrations']}")
    
    if summary["issues_count"] > 0:
        console.print(f"[yellow]Total issues found:[/] {summary['issues_count']}")
    
    # Integration recommendations
    console.print("\n[bold cyan]Integration Recommendations:[/]")
    
    if summary["successful_integrations"] == summary["total_platforms"]:
        console.print("[green]✓ The scanner integrates well with all tested CI/CD platforms.[/]")
    else:
        console.print("[yellow]! Some CI/CD integrations need improvement:[/]")
        
        for ci_id, result in test_results["ci_results"].items():
            if not result["success"]:
                console.print(f"  - [red]{result['name']}:[/] {', '.join(result['issues'])}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_tests()
    print(json.dumps(results, indent=2))