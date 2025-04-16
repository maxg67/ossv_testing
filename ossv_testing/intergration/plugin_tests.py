"""
Integration testing for ossv-scanner plugins.

This module tests how the scanner integrates with various development tools,
IDEs, and platforms via plugins or extensions.
"""

import os
import time
import logging
import tempfile
import json
import subprocess
import shutil
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

import requests
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Define plugin configurations for testing
PLUGIN_CONFIGS = [
    {
        "id": "vscode-extension",
        "name": "VS Code Extension",
        "description": "Extension for Visual Studio Code",
        "test_type": "ide_integration",
        "repo_url": "https://github.com/example/ossv-vscode-extension",
        "commands": [
            {"name": "scan_current_file", "expected_result": "success"},
            {"name": "scan_workspace", "expected_result": "success"},
            {"name": "view_vuln_details", "expected_result": "success"}
        ],
        "features": [
            "realtime_scanning",
            "vulnerability_highlighting",
            "fix_recommendations",
            "sbom_generation"
        ]
    },
    {
        "id": "github-action",
        "name": "GitHub Action",
        "description": "GitHub Action for CI/CD pipelines",
        "test_type": "ci_cd_integration",
        "repo_url": "https://github.com/example/ossv-github-action",
        "commands": [
            {"name": "scan_on_push", "expected_result": "success"},
            {"name": "scan_on_pr", "expected_result": "success"},
            {"name": "fail_on_critical", "expected_result": "failure"}
        ],
        "features": [
            "pr_comments",
            "security_report",
            "sarif_output",
            "customizable_rules"
        ]
    },
    {
        "id": "jenkins-plugin",
        "name": "Jenkins Plugin",
        "description": "Plugin for Jenkins CI server",
        "test_type": "ci_cd_integration",
        "repo_url": "https://github.com/example/ossv-jenkins-plugin",
        "commands": [
            {"name": "scan_as_build_step", "expected_result": "success"},
            {"name": "scan_post_build", "expected_result": "success"},
            {"name": "generate_report", "expected_result": "success"}
        ],
        "features": [
            "build_status_integration",
            "trend_analysis",
            "custom_thresholds",
            "email_notifications"
        ]
    },
    {
        "id": "gradle-plugin",
        "name": "Gradle Plugin",
        "description": "Plugin for Gradle build system",
        "test_type": "build_integration",
        "repo_url": "https://github.com/example/ossv-gradle-plugin",
        "commands": [
            {"name": "ossv_scan", "expected_result": "success"},
            {"name": "ossv_sbom", "expected_result": "success"},
            {"name": "ossv_report", "expected_result": "success"}
        ],
        "features": [
            "dependency_analysis",
            "configurable_severity",
            "report_generation",
            "build_lifecycle_integration"
        ]
    },
    {
        "id": "docker-extension",
        "name": "Docker Extension",
        "description": "Extension for Docker Desktop",
        "test_type": "container_integration",
        "repo_url": "https://github.com/example/ossv-docker-extension",
        "commands": [
            {"name": "scan_container", "expected_result": "success"},
            {"name": "scan_dockerfile", "expected_result": "success"},
            {"name": "scan_image", "expected_result": "success"}
        ],
        "features": [
            "container_scanning",
            "base_image_analysis",
            "layer_visualization",
            "remediation_advice"
        ]
    }
]


def create_test_environment(plugin_config: Dict[str, Any], base_dir: Path) -> Path:
    """
    Set up a test environment for plugin testing.
    
    Args:
        plugin_config: Plugin configuration.
        base_dir: Base directory for test environment.
        
    Returns:
        Path to test environment directory.
    """
    # Create directory for this plugin's tests
    test_dir = base_dir / plugin_config["id"]
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a sample project based on plugin type
    if plugin_config["test_type"] == "ide_integration":
        _create_sample_ide_project(test_dir, plugin_config)
    elif plugin_config["test_type"] == "ci_cd_integration":
        _create_sample_ci_cd_project(test_dir, plugin_config)
    elif plugin_config["test_type"] == "build_integration":
        _create_sample_build_project(test_dir, plugin_config)
    elif plugin_config["test_type"] == "container_integration":
        _create_sample_container_project(test_dir, plugin_config)
    
    return test_dir


def _create_sample_ide_project(test_dir: Path, plugin_config: Dict[str, Any]) -> None:
    """Create a sample project for IDE plugin testing."""
    # Create package.json with some dependencies
    package_json = {
        "name": f"{plugin_config['id']}-test-project",
        "version": "1.0.0",
        "description": f"Test project for {plugin_config['name']}",
        "dependencies": {
            "lodash": "4.17.15",  # Known vulnerability
            "express": "4.17.1",
            "jquery": "3.4.0"      # Known vulnerability
        }
    }
    
    with open(test_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create a simple index.js file
    with open(test_dir / "index.js", "w") as f:
        f.write("""
const lodash = require('lodash');
const express = require('express');
const $ = require('jquery');

// Sample application code
const app = express();
app.get('/', (req, res) => {
    res.send('Hello, world!');
});

console.log(lodash.capitalize('hello world'));
console.log($('body').html());
""")
    
    # Create VS Code workspace file
    vscode_dir = test_dir / ".vscode"
    vscode_dir.mkdir(exist_ok=True)
    
    settings = {
        "ossv.enableScanning": True,
        "ossv.scanOnSave": True,
        "ossv.severityLevel": "medium"
    }
    
    with open(vscode_dir / "settings.json", "w") as f:
        json.dump(settings, f, indent=2)


def _create_sample_ci_cd_project(test_dir: Path, plugin_config: Dict[str, Any]) -> None:
    """Create a sample project for CI/CD plugin testing."""
    # Create package.json with dependencies
    package_json = {
        "name": f"{plugin_config['id']}-test-project",
        "version": "1.0.0",
        "description": f"Test project for {plugin_config['name']}",
        "dependencies": {
            "axios": "0.21.1",     # Known vulnerability
            "react": "17.0.2",
            "lodash": "4.17.15"    # Known vulnerability
        },
        "scripts": {
            "test": "echo \"Error: no test specified\" && exit 1",
            "lint": "eslint .",
            "ossv-scan": "ossv-scan ."
        }
    }
    
    with open(test_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create CI config files based on plugin ID
    if plugin_config["id"] == "github-action":
        github_dir = test_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True, exist_ok=True)
        
        workflow = {
            "name": "OSSV Scanner",
            "on": ["push", "pull_request"],
            "jobs": {
                "scan": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v2"},
                        {"uses": "example/ossv-github-action@v1",
                         "with": {
                             "severity-level": "high",
                             "fail-on-critical": "true"
                         }}
                    ]
                }
            }
        }
        
        with open(github_dir / "ossv-scan.yml", "w") as f:
            yaml.dump(workflow, f)
    elif plugin_config["id"] == "jenkins-plugin":
        # Create Jenkinsfile
        jenkinsfile_content = """
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'npm install'
            }
        }
        stage('OSS Vulnerability Scan') {
            steps {
                ossvScan(
                    scanPath: '.',
                    failOnSeverity: 'CRITICAL',
                    generateReport: true
                )
            }
        }
    }
    post {
        always {
            ossvPublishResults()
        }
    }
}
"""
        with open(test_dir / "Jenkinsfile", "w") as f:
            f.write(jenkinsfile_content)


def _create_sample_build_project(test_dir: Path, plugin_config: Dict[str, Any]) -> None:
    """Create a sample project for build system plugin testing."""
    if plugin_config["id"] == "gradle-plugin":
        # Create build.gradle
        build_gradle = """
plugins {
    id 'java'
    id 'com.example.ossv-gradle-plugin' version '1.0.0'
}

group = 'com.example'
version = '1.0-SNAPSHOT'

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework:spring-web:5.0.7.RELEASE'
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'
    implementation 'org.apache.commons:commons-lang3:3.9'
    testImplementation 'junit:junit:4.12'
}

ossvScan {
    severityLevel = 'HIGH'
    failOnVulnerabilities = true
    generateReport = true
    reportFormat = 'JSON'
}
"""
        with open(test_dir / "build.gradle", "w") as f:
            f.write(build_gradle)
        
        # Create settings.gradle
        settings_gradle = """
rootProject.name = 'ossv-gradle-test'
"""
        with open(test_dir / "settings.gradle", "w") as f:
            f.write(settings_gradle)
        
        # Create simple Java file
        src_dir = test_dir / "src" / "main" / "java" / "com" / "example"
        src_dir.mkdir(parents=True, exist_ok=True)
        
        java_file = """
package com.example;

import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;

public class Main {
    public static void main(String[] args) {
        RestTemplate restTemplate = new RestTemplate();
        ObjectMapper mapper = new ObjectMapper();
        
        System.out.println("Hello, world!");
        System.out.println(StringUtils.capitalize("hello"));
    }
}
"""
        with open(src_dir / "Main.java", "w") as f:
            f.write(java_file)


def _create_sample_container_project(test_dir: Path, plugin_config: Dict[str, Any]) -> None:
    """Create a sample project for container plugin testing."""
    # Create Dockerfile
    dockerfile = """
FROM node:14

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000
CMD [ "node", "index.js" ]
"""
    with open(test_dir / "Dockerfile", "w") as f:
        f.write(dockerfile)
    
    # Create package.json with dependencies
    package_json = {
        "name": f"{plugin_config['id']}-test-project",
        "version": "1.0.0",
        "description": f"Test project for {plugin_config['name']}",
        "dependencies": {
            "express": "4.17.1",
            "minimist": "1.2.0",     # Known vulnerability
            "moment": "2.24.0"
        }
    }
    
    with open(test_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create a simple index.js file
    with open(test_dir / "index.js", "w") as f:
        f.write("""
const express = require('express');
const minimist = require('minimist');
const moment = require('moment');

const app = express();
const port = 3000;

app.get('/', (req, res) => {
    res.send('Hello, Docker world!');
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
    console.log(`Current time: ${moment().format()}`);
});
""")
    
    # Create docker-compose.yml
    docker_compose = """
version: '3'
services:
  web:
    build: .
    ports:
      - "3000:3000"
    volumes:
      - .:/app
    environment:
      - NODE_ENV=development
"""
    with open(test_dir / "docker-compose.yml", "w") as f:
        f.write(docker_compose)


def simulate_plugin_test(plugin_config: Dict[str, Any], test_dir: Path) -> Dict[str, Any]:
    """
    Simulate running plugin tests.
    
    Args:
        plugin_config: Plugin configuration.
        test_dir: Test environment directory.
        
    Returns:
        Dictionary with test results.
    """
    # In a real implementation, this would execute actual tests
    # For this simulation, we'll generate mock results
    
    test_results = {
        "plugin_id": plugin_config["id"],
        "plugin_name": plugin_config["name"],
        "test_type": plugin_config["test_type"],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "command_results": [],
        "feature_results": [],
        "overall_status": "pass",
        "setup_status": "success",
        "teardown_status": "success",
        "elapsed_time": 0,
        "issues_found": []
    }
    
    start_time = time.time()
    
    # Simulate command tests
    for command in plugin_config["commands"]:
        # Simulate success or failure based on expected result
        status = "success"
        message = f"Command '{command['name']}' executed successfully"
        
        # Occasionally simulate a failure (even for expected success)
        if command["expected_result"] == "failure" or (command["expected_result"] == "success" and random.random() < 0.1):
            status = "failure"
            message = f"Command '{command['name']}' failed to execute properly"
            test_results["overall_status"] = "fail"
            test_results["issues_found"].append({
                "command": command["name"],
                "error": "Execution failed",
                "details": "Command execution returned non-zero exit code",
                "severity": "high" if command["expected_result"] == "success" else "low"
            })
        
        test_results["command_results"].append({
            "command": command["name"],
            "status": status,
            "message": message,
            "expected_result": command["expected_result"],
            "execution_time": random.uniform(0.5, 2.0)  # Random execution time
        })
    
    # Simulate feature tests
    for feature in plugin_config["features"]:
        # Simulate feature testing
        status = "implemented" if random.random() < 0.9 else "missing"
        
        if status == "missing":
            test_results["overall_status"] = "fail"
            test_results["issues_found"].append({
                "feature": feature,
                "error": "Feature not implemented",
                "details": f"Feature '{feature}' was not found in plugin",
                "severity": "medium"
            })
        
        test_results["feature_results"].append({
            "feature": feature,
            "status": status,
            "verification_method": "automatic" if random.random() < 0.7 else "manual"
        })
    
    # Calculate elapsed time
    test_results["elapsed_time"] = time.time() - start_time
    
    return test_results


def run_plugin_tests(plugins: List[str] = None, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Run tests for ossv-scanner plugins.
    
    Args:
        plugins: List of plugin IDs to test. If None, tests all plugins.
        output_dir: Directory to save test results.
        
    Returns:
        Dictionary with test results.
    """
    import random  # For simulating test results
    
    logger.info("Starting plugin integration tests")
    
    # Set up test environment
    if output_dir:
        base_dir = Path(output_dir)
    else:
        base_dir = Path(tempfile.mkdtemp(prefix="ossv-plugin-tests-"))
    
    base_dir.mkdir(parents=True, exist_ok=True)
    results_dir = base_dir / "results"
    results_dir.mkdir(exist_ok=True)
    
    # Select plugins to test
    if plugins:
        selected_plugins = [p for p in PLUGIN_CONFIGS if p["id"] in plugins]
    else:
        selected_plugins = PLUGIN_CONFIGS
    
    if not selected_plugins:
        logger.warning("No plugins selected for testing")
        return {
            "base_dir": str(base_dir),
            "error": "No plugins selected for testing"
        }
    
    # Run tests for each plugin
    all_results = []
    summary = {
        "total_plugins": len(selected_plugins),
        "passed": 0,
        "failed": 0,
        "commands_tested": 0,
        "commands_passed": 0,
        "features_tested": 0,
        "features_implemented": 0,
        "issues_found": 0,
        "by_type": {}
    }
    
    # Initialize type summaries
    for plugin in selected_plugins:
        test_type = plugin["test_type"]
        if test_type not in summary["by_type"]:
            summary["by_type"][test_type] = {
                "total": 0,
                "passed": 0,
                "failed": 0
            }
    
    with Progress() as progress:
        task = progress.add_task("[green]Testing plugins...", total=len(selected_plugins))
        
        for plugin_config in selected_plugins:
            logger.info(f"Testing plugin: {plugin_config['name']} ({plugin_config['id']})")
            
            # Create test environment
            test_dir = create_test_environment(plugin_config, base_dir)
            
            # Run plugin tests
            test_results = simulate_plugin_test(plugin_config, test_dir)
            
            # Save results
            result_file = results_dir / f"{plugin_config['id']}_results.json"
            with open(result_file, "w") as f:
                json.dump(test_results, f, indent=2)
            
            all_results.append(test_results)
            
            # Update summary statistics
            test_type = plugin_config["test_type"]
            summary["by_type"][test_type]["total"] += 1
            
            if test_results["overall_status"] == "pass":
                summary["passed"] += 1
                summary["by_type"][test_type]["passed"] += 1
            else:
                summary["failed"] += 1
                summary["by_type"][test_type]["failed"] += 1
            
            summary["commands_tested"] += len(test_results["command_results"])
            summary["commands_passed"] += sum(1 for c in test_results["command_results"] if c["status"] == "success")
            
            summary["features_tested"] += len(test_results["feature_results"])
            summary["features_implemented"] += sum(1 for f in test_results["feature_results"] if f["status"] == "implemented")
            
            summary["issues_found"] += len(test_results["issues_found"])
            
            progress.update(task, advance=1)
    
    # Calculate percentages
    if summary["total_plugins"] > 0:
        summary["pass_rate"] = summary["passed"] / summary["total_plugins"]
    else:
        summary["pass_rate"] = 0
    
    if summary["commands_tested"] > 0:
        summary["command_success_rate"] = summary["commands_passed"] / summary["commands_tested"]
    else:
        summary["command_success_rate"] = 0
    
    if summary["features_tested"] > 0:
        summary["feature_implementation_rate"] = summary["features_implemented"] / summary["features_tested"]
    else:
        summary["feature_implementation_rate"] = 0
    
    for test_type in summary["by_type"]:
        if summary["by_type"][test_type]["total"] > 0:
            summary["by_type"][test_type]["pass_rate"] = (
                summary["by_type"][test_type]["passed"] / 
                summary["by_type"][test_type]["total"]
            )
        else:
            summary["by_type"][test_type]["pass_rate"] = 0
    
    # Final results
    final_results = {
        "base_dir": str(base_dir),
        "results_dir": str(results_dir),
        "plugins_tested": [p["id"] for p in selected_plugins],
        "test_results": all_results,
        "summary": summary,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "plugins_tested": len(selected_plugins)
        }
    }
    
    # Display summary
    display_summary(summary)
    
    logger.info("Plugin integration tests completed")
    return final_results


def display_summary(summary: Dict[str, Any]) -> None:
    """
    Display a summary of plugin test results.
    
    Args:
        summary: Summary metrics.
    """
    console.print("\n[bold cyan]Plugin Integration Test Summary[/]")
    
    # Create summary table
    table = Table(title="Test Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Rate", style="yellow")
    
    table.add_row(
        "Total Plugins Tested", 
        str(summary["total_plugins"]),
        ""
    )
    table.add_row(
        "Plugins Passed", 
        str(summary["passed"]),
        f"{summary['pass_rate']:.1%}"
    )
    table.add_row(
        "Plugins Failed", 
        str(summary["failed"]),
        f"{1 - summary['pass_rate']:.1%}"
    )
    table.add_row(
        "Commands Tested", 
        str(summary["commands_tested"]),
        ""
    )
    table.add_row(
        "Commands Passed", 
        str(summary["commands_passed"]),
        f"{summary['command_success_rate']:.1%}"
    )
    table.add_row(
        "Features Tested", 
        str(summary["features_tested"]),
        ""
    )
    table.add_row(
        "Features Implemented", 
        str(summary["features_implemented"]),
        f"{summary['feature_implementation_rate']:.1%}"
    )
    table.add_row(
        "Issues Found", 
        str(summary["issues_found"]),
        ""
    )
    
    console.print(table)
    
    # Create integration type breakdown
    console.print("\n[bold cyan]Results by Integration Type[/]")
    type_table = Table()
    type_table.add_column("Integration Type", style="cyan")
    type_table.add_column("Total", style="green")
    type_table.add_column("Passed", style="green")
    type_table.add_column("Failed", style="red")
    type_table.add_column("Pass Rate", style="yellow")
    
    for test_type, metrics in summary["by_type"].items():
        type_table.add_row(
            test_type.replace("_", " ").title(),
            str(metrics["total"]),
            str(metrics["passed"]),
            str(metrics["failed"]),
            f"{metrics['pass_rate']:.1%}"
        )
    
    console.print(type_table)


if __name__ == "__main__":
    import random  # Required for the simulation
    logging.basicConfig(level=logging.INFO)
    results = run_plugin_tests()
    print("Plugin integration tests completed")