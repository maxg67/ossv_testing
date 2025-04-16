"""
Progressive load testing for ossv-scanner.

This module evaluates the scanner's performance under increasing load,
measuring how it handles projects of varying sizes and complexity.
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
import statistics
import random
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Load test configurations with increasing complexity
LOAD_TEST_CONFIGS = [
    {
        "id": "lt-tiny",
        "name": "Tiny Project",
        "description": "A tiny project with few dependencies",
        "npm_deps": 5,
        "python_deps": 3,
        "java_deps": 2,
        "files": 10,
        "concurrency": 1
    },
    {
        "id": "lt-small",
        "name": "Small Project",
        "description": "A small project with typical dependencies",
        "npm_deps": 15,
        "python_deps": 10,
        "java_deps": 5,
        "files": 25,
        "concurrency": 1
    },
    {
        "id": "lt-medium",
        "name": "Medium Project",
        "description": "A medium-sized project with moderate dependencies",
        "npm_deps": 50,
        "python_deps": 25,
        "java_deps": 15,
        "files": 100,
        "concurrency": 2
    },
    {
        "id": "lt-large",
        "name": "Large Project",
        "description": "A large project with many dependencies",
        "npm_deps": 150,
        "python_deps": 75,
        "java_deps": 30,
        "files": 250,
        "concurrency": 4
    },
    {
        "id": "lt-xlarge",
        "name": "Extra Large Project",
        "description": "An extra large project with extensive dependencies",
        "npm_deps": 300,
        "python_deps": 150,
        "java_deps": 50,
        "files": 500,
        "concurrency": 8
    }
]

# Lists of common package names for generating test projects
NPM_PACKAGES = [
    "lodash", "express", "react", "async", "chalk", "moment", "commander",
    "request", "debug", "bluebird", "underscore", "minimist", "mkdirp", "uuid",
    "glob", "axios", "fs-extra", "colors", "prop-types", "webpack", "babel-core",
    "typescript", "jquery", "mocha", "yargs", "socket.io", "eslint", "rimraf",
    "semver", "body-parser", "shelljs", "yeoman-generator", "jest", "cheerio"
]

PYTHON_PACKAGES = [
    "django", "flask", "requests", "numpy", "pandas", "pytest", "pillow",
    "sqlalchemy", "matplotlib", "scipy", "beautifulsoup4", "tensorflow",
    "werkzeug", "jinja2", "cryptography", "psycopg2", "boto3", "nltk", "scikit-learn",
    "certifi", "pyyaml", "six", "urllib3", "setuptools", "wheel", "tqdm", "click",
    "tornado", "lxml", "pytz", "pyjwt", "chardet", "future", "pycparser", "virtualenv"
]

JAVA_PACKAGES = [
    "org.springframework:spring-core", "org.springframework:spring-web", 
    "org.springframework:spring-context", "com.fasterxml.jackson.core:jackson-databind",
    "org.hibernate:hibernate-core", "org.apache.commons:commons-lang3",
    "junit:junit", "org.mockito:mockito-core", "ch.qos.logback:logback-classic",
    "org.slf4j:slf4j-api", "org.projectlombok:lombok", "com.google.guava:guava",
    "com.google.code.gson:gson", "org.apache.httpcomponents:httpclient",
    "mysql:mysql-connector-java", "org.postgresql:postgresql", "io.jsonwebtoken:jjwt",
    "org.apache.tomcat.embed:tomcat-embed-core", "org.springframework.boot:spring-boot",
    "org.springframework.boot:spring-boot-starter-web"
]


def generate_package_json(num_deps: int) -> Dict[str, Any]:
    """
    Generate a package.json file with the specified number of dependencies.
    
    Args:
        num_deps: Number of dependencies to include.
        
    Returns:
        Dictionary representing the package.json content.
    """
    # Select random dependencies
    deps = random.sample(NPM_PACKAGES, min(num_deps, len(NPM_PACKAGES)))
    
    # Generate dependency object
    dependencies = {}
    for dep in deps:
        # Generate random version
        major = random.randint(0, 10)
        minor = random.randint(0, 20)
        patch = random.randint(0, 99)
        dependencies[dep] = f"{major}.{minor}.{patch}"
    
    # Create package.json structure
    return {
        "name": f"load-test-npm-{num_deps}",
        "version": "1.0.0",
        "description": f"Load test with {num_deps} npm dependencies",
        "dependencies": dependencies
    }


def generate_requirements_txt(num_deps: int) -> str:
    """
    Generate a requirements.txt file with the specified number of dependencies.
    
    Args:
        num_deps: Number of dependencies to include.
        
    Returns:
        String content for requirements.txt.
    """
    # Select random dependencies
    deps = random.sample(PYTHON_PACKAGES, min(num_deps, len(PYTHON_PACKAGES)))
    
    # Generate requirements lines
    lines = []
    for dep in deps:
        # Generate random version
        major = random.randint(0, 5)
        minor = random.randint(0, 20)
        patch = random.randint(0, 99)
        lines.append(f"{dep}=={major}.{minor}.{patch}")
    
    return "\n".join(lines)


def generate_pom_xml(num_deps: int) -> str:
    """
    Generate a pom.xml file with the specified number of dependencies.
    
    Args:
        num_deps: Number of dependencies to include.
        
    Returns:
        String content for pom.xml.
    """
    # Select random dependencies
    deps = random.sample(JAVA_PACKAGES, min(num_deps, len(JAVA_PACKAGES)))
    
    # Generate dependency XML
    dependency_xml = []
    for dep in deps:
        # Split group and artifact IDs
        parts = dep.split(":")
        group_id = parts[0]
        artifact_id = parts[1]
        
        # Generate random version
        major = random.randint(0, 5)
        minor = random.randint(0, 20)
        patch = random.randint(0, 99)
        
        # Create dependency XML
        dependency_xml.append(f"""        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
            <version>{major}.{minor}.{patch}</version>
        </dependency>""")
    
    # Create pom.xml structure
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>load-test-java-{num_deps}</artifactId>
    <version>1.0.0</version>

    <dependencies>
{os.linesep.join(dependency_xml)}
    </dependencies>
</project>"""


def create_load_test_project(config: Dict[str, Any], base_dir: Path) -> Path:
    """
    Create a test project with the specified configuration.
    
    Args:
        config: Load test configuration.
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created project.
    """
    # Create project directory
    project_dir = base_dir / config["id"]
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package.json with specified dependencies
    with open(project_dir / "package.json", "w") as f:
        json.dump(generate_package_json(config["npm_deps"]), f, indent=2)
    
    # Create requirements.txt with specified dependencies
    with open(project_dir / "requirements.txt", "w") as f:
        f.write(generate_requirements_txt(config["python_deps"]))
    
    # Create pom.xml with specified dependencies
    with open(project_dir / "pom.xml", "w") as f:
        f.write(generate_pom_xml(config["java_deps"]))
    
    # Create additional random files to simulate project complexity
    for i in range(config["files"]):
        # Determine file type
        file_type = random.choice(["js", "py", "java", "md", "txt", "json", "html", "css"])
        
        # Create random directory structure
        depth = random.randint(0, 3)
        if depth > 0:
            path_parts = []
            for _ in range(depth):
                path_parts.append(f"dir_{random.randint(1, 10)}")
            
            dir_path = project_dir
            for part in path_parts:
                dir_path = dir_path / part
                dir_path.mkdir(exist_ok=True)
            
            file_path = dir_path / f"file_{i}.{file_type}"
        else:
            file_path = project_dir / f"file_{i}.{file_type}"
        
        # Create random file content (not meaningful, just to have files)
        with open(file_path, "w") as f:
            f.write(f"// Test file {i}\n")
            f.write(f"// This is a random file for load testing\n")
            
            # Add some random content based on file type
            if file_type == "js":
                f.write("console.log('Hello, world!');\n")
            elif file_type == "py":
                f.write("print('Hello, world!')\n")
            elif file_type == "java":
                f.write("System.out.println(\"Hello, world!\");\n")
    
    return project_dir


def run_scanner(project_path: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Run ossv-scanner on a project and measure performance metrics.
    
    Args:
        project_path: Path to the project.
        output_dir: Directory to save scanner output.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_path.name}-results.json"
    
    metrics = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "cpu_usage": [],
        "memory_usage": [],
        "success": False,
        "error": None
    }
    
    # Process to monitor
    scanner_process = None
    
    # Thread for monitoring resource usage
    stop_monitoring = threading.Event()
    
    def monitor_resources():
        """Monitor CPU and memory usage of the scanner process."""
        while not stop_monitoring.is_set() and scanner_process and scanner_process.poll() is None:
            try:
                process = psutil.Process(scanner_process.pid)
                
                # Get CPU and memory usage
                cpu_percent = process.cpu_percent(interval=0.1)
                memory_info = process.memory_info()
                
                metrics["cpu_usage"].append(cpu_percent)
                metrics["memory_usage"].append(memory_info.rss / (1024 * 1024))  # Convert to MB
                
                time.sleep(0.5)  # Sample every 0.5 seconds
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process might have ended
                break
    
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
            # Start resource monitoring
            monitor_thread = threading.Thread(target=monitor_resources)
            monitor_thread.daemon = True
            
            # Try to run as installed package
            scanner_process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            monitor_thread.start()
            
            stdout, stderr = scanner_process.communicate()
            
            if scanner_process.returncode != 0:
                logger.warning(f"Scanner returned non-zero exit code: {scanner_process.returncode}")
                logger.warning(f"Error output: {stderr.decode('utf-8')}")
                metrics["error"] = stderr.decode('utf-8')
            else:
                metrics["success"] = True
                
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            scan_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_path)
            ]
            
            scanner_process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if not monitor_thread.is_alive():
                monitor_thread = threading.Thread(target=monitor_resources)
                monitor_thread.daemon = True
                monitor_thread.start()
                
            stdout, stderr = scanner_process.communicate()
            
            if scanner_process.returncode != 0:
                logger.warning(f"Scanner returned non-zero exit code: {scanner_process.returncode}")
                logger.warning(f"Error output: {stderr.decode('utf-8')}")
                metrics["error"] = stderr.decode('utf-8')
            else:
                metrics["success"] = True
        
        # Record end time and duration
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        
        # Stop monitoring
        stop_monitoring.set()
        if monitor_thread.is_alive():
            monitor_thread.join(timeout=1.0)
        
        logger.info(f"Scanner completed in {metrics['duration']:.2f} seconds. Results at {output_path}")
        
        # Calculate resource usage statistics
        if metrics["cpu_usage"]:
            metrics["avg_cpu"] = statistics.mean(metrics["cpu_usage"])
            metrics["max_cpu"] = max(metrics["cpu_usage"])
        else:
            metrics["avg_cpu"] = 0.0
            metrics["max_cpu"] = 0.0
            
        if metrics["memory_usage"]:
            metrics["avg_memory_mb"] = statistics.mean(metrics["memory_usage"])
            metrics["max_memory_mb"] = max(metrics["memory_usage"])
            metrics["min_memory_mb"] = min(metrics["memory_usage"])
        else:
            metrics["avg_memory_mb"] = 0.0
            metrics["max_memory_mb"] = 0.0
            metrics["min_memory_mb"] = 0.0
        
        return output_path, metrics
        
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        metrics["error"] = str(e)
        
        # Stop monitoring
        stop_monitoring.set()
        
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path, metrics


def run_concurrent_tests(config: Dict[str, Any], base_dir: Path, output_dir: Path) -> Dict[str, Any]:
    """
    Run multiple concurrent scanner tests.
    
    Args:
        config: Load test configuration.
        base_dir: Base directory for test projects.
        output_dir: Directory to save scanner output.
        
    Returns:
        Dictionary with test results.
    """
    concurrency = config["concurrency"]
    projects = []
    
    # Create test projects
    for i in range(concurrency):
        # Create a separate project for each concurrent test
        project_config = config.copy()
        project_config["id"] = f"{config['id']}-concurrent-{i+1}"
        project_dir = create_load_test_project(project_config, base_dir)
        projects.append(project_dir)
    
    # Run tests concurrently
    results = []
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        # Submit all tasks
        future_to_project = {
            executor.submit(run_scanner, project, output_dir): project
            for project in projects
        }
        
        # Process as they complete
        for future in as_completed(future_to_project):
            project = future_to_project[future]
            try:
                output_path, metrics = future.result()
                results.append({
                    "project": project.name,
                    "output_path": str(output_path),
                    "metrics": metrics
                })
            except Exception as e:
                logger.error(f"Error in concurrent test for {project}: {str(e)}")
                results.append({
                    "project": project.name,
                    "error": str(e)
                })
    
    end_time = time.time()
    total_duration = end_time - start_time
    
    # Calculate aggregate metrics
    successful_tests = sum(1 for r in results if r.get("metrics", {}).get("success", False))
    if successful_tests > 0:
        avg_duration = sum(r["metrics"]["duration"] for r in results if r.get("metrics", {}).get("success", False)) / successful_tests
        max_duration = max((r["metrics"]["duration"] for r in results if r.get("metrics", {}).get("success", False)), default=0)
        min_duration = min((r["metrics"]["duration"] for r in results if r.get("metrics", {}).get("success", False)), default=0)
    else:
        avg_duration = 0
        max_duration = 0
        min_duration = 0
    
    # Return results
    return {
        "concurrency": concurrency,
        "projects": [str(p) for p in projects],
        "results": results,
        "aggregate_metrics": {
            "total_duration": total_duration,
            "avg_duration": avg_duration,
            "max_duration": max_duration,
            "min_duration": min_duration,
            "successful_tests": successful_tests,
            "failed_tests": concurrency - successful_tests
        }
    }


def analyze_results(test_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze load test results.
    
    Args:
        test_results: Dictionary of test results by config ID.
        
    Returns:
        Analysis results.
    """
    analysis = {
        "overall": {
            "total_tests": len(test_results),
            "successful_tests": 0,
            "failed_tests": 0,
            "avg_duration": 0.0
        },
        "scaling": {
            "projects": [],
            "durations": [],
            "success_rates": [],
            "memory_usage": [],
            "cpu_usage": []
        },
        "concurrency": {
            "levels": [],
            "throughput": [],  # Tests per second
            "efficiency": []   # Relative efficiency compared to single-threaded
        }
    }
    
    # Process each test result
    successful_durations = []
    
    for config_id, result in test_results.items():
        config = result["config"]
        metrics = result["metrics"]
        
        # Count success/failure
        if metrics.get("success", False):
            analysis["overall"]["successful_tests"] += 1
            successful_durations.append(metrics["duration"])
        else:
            analysis["overall"]["failed_tests"] += 1
        
        # Add data points for scaling analysis
        project_size = config["npm_deps"] + config["python_deps"] + config["java_deps"]
        success_rate = 1.0 if metrics.get("success", False) else 0.0
        
        analysis["scaling"]["projects"].append(project_size)
        analysis["scaling"]["durations"].append(metrics.get("duration", 0))
        analysis["scaling"]["success_rates"].append(success_rate)
        analysis["scaling"]["memory_usage"].append(metrics.get("max_memory_mb", 0))
        analysis["scaling"]["cpu_usage"].append(metrics.get("max_cpu", 0))
        
        # Process concurrency results
        if "concurrent_results" in result:
            concurrent = result["concurrent_results"]
            concurrency_level = concurrent["concurrency"]
            agg_metrics = concurrent["aggregate_metrics"]
            
            # Calculate throughput and efficiency
            throughput = concurrent["aggregate_metrics"]["successful_tests"] / concurrent["aggregate_metrics"]["total_duration"] if concurrent["aggregate_metrics"]["total_duration"] > 0 else 0
            
            # Efficiency is throughput per concurrency level relative to single-threaded
            # (perfect scaling would maintain an efficiency of 1.0)
            single_throughput = 1.0 / metrics["duration"] if metrics["duration"] > 0 else 0
            efficiency = (throughput / concurrency_level) / single_throughput if single_throughput > 0 else 0
            
            analysis["concurrency"]["levels"].append(concurrency_level)
            analysis["concurrency"]["throughput"].append(throughput)
            analysis["concurrency"]["efficiency"].append(efficiency)
    
    # Calculate overall average duration
    if successful_durations:
        analysis["overall"]["avg_duration"] = sum(successful_durations) / len(successful_durations)
    
    return analysis


def generate_plots(analysis: Dict[str, Any], output_dir: Path) -> Dict[str, Path]:
    """
    Generate performance analysis plots.
    
    Args:
        analysis: Analysis results.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # 1. Project Size vs Duration Plot
    plt.figure(figsize=(10, 6))
    plt.scatter(analysis["scaling"]["projects"], analysis["scaling"]["durations"], alpha=0.7)
    
    # Add trend line
    if len(analysis["scaling"]["projects"]) > 1:
        z = np.polyfit(analysis["scaling"]["projects"], analysis["scaling"]["durations"], 1)
        p = np.poly1d(z)
        plt.plot(analysis["scaling"]["projects"], p(analysis["scaling"]["projects"]), "r--", alpha=0.7)
    
    plt.title("Scanner Performance vs. Project Size")
    plt.xlabel("Project Size (Number of Dependencies)")
    plt.ylabel("Scan Duration (seconds)")
    plt.grid(True)
    
    size_vs_duration_path = output_dir / "size_vs_duration.png"
    plt.savefig(size_vs_duration_path)
    plt.close()
    plots["size_vs_duration"] = size_vs_duration_path
    
    # 2. Project Size vs Resource Usage Plot
    plt.figure(figsize=(10, 6))
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    # CPU usage on left y-axis
    color = 'tab:blue'
    ax1.set_xlabel("Project Size (Number of Dependencies)")
    ax1.set_ylabel("CPU Usage (%)", color=color)
    ax1.scatter(analysis["scaling"]["projects"], analysis["scaling"]["cpu_usage"], color=color, alpha=0.7)
    ax1.tick_params(axis='y', labelcolor=color)
    
    # Memory usage on right y-axis
    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel("Memory Usage (MB)", color=color)
    ax2.scatter(analysis["scaling"]["projects"], analysis["scaling"]["memory_usage"], color=color, alpha=0.7)
    ax2.tick_params(axis='y', labelcolor=color)
    
    plt.title("Resource Usage vs. Project Size")
    plt.grid(True)
    
    resource_usage_path = output_dir / "resource_usage.png"
    plt.savefig(resource_usage_path)
    plt.close()
    plots["resource_usage"] = resource_usage_path
    
    # 3. Concurrency Performance Plot (if concurrency tests were run)
    if analysis["concurrency"]["levels"]:
        plt.figure(figsize=(10, 6))
        
        plt.plot(analysis["concurrency"]["levels"], analysis["concurrency"]["throughput"], 'o-', label="Throughput")
        
        # Add ideal scaling line
        if len(analysis["concurrency"]["levels"]) > 1:
            ideal_throughput = [t * l for l, t in zip(analysis["concurrency"]["levels"], [analysis["concurrency"]["throughput"][0] / analysis["concurrency"]["levels"][0]] * len(analysis["concurrency"]["levels"]))]
            plt.plot(analysis["concurrency"]["levels"], ideal_throughput, 'r--', alpha=0.5, label="Ideal Scaling")
        
        plt.title("Scanner Throughput vs. Concurrency")
        plt.xlabel("Concurrency Level")
        plt.ylabel("Throughput (scans/second)")
        plt.grid(True)
        plt.legend()
        
        concurrency_path = output_dir / "concurrency_performance.png"
        plt.savefig(concurrency_path)
        plt.close()
        plots["concurrency_performance"] = concurrency_path
        
        # 4. Concurrency Efficiency Plot
        plt.figure(figsize=(10, 6))
        plt.plot(analysis["concurrency"]["levels"], analysis["concurrency"]["efficiency"], 'o-')
        plt.axhline(y=1.0, color='r', linestyle='--', alpha=0.5, label="Perfect Scaling")
        plt.title("Concurrency Efficiency")
        plt.xlabel("Concurrency Level")
        plt.ylabel("Relative Efficiency")
        plt.grid(True)
        plt.legend()
        
        efficiency_path = output_dir / "concurrency_efficiency.png"
        plt.savefig(efficiency_path)
        plt.close()
        plots["concurrency_efficiency"] = efficiency_path
    
    return plots


def run_test(duration: int = 60, basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run load tests with increasing project sizes.
    
    Args:
        duration: Maximum test duration in seconds (approximate).
        basic: Whether to run a basic subset of tests.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting load testing")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-load-tests-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    plots_dir = base_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Select test configurations
    if basic:
        # Use a minimal set for basic testing
        selected_configs = [LOAD_TEST_CONFIGS[0], LOAD_TEST_CONFIGS[2]]  # Tiny and Medium
    elif comprehensive:
        # Use all configs for comprehensive testing
        selected_configs = LOAD_TEST_CONFIGS
    else:
        # Default to a standard set
        selected_configs = [LOAD_TEST_CONFIGS[0], LOAD_TEST_CONFIGS[1], LOAD_TEST_CONFIGS[2]]  # Tiny, Small, Medium
    
    # Adjust based on duration
    if duration < 30 and not basic:
        logger.info(f"Short duration ({duration}s) - reducing test set")
        selected_configs = selected_configs[:2]  # Use only the smallest configs
    elif duration > 300 and not comprehensive:
        logger.info(f"Long duration ({duration}s) - including larger test cases")
        if LOAD_TEST_CONFIGS[3] not in selected_configs:
            selected_configs.append(LOAD_TEST_CONFIGS[3])  # Add Large config
    
    test_results = {}
    
    with Progress() as progress:
        task1 = progress.add_task("[green]Creating test projects...", total=len(selected_configs))
        task2 = progress.add_task("[cyan]Running load tests...", total=len(selected_configs))
        task3 = progress.add_task("[magenta]Running concurrent tests...", total=len(selected_configs))
        
        # First, create all test projects
        for config in selected_configs:
            logger.info(f"Creating project: {config['name']} ({config['id']})")
            project_dir = create_load_test_project(config, base_dir)
            config["project_dir"] = project_dir
            progress.update(task1, advance=1)
        
        # Now run the tests
        start_time = time.time()
        for config in selected_configs:
            # Run single-threaded test
            logger.info(f"Testing {config['name']} ({config['id']})")
            output_path, metrics = run_scanner(config["project_dir"], output_dir)
            
            test_results[config["id"]] = {
                "config": config,
                "output_path": str(output_path),
                "metrics": metrics
            }
            
            progress.update(task2, advance=1)
            
            # Run concurrent test if concurrency > 1
            if config["concurrency"] > 1:
                logger.info(f"Running concurrent test with {config['concurrency']} workers")
                concurrent_results = run_concurrent_tests(config, base_dir, output_dir)
                test_results[config["id"]]["concurrent_results"] = concurrent_results
            
            progress.update(task3, advance=1)
            
            # Check if we've exceeded the duration limit
            elapsed = time.time() - start_time
            if elapsed > duration and len(test_results) >= 2:  # Ensure we have at least 2 data points
                logger.info(f"Duration limit reached ({elapsed:.1f}s > {duration}s), stopping tests")
                break
    
    # Analyze results
    logger.info("Analyzing test results")
    analysis = analyze_results(test_results)
    
    # Generate plots
    logger.info("Generating performance plots")
    plots = generate_plots(analysis, plots_dir)
    
    # Combine results
    final_results = {
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir),
            "plots_dir": str(plots_dir)
        },
        "configurations": [c for c in selected_configs],
        "test_results": test_results,
        "analysis": analysis,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "num_configs": len(selected_configs),
            "actual_duration": time.time() - start_time
        }
    }
    
    # Display summary
    display_summary(analysis, test_results)
    
    logger.info("Load testing completed")
    return final_results


def display_summary(analysis: Dict[str, Any], test_results: Dict[str, Dict[str, Any]]) -> None:
    """
    Display a summary of load test results.
    
    Args:
        analysis: Analysis results.
        test_results: Test results by config ID.
    """
    console.print("\n[bold cyan]Load Test Summary[/]")
    
    # Create overall summary table
    table = Table(title="Scanner Performance Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Tests", str(analysis["overall"]["total_tests"]))
    table.add_row("Successful Tests", str(analysis["overall"]["successful_tests"]))
    table.add_row("Failed Tests", str(analysis["overall"]["failed_tests"]))
    table.add_row("Average Duration", f"{analysis['overall']['avg_duration']:.2f} seconds")
    
    console.print(table)
    
    # Create performance by project size table
    console.print("\n[bold cyan]Performance by Project Size[/]")
    size_table = Table()
    size_table.add_column("Project", style="cyan")
    size_table.add_column("Dependencies", style="green")
    size_table.add_column("Duration (s)", style="yellow")
    size_table.add_column("Memory (MB)", style="magenta")
    size_table.add_column("CPU (%)", style="blue")
    
    # Sort test results by project size
    sorted_results = sorted(
        test_results.items(),
        key=lambda x: x[1]["config"]["npm_deps"] + x[1]["config"]["python_deps"] + x[1]["config"]["java_deps"]
    )
    
    for config_id, result in sorted_results:
        config = result["config"]
        metrics = result["metrics"]
        
        total_deps = config["npm_deps"] + config["python_deps"] + config["java_deps"]
        
        size_table.add_row(
            config["name"],
            str(total_deps),
            f"{metrics.get('duration', 0):.2f}",
            f"{metrics.get('max_memory_mb', 0):.1f}",
            f"{metrics.get('max_cpu', 0):.1f}"
        )
    
    console.print(size_table)
    
    # Create concurrency performance table if available
    has_concurrency = any("concurrent_results" in result for result in test_results.values())
    
    if has_concurrency:
        console.print("\n[bold cyan]Concurrency Performance[/]")
        conc_table = Table()
        conc_table.add_column("Concurrency", style="cyan")
        conc_table.add_column("Throughput (scans/s)", style="green")
        conc_table.add_column("Efficiency", style="yellow")
        conc_table.add_column("Speedup", style="magenta")
        
        # Get concurrency data
        if analysis["concurrency"]["levels"]:
            for i, level in enumerate(analysis["concurrency"]["levels"]):
                conc_table.add_row(
                    str(level),
                    f"{analysis['concurrency']['throughput'][i]:.3f}",
                    f"{analysis['concurrency']['efficiency'][i]:.2f}",
                    f"{analysis['concurrency']['throughput'][i] / analysis['concurrency']['throughput'][0] if i > 0 and analysis['concurrency']['throughput'][0] > 0 else 1.0:.2f}x"
                )
            
            console.print(conc_table)
    
    # Overall assessment
    if analysis["overall"]["successful_tests"] / analysis["overall"]["total_tests"] >= 0.8:
        console.print("[bold green]Overall Assessment:[/] Scanner performs reliably under load")
    elif analysis["overall"]["successful_tests"] / analysis["overall"]["total_tests"] >= 0.5:
        console.print("[bold yellow]Overall Assessment:[/] Scanner has mixed performance under load")
    else:
        console.print("[bold red]Overall Assessment:[/] Scanner struggles under load")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_test(duration=120)
    print(json.dumps(results, indent=2))
