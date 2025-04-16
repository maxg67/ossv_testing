"""
Resource usage profiling for ossv-scanner.

This module profiles the memory and CPU usage of the scanner in detail,
providing insights into the efficiency and resource requirements.
"""

import os
import time
import logging
import tempfile
import json
import subprocess
import shutil
import platform
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import statistics

import psutil
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Test project configurations for resource profiling
PROFILE_CONFIGS = [
    {
        "id": "resource-small",
        "name": "Small Project",
        "description": "Small project with few dependencies",
        "npm_deps": 10,
        "python_deps": 5,
        "java_deps": 3,
        "sampling_rate": 0.1  # seconds between samples
    },
    {
        "id": "resource-medium",
        "name": "Medium Project",
        "description": "Medium project with moderate dependencies",
        "npm_deps": 50,
        "python_deps": 25,
        "java_deps": 10,
        "sampling_rate": 0.1
    },
    {
        "id": "resource-large",
        "name": "Large Project",
        "description": "Large project with many dependencies",
        "npm_deps": 200,
        "python_deps": 100,
        "java_deps": 50,
        "sampling_rate": 0.1
    },
    {
        "id": "resource-iterations",
        "name": "Multiple Iterations",
        "description": "Multiple iterations to test memory leaks",
        "npm_deps": 30,
        "python_deps": 15,
        "java_deps": 5,
        "iterations": 5,
        "sampling_rate": 0.1
    }
]

# Reference data for creating test projects
TEST_NPM_PACKAGES = [
    "lodash", "express", "react", "async", "chalk", "moment", "commander",
    "request", "debug", "bluebird", "underscore", "minimist", "mkdirp", "uuid",
    "glob", "axios", "fs-extra", "colors", "prop-types", "webpack", "babel-core",
    "typescript", "jquery", "mocha", "yargs", "socket.io", "eslint", "rimraf",
    "semver", "body-parser", "shelljs", "yeoman-generator", "jest", "cheerio"
]

TEST_PYTHON_PACKAGES = [
    "django", "flask", "requests", "numpy", "pandas", "pytest", "pillow",
    "sqlalchemy", "matplotlib", "scipy", "beautifulsoup4", "tensorflow",
    "werkzeug", "jinja2", "cryptography", "psycopg2", "boto3", "nltk", "scikit-learn",
    "certifi", "pyyaml", "six", "urllib3", "setuptools", "wheel", "tqdm", "click",
    "tornado", "lxml", "pytz", "pyjwt", "chardet", "future", "pycparser", "virtualenv"
]

TEST_JAVA_PACKAGES = [
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


def create_test_project(config: Dict[str, Any], base_dir: Path) -> Path:
    """
    Create a test project with specified configuration.
    
    Args:
        config: Test configuration.
        base_dir: Base directory for projects.
        
    Returns:
        Path to created project.
    """
    project_dir = base_dir / config["id"]
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Sample packages
    npm_packages = random.sample(TEST_NPM_PACKAGES, min(config["npm_deps"], len(TEST_NPM_PACKAGES)))
    if config["npm_deps"] > len(TEST_NPM_PACKAGES):
        # Add generated packages for large numbers
        for i in range(config["npm_deps"] - len(TEST_NPM_PACKAGES)):
            npm_packages.append(f"generated-pkg-{i}")
    
    python_packages = random.sample(TEST_PYTHON_PACKAGES, min(config["python_deps"], len(TEST_PYTHON_PACKAGES)))
    if config["python_deps"] > len(TEST_PYTHON_PACKAGES):
        # Add generated packages for large numbers
        for i in range(config["python_deps"] - len(TEST_PYTHON_PACKAGES)):
            python_packages.append(f"generated-python-pkg-{i}")
    
    java_packages = random.sample(TEST_JAVA_PACKAGES, min(config["java_deps"], len(TEST_JAVA_PACKAGES)))
    if config["java_deps"] > len(TEST_JAVA_PACKAGES):
        # Add generated packages for large numbers
        for i in range(config["java_deps"] - len(TEST_JAVA_PACKAGES)):
            java_packages.append(f"org.example:generated-java-pkg-{i}")
    
    # Create package.json
    deps = {}
    for pkg in npm_packages:
        if ":" in pkg:  # Handle any generated package names with colons
            pkg = pkg.split(":")[1]
        version = f"{random.randint(1, 10)}.{random.randint(0, 20)}.{random.randint(0, 99)}"
        deps[pkg] = version
    
    package_json = {
        "name": f"resource-test-{config['id']}",
        "version": "1.0.0",
        "description": config["description"],
        "dependencies": deps
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create requirements.txt
    requirements = []
    for pkg in python_packages:
        if ":" in pkg:  # Handle any generated package names with colons
            pkg = pkg.split(":")[1]
        version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 99)}"
        requirements.append(f"{pkg}=={version}")
    
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("\n".join(requirements))
    
    # Create pom.xml
    dep_xml = []
    for pkg in java_packages:
        if ":" in pkg:
            group_id, artifact_id = pkg.split(":")
        else:
            group_id = "org.example"
            artifact_id = pkg
        
        version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 99)}"
        
        dep_xml.append(f"""        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
            <version>{version}</version>
        </dependency>""")
    
    pom_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>resource-test-{config['id']}</artifactId>
    <version>1.0.0</version>

    <dependencies>
{os.linesep.join(dep_xml)}
    </dependencies>
</project>"""
    
    with open(project_dir / "pom.xml", "w") as f:
        f.write(pom_xml)
    
    return project_dir


def profile_process(process, sampling_rate: float) -> Dict[str, Any]:
    """
    Profile a process for resource usage.
    
    Args:
        process: Process to profile.
        sampling_rate: Seconds between samples.
        
    Returns:
        Dictionary of resource usage data.
    """
    profile_data = {
        "timestamp": [],
        "cpu_percent": [],
        "memory_usage": [],
        "io_read_bytes": [],
        "io_write_bytes": [],
        "thread_count": [],
        "is_running": True
    }
    
    # Create process object for monitoring
    try:
        p = psutil.Process(process.pid)
        
        # Get initial I/O counters
        try:
            io_counters_start = p.io_counters()
            has_io_counters = True
        except (psutil.AccessDenied, AttributeError):
            has_io_counters = False
        
        # Profile until process ends
        start_time = time.time()
        
        while process.poll() is None:
            try:
                # Record timestamp
                current_time = time.time()
                profile_data["timestamp"].append(current_time - start_time)
                
                # CPU usage
                profile_data["cpu_percent"].append(p.cpu_percent())
                
                # Memory usage (in MB)
                memory_info = p.memory_info()
                profile_data["memory_usage"].append(memory_info.rss / (1024 * 1024))
                
                # Thread count
                profile_data["thread_count"].append(p.num_threads())
                
                # I/O counters
                if has_io_counters:
                    try:
                        io_counters = p.io_counters()
                        profile_data["io_read_bytes"].append(io_counters.read_bytes)
                        profile_data["io_write_bytes"].append(io_counters.write_bytes)
                    except (psutil.AccessDenied, AttributeError):
                        profile_data["io_read_bytes"].append(None)
                        profile_data["io_write_bytes"].append(None)
                
                # Sleep until next sample
                time.sleep(sampling_rate)
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                break
        
        profile_data["is_running"] = False
        
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        profile_data["is_running"] = False
    
    return profile_data


def run_scanner_with_profiling(project_dir: Path, output_dir: Path, sampling_rate: float) -> Tuple[Path, Dict[str, Any]]:
    """
    Run ossv-scanner with detailed resource profiling.
    
    Args:
        project_dir: Test project directory.
        output_dir: Directory for results.
        sampling_rate: Seconds between resource usage samples.
        
    Returns:
        Tuple of (output path, profiling data).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-results.json"
    
    profile_data = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "exit_code": None,
        "success": False,
        "error": None,
        "resource_usage": None
    }
    
    try:
        # Run the scanner
        logger.info(f"Running ossv-scanner on {project_dir} with resource profiling")
        
        scan_cmd = [
            "ossv-scan",
            "--output-format", "json",
            "--output-path", str(output_path),
            str(project_dir)
        ]
        
        try:
            # Try to run as installed package
            process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Profile the process
            resource_usage = profile_process(process, sampling_rate)
            profile_data["resource_usage"] = resource_usage
            
            # Wait for process to complete
            stdout, stderr = process.communicate()
            profile_data["exit_code"] = process.returncode
            
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            scan_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_dir)
            ]
            
            process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Profile the process
            resource_usage = profile_process(process, sampling_rate)
            profile_data["resource_usage"] = resource_usage
            
            # Wait for process to complete
            stdout, stderr = process.communicate()
            profile_data["exit_code"] = process.returncode
        
        # Record end time and duration
        profile_data["end_time"] = time.time()
        profile_data["duration"] = profile_data["end_time"] - profile_data["start_time"]
        
        # Check if scan was successful
        profile_data["success"] = (profile_data["exit_code"] == 0 and output_path.exists())
        
        logger.info(f"Scanner completed with exit code {profile_data['exit_code']}. Results at {output_path}")
        
        return output_path, profile_data
        
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        profile_data["end_time"] = time.time()
        profile_data["duration"] = profile_data["end_time"] - profile_data["start_time"]
        profile_data["error"] = str(e)
        
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path, profile_data


def run_multiple_iterations(config: Dict[str, Any], project_dir: Path, output_dir: Path) -> List[Dict[str, Any]]:
    """
    Run multiple iterations of the scanner on the same project.
    
    Args:
        config: Test configuration.
        project_dir: Test project directory.
        output_dir: Directory for results.
        
    Returns:
        List of profiling data for each iteration.
    """
    iterations = config.get("iterations", 1)
    sampling_rate = config.get("sampling_rate", 0.1)
    results = []
    
    logger.info(f"Running {iterations} iterations on {project_dir}")
    
    for i in range(iterations):
        iteration_output_dir = output_dir / f"iteration_{i+1}"
        iteration_output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Starting iteration {i+1}/{iterations}")
        output_path, profile_data = run_scanner_with_profiling(project_dir, iteration_output_dir, sampling_rate)
        
        profile_data["iteration"] = i + 1
        results.append(profile_data)
        
        # Short pause between iterations
        time.sleep(1.0)
    
    return results


def analyze_profile_data(profile_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze resource profiling data.
    
    Args:
        profile_data: Resource usage profile data.
        
    Returns:
        Analysis results.
    """
    resource_usage = profile_data.get("resource_usage", {})
    
    # Initialize analysis dictionary
    analysis = {
        "cpu": {
            "average": 0,
            "peak": 0,
            "samples": len(resource_usage.get("cpu_percent", [])),
        },
        "memory": {
            "average_mb": 0,
            "peak_mb": 0,
            "final_mb": 0,
            "growth_rate": 0,  # MB per second
        },
        "io": {
            "total_read_mb": 0,
            "total_write_mb": 0,
            "read_rate": 0,    # MB per second
            "write_rate": 0,   # MB per second
        },
        "threads": {
            "average": 0,
            "peak": 0,
        },
        "duration": profile_data.get("duration", 0),
        "exit_code": profile_data.get("exit_code", None),
        "warnings": []
    }
    
    # CPU analysis
    cpu_data = resource_usage.get("cpu_percent", [])
    if cpu_data:
        analysis["cpu"]["average"] = statistics.mean(cpu_data)
        analysis["cpu"]["peak"] = max(cpu_data)
        
        # Check for sustained high CPU usage
        if analysis["cpu"]["average"] > 90:
            analysis["warnings"].append("Sustained high CPU usage detected")
    
    # Memory analysis
    memory_data = resource_usage.get("memory_usage", [])
    if memory_data:
        analysis["memory"]["average_mb"] = statistics.mean(memory_data)
        analysis["memory"]["peak_mb"] = max(memory_data)
        analysis["memory"]["final_mb"] = memory_data[-1] if memory_data else 0
        
        # Calculate memory growth rate
        if len(memory_data) > 1 and resource_usage.get("timestamp", []):
            # Simple linear regression for growth rate
            time_data = resource_usage["timestamp"]
            
            # Ensure data lengths match
            min_len = min(len(time_data), len(memory_data))
            time_data = time_data[:min_len]
            memory_data = memory_data[:min_len]
            
            if len(time_data) > 1:
                # Calculate slope (MB per second)
                x = np.array(time_data)
                y = np.array(memory_data)
                A = np.vstack([x, np.ones(len(x))]).T
                m, c = np.linalg.lstsq(A, y, rcond=None)[0]
                
                analysis["memory"]["growth_rate"] = m
                
                # Warning for potential memory leak
                if m > 5.0:  # 5 MB/s is quite high
                    analysis["warnings"].append("Potential memory leak detected")
        
        # Warning for high memory usage
        if analysis["memory"]["peak_mb"] > 1000:  # 1 GB
            analysis["warnings"].append("High peak memory usage detected")
    
    # I/O analysis
    io_read = resource_usage.get("io_read_bytes", [])
    io_write = resource_usage.get("io_write_bytes", [])
    
    if io_read and io_write and all(x is not None for x in io_read) and all(x is not None for x in io_write):
        # Convert bytes to MB
        total_read_mb = (io_read[-1] - io_read[0]) / (1024 * 1024) if len(io_read) > 1 else 0
        total_write_mb = (io_write[-1] - io_write[0]) / (1024 * 1024) if len(io_write) > 1 else 0
        
        analysis["io"]["total_read_mb"] = total_read_mb
        analysis["io"]["total_write_mb"] = total_write_mb
        
        # Calculate I/O rates
        duration = profile_data.get("duration", 0)
        if duration > 0:
            analysis["io"]["read_rate"] = total_read_mb / duration
            analysis["io"]["write_rate"] = total_write_mb / duration
    
    # Thread analysis
    thread_data = resource_usage.get("thread_count", [])
    if thread_data:
        analysis["threads"]["average"] = statistics.mean(thread_data)
        analysis["threads"]["peak"] = max(thread_data)
        
        # Warning for high thread count
        if analysis["threads"]["peak"] > 50:
            analysis["warnings"].append("High thread count detected")
    
    return analysis


def analyze_iterations(iteration_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze results from multiple iterations.
    
    Args:
        iteration_results: List of profiling data from multiple iterations.
        
    Returns:
        Analysis of trends across iterations.
    """
    analysis = {
        "iterations": len(iteration_results),
        "memory": {
            "peak_trend": [],
            "final_trend": [],
            "increasing": False
        },
        "duration": {
            "trend": [],
            "consistent": True
        },
        "warnings": []
    }
    
    if not iteration_results:
        return analysis
    
    # Extract trends
    peak_memory = []
    final_memory = []
    durations = []
    
    for result in iteration_results:
        result_analysis = analyze_profile_data(result)
        peak_memory.append(result_analysis["memory"]["peak_mb"])
        final_memory.append(result_analysis["memory"]["final_mb"])
        durations.append(result_analysis["duration"])
    
    analysis["memory"]["peak_trend"] = peak_memory
    analysis["memory"]["final_trend"] = final_memory
    analysis["duration"]["trend"] = durations
    
    # Check for memory growth across iterations
    if len(peak_memory) > 2:
        # Simple trend analysis
        increasing = all(b >= a for a, b in zip(peak_memory, peak_memory[1:]))
        
        if increasing and (peak_memory[-1] - peak_memory[0]) > 50:  # Significant increase
            analysis["memory"]["increasing"] = True
            analysis["warnings"].append("Memory usage increases across iterations - potential leak")
    
    # Check for consistent duration
    if len(durations) > 2:
        # Calculate coefficient of variation
        mean_duration = statistics.mean(durations)
        stdev_duration = statistics.stdev(durations)
        cv = stdev_duration / mean_duration if mean_duration > 0 else 0
        
        # CV > 0.2 indicates significant variation
        if cv > 0.2:
            analysis["duration"]["consistent"] = False
            analysis["warnings"].append("Inconsistent execution duration across iterations")
    
    return analysis


def generate_profile_plots(profile_data: Dict[str, Any], output_dir: Path) -> Dict[str, Path]:
    """
    Generate plots from resource profiling data.
    
    Args:
        profile_data: Resource usage profile data.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    resource_usage = profile_data.get("resource_usage", {})
    
    # Check if we have data to plot
    if not resource_usage or "timestamp" not in resource_usage:
        return plots
    
    # 1. CPU Usage Plot
    if "cpu_percent" in resource_usage:
        plt.figure(figsize=(10, 6))
        plt.plot(resource_usage["timestamp"], resource_usage["cpu_percent"])
        plt.title("CPU Usage Over Time")
        plt.xlabel("Time (seconds)")
        plt.ylabel("CPU Usage (%)")
        plt.grid(True)
        
        cpu_plot_path = output_dir / "cpu_usage.png"
        plt.savefig(cpu_plot_path)
        plt.close()
        plots["cpu_usage"] = cpu_plot_path
    
    # 2. Memory Usage Plot
    if "memory_usage" in resource_usage:
        plt.figure(figsize=(10, 6))
        plt.plot(resource_usage["timestamp"], resource_usage["memory_usage"])
        plt.title("Memory Usage Over Time")
        plt.xlabel("Time (seconds)")
        plt.ylabel("Memory Usage (MB)")
        plt.grid(True)
        
        memory_plot_path = output_dir / "memory_usage.png"
        plt.savefig(memory_plot_path)
        plt.close()
        plots["memory_usage"] = memory_plot_path
    
    # 3. Thread Count Plot
    if "thread_count" in resource_usage:
        plt.figure(figsize=(10, 6))
        plt.plot(resource_usage["timestamp"], resource_usage["thread_count"])
        plt.title("Thread Count Over Time")
        plt.xlabel("Time (seconds)")
        plt.ylabel("Number of Threads")
        plt.grid(True)
        
        thread_plot_path = output_dir / "thread_count.png"
        plt.savefig(thread_plot_path)
        plt.close()
        plots["thread_count"] = thread_plot_path
    
    # 4. I/O Activity Plot
    if "io_read_bytes" in resource_usage and "io_write_bytes" in resource_usage:
        # Only create if we have valid I/O data
        if (all(x is not None for x in resource_usage["io_read_bytes"]) and 
            all(x is not None for x in resource_usage["io_write_bytes"])):
            
            # Convert to MB for readability
            io_read_mb = [x / (1024 * 1024) for x in resource_usage["io_read_bytes"]]
            io_write_mb = [x / (1024 * 1024) for x in resource_usage["io_write_bytes"]]
            
            plt.figure(figsize=(10, 6))
            plt.plot(resource_usage["timestamp"], io_read_mb, label="Read")
            plt.plot(resource_usage["timestamp"], io_write_mb, label="Write")
            plt.title("I/O Activity Over Time")
            plt.xlabel("Time (seconds)")
            plt.ylabel("Cumulative I/O (MB)")
            plt.legend()
            plt.grid(True)
            
            io_plot_path = output_dir / "io_activity.png"
            plt.savefig(io_plot_path)
            plt.close()
            plots["io_activity"] = io_plot_path
    
    # 5. Combined Resource Usage Plot
    plt.figure(figsize=(12, 10))
    
    # Create subplots
    fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
    
    # CPU Usage
    if "cpu_percent" in resource_usage:
        axes[0].plot(resource_usage["timestamp"], resource_usage["cpu_percent"], color='red')
        axes[0].set_ylabel("CPU Usage (%)")
        axes[0].set_title("Scanner Resource Usage Over Time")
        axes[0].grid(True)
    
    # Memory Usage
    if "memory_usage" in resource_usage:
        axes[1].plot(resource_usage["timestamp"], resource_usage["memory_usage"], color='blue')
        axes[1].set_ylabel("Memory (MB)")
        axes[1].grid(True)
    
    # Thread Count
    if "thread_count" in resource_usage:
        axes[2].plot(resource_usage["timestamp"], resource_usage["thread_count"], color='green')
        axes[2].set_xlabel("Time (seconds)")
        axes[2].set_ylabel("Threads")
        axes[2].grid(True)
    
    plt.tight_layout()
    
    combined_plot_path = output_dir / "combined_resources.png"
    plt.savefig(combined_plot_path)
    plt.close()
    plots["combined_resources"] = combined_plot_path
    
    return plots


def generate_iteration_plots(iteration_results: List[Dict[str, Any]], output_dir: Path) -> Dict[str, Path]:
    """
    Generate plots comparing results across iterations.
    
    Args:
        iteration_results: List of profiling data from multiple iterations.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    if not iteration_results:
        return plots
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # Prepare data
    iterations = []
    durations = []
    peak_memory = []
    final_memory = []
    avg_cpu = []
    
    for i, result in enumerate(iteration_results, 1):
        analysis = analyze_profile_data(result)
        iterations.append(i)
        durations.append(analysis["duration"])
        peak_memory.append(analysis["memory"]["peak_mb"])
        final_memory.append(analysis["memory"]["final_mb"])
        avg_cpu.append(analysis["cpu"]["average"])
    
    # 1. Duration Trend Plot
    plt.figure(figsize=(10, 6))
    plt.bar(iterations, durations, color='skyblue')
    plt.title("Execution Duration Across Iterations")
    plt.xlabel("Iteration")
    plt.ylabel("Duration (seconds)")
    plt.grid(True, axis='y')
    
    duration_plot_path = output_dir / "duration_trend.png"
    plt.savefig(duration_plot_path)
    plt.close()
    plots["duration_trend"] = duration_plot_path
    
    # 2. Memory Trend Plot
    plt.figure(figsize=(10, 6))
    plt.plot(iterations, peak_memory, marker='o', label="Peak Memory")
    plt.plot(iterations, final_memory, marker='s', label="Final Memory")
    plt.title("Memory Usage Across Iterations")
    plt.xlabel("Iteration")
    plt.ylabel("Memory (MB)")
    plt.legend()
    plt.grid(True)
    
    memory_plot_path = output_dir / "memory_trend.png"
    plt.savefig(memory_plot_path)
    plt.close()
    plots["memory_trend"] = memory_plot_path
    
    # 3. CPU Usage Trend Plot
    plt.figure(figsize=(10, 6))
    plt.bar(iterations, avg_cpu, color='orange')
    plt.title("Average CPU Usage Across Iterations")
    plt.xlabel("Iteration")
    plt.ylabel("Average CPU Usage (%)")
    plt.grid(True, axis='y')
    
    cpu_plot_path = output_dir / "cpu_trend.png"
    plt.savefig(cpu_plot_path)
    plt.close()
    plots["cpu_trend"] = cpu_plot_path
    
    # 4. Combined Metrics Trend
    plt.figure(figsize=(12, 10))
    
    # Create subplots
    fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
    
    # Duration
    axes[0].bar(iterations, durations, color='skyblue')
    axes[0].set_ylabel("Duration (s)")
    axes[0].set_title("Performance Metrics Across Iterations")
    axes[0].grid(True, axis='y')
    
    # Memory
    axes[1].plot(iterations, peak_memory, marker='o', color='blue', label="Peak")
    axes[1].plot(iterations, final_memory, marker='s', color='cyan', label="Final")
    axes[1].set_ylabel("Memory (MB)")
    axes[1].legend()
    axes[1].grid(True)
    
    # CPU
    axes[2].bar(iterations, avg_cpu, color='orange')
    axes[2].set_xlabel("Iteration")
    axes[2].set_ylabel("Avg CPU (%)")
    axes[2].grid(True, axis='y')
    
    plt.tight_layout()
    
    combined_plot_path = output_dir / "combined_trends.png"
    plt.savefig(combined_plot_path)
    plt.close()
    plots["combined_trends"] = combined_plot_path
    
    return plots


def run_test(duration: int = 60, basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run resource usage profiling tests.
    
    Args:
        duration: Maximum test duration in seconds.
        basic: Whether to run basic tests only.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting resource usage profiling")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-resource-profile-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    plots_dir = base_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Select configurations based on test mode
    if basic:
        # Use minimal configurations
        selected_configs = [PROFILE_CONFIGS[0]]  # Small project only
    elif comprehensive:
        # Use all configurations
        selected_configs = PROFILE_CONFIGS
    else:
        # Use standard configurations
        selected_configs = [PROFILE_CONFIGS[0], PROFILE_CONFIGS[1]]  # Small and medium projects
    
    # Adjust based on available time
    if duration < 30 and not basic:
        logger.info(f"Short duration ({duration}s) - reducing test set")
        selected_configs = [PROFILE_CONFIGS[0]]  # Small project only
    elif duration > 300 and not comprehensive:
        logger.info(f"Long duration ({duration}s) - adding more tests")
        if PROFILE_CONFIGS[2] not in selected_configs:  # Add large project test
            selected_configs.append(PROFILE_CONFIGS[2])
    
    test_results = {}
    
    with Progress() as progress:
        task1 = progress.add_task("[green]Creating test projects...", total=len(selected_configs))
        task2 = progress.add_task("[cyan]Running profiling tests...", total=len(selected_configs))
        
        # Start timing
        start_time = time.time()
        
        # Process each configuration
        for config in selected_configs:
            logger.info(f"Testing {config['name']} ({config['id']})")
            
            # Create test project
            project_dir = create_test_project(config, base_dir)
            progress.update(task1, advance=1)
            
            # Run test based on configuration type
            if "iterations" in config:
                # Multiple iterations test
                test_output_dir = output_dir / config["id"]
                test_output_dir.mkdir(parents=True, exist_ok=True)
                
                iteration_results = run_multiple_iterations(config, project_dir, test_output_dir)
                
                # Analyze iterations
                iteration_analysis = analyze_iterations(iteration_results)
                
                # Generate iteration plots
                iteration_plots_dir = plots_dir / config["id"]
                iteration_plots = generate_iteration_plots(iteration_results, iteration_plots_dir)
                
                # Store results
                test_results[config["id"]] = {
                    "config": config,
                    "project_dir": str(project_dir),
                    "output_dir": str(test_output_dir),
                    "iteration_results": iteration_results,
                    "iteration_analysis": iteration_analysis,
                    "iteration_plots": {name: str(path) for name, path in iteration_plots.items()}
                }
            else:
                # Single run test
                test_output_dir = output_dir / config["id"]
                test_output_dir.mkdir(parents=True, exist_ok=True)
                
                output_path, profile_data = run_scanner_with_profiling(
                    project_dir, test_output_dir, config.get("sampling_rate", 0.1)
                )
                
                # Analyze profile data
                analysis = analyze_profile_data(profile_data)
                
                # Generate plots
                plots_output_dir = plots_dir / config["id"]
                plots = generate_profile_plots(profile_data, plots_output_dir)
                
                # Store results
                test_results[config["id"]] = {
                    "config": config,
                    "project_dir": str(project_dir),
                    "output_path": str(output_path),
                    "profile_data": profile_data,
                    "analysis": analysis,
                    "plots": {name: str(path) for name, path in plots.items()}
                }
            
            progress.update(task2, advance=1)
            
            # Check if we've exceeded the duration limit
            elapsed = time.time() - start_time
            if elapsed > duration and len(test_results) >= 1:  # Ensure we have at least 1 data point
                logger.info(f"Duration limit reached ({elapsed:.1f}s > {duration}s), stopping tests")
                break
    
    # Create overall analysis
    overall_analysis = {
        "tests_completed": len(test_results),
        "resource_usage": {
            "avg_memory_mb": [],
            "peak_memory_mb": [],
            "avg_cpu_percent": [],
            "small_project": {},
            "medium_project": {},
            "large_project": {},
            "memory_leak_risk": "Low"
        },
        "recommendations": []
    }
    
    # Extract key metrics
    for config_id, result in test_results.items():
        config = result["config"]
        
        # Handle different test types
        if "iteration_results" in result:
            # Multiple iterations test
            iteration_analysis = result["iteration_analysis"]
            
            # Check for memory leak risk
            if iteration_analysis["memory"]["increasing"]:
                overall_analysis["resource_usage"]["memory_leak_risk"] = "High"
                overall_analysis["recommendations"].append(
                    "Investigate potential memory leaks across multiple runs"
                )
        else:
            # Single run test
            analysis = result["analysis"]
            
            # Add to overall metrics
            overall_analysis["resource_usage"]["avg_memory_mb"].append(analysis["memory"]["average_mb"])
            overall_analysis["resource_usage"]["peak_memory_mb"].append(analysis["memory"]["peak_mb"])
            overall_analysis["resource_usage"]["avg_cpu_percent"].append(analysis["cpu"]["average"])
            
            # Store project-specific metrics
            if config["id"] == "resource-small":
                overall_analysis["resource_usage"]["small_project"] = {
                    "peak_memory_mb": analysis["memory"]["peak_mb"],
                    "avg_cpu_percent": analysis["cpu"]["average"],
                    "duration": analysis["duration"]
                }
            elif config["id"] == "resource-medium":
                overall_analysis["resource_usage"]["medium_project"] = {
                    "peak_memory_mb": analysis["memory"]["peak_mb"],
                    "avg_cpu_percent": analysis["cpu"]["average"],
                    "duration": analysis["duration"]
                }
            elif config["id"] == "resource-large":
                overall_analysis["resource_usage"]["large_project"] = {
                    "peak_memory_mb": analysis["memory"]["peak_mb"],
                    "avg_cpu_percent": analysis["cpu"]["average"],
                    "duration": analysis["duration"]
                }
            
            # Add any warnings to overall recommendations
            for warning in analysis["warnings"]:
                if warning not in overall_analysis["recommendations"]:
                    overall_analysis["recommendations"].append(warning)
    
    # Final results
    final_results = {
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir),
            "plots_dir": str(plots_dir)
        },
        "test_results": test_results,
        "overall_analysis": overall_analysis,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "num_configs": len(selected_configs),
            "actual_duration": time.time() - start_time
        }
    }
    
    # Display summary
    display_summary(overall_analysis, test_results)
    
    logger.info("Resource usage profiling completed")
    return final_results


def display_summary(overall_analysis: Dict[str, Any], test_results: Dict[str, Dict[str, Any]]) -> None:
    """
    Display a summary of resource usage profiling results.
    
    Args:
        overall_analysis: Overall analysis results.
        test_results: Detailed test results.
    """
    console.print("\n[bold cyan]Resource Usage Profiling Summary[/]")
    
    # Create overall summary table
    table = Table(title="Overall Resource Usage")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    # Calculate overall averages
    avg_memory = statistics.mean(overall_analysis["resource_usage"]["avg_memory_mb"]) if overall_analysis["resource_usage"]["avg_memory_mb"] else 0
    peak_memory = max(overall_analysis["resource_usage"]["peak_memory_mb"]) if overall_analysis["resource_usage"]["peak_memory_mb"] else 0
    avg_cpu = statistics.mean(overall_analysis["resource_usage"]["avg_cpu_percent"]) if overall_analysis["resource_usage"]["avg_cpu_percent"] else 0
    
    table.add_row("Average Memory Usage", f"{avg_memory:.1f} MB")
    table.add_row("Peak Memory Usage", f"{peak_memory:.1f} MB")
    table.add_row("Average CPU Usage", f"{avg_cpu:.1f}%")
    table.add_row("Memory Leak Risk", overall_analysis["resource_usage"]["memory_leak_risk"])
    
    console.print(table)
    
    # Create project comparison table
    has_multiple_projects = (
        "small_project" in overall_analysis["resource_usage"] and
        ("medium_project" in overall_analysis["resource_usage"] or 
         "large_project" in overall_analysis["resource_usage"])
    )
    
    if has_multiple_projects:
        console.print("\n[bold cyan]Project Size Comparison[/]")
        size_table = Table()
        size_table.add_column("Project Size", style="cyan")
        size_table.add_column("Peak Memory (MB)", style="green")
        size_table.add_column("Avg CPU (%)", style="yellow")
        size_table.add_column("Duration (s)", style="blue")
        
        if "small_project" in overall_analysis["resource_usage"]:
            small = overall_analysis["resource_usage"]["small_project"]
            size_table.add_row(
                "Small",
                f"{small.get('peak_memory_mb', 0):.1f}",
                f"{small.get('avg_cpu_percent', 0):.1f}",
                f"{small.get('duration', 0):.2f}"
            )
        
        if "medium_project" in overall_analysis["resource_usage"]:
            medium = overall_analysis["resource_usage"]["medium_project"]
            size_table.add_row(
                "Medium",
                f"{medium.get('peak_memory_mb', 0):.1f}",
                f"{medium.get('avg_cpu_percent', 0):.1f}",
                f"{medium.get('duration', 0):.2f}"
            )
        
        if "large_project" in overall_analysis["resource_usage"]:
            large = overall_analysis["resource_usage"]["large_project"]
            size_table.add_row(
                "Large",
                f"{large.get('peak_memory_mb', 0):.1f}",
                f"{large.get('avg_cpu_percent', 0):.1f}",
                f"{large.get('duration', 0):.2f}"
            )
        
        console.print(size_table)
    
    # Display iteration analysis if available
    iteration_tests = [
        test for test in test_results.values() 
        if "iteration_analysis" in test
    ]
    
    if iteration_tests:
        console.print("\n[bold cyan]Multiple Iterations Analysis[/]")
        for test in iteration_tests:
            config = test["config"]
            analysis = test["iteration_analysis"]
            
            console.print(f"[bold]Test: {config['name']}[/]")
            
            if analysis["memory"]["increasing"]:
                console.print("[red]Memory usage increases across iterations - potential memory leak[/]")
            else:
                console.print("[green]Memory usage is stable across iterations[/]")
            
            if analysis["duration"]["consistent"]:
                console.print("[green]Execution time is consistent across iterations[/]")
            else:
                console.print("[yellow]Execution time varies significantly across iterations[/]")
    
    # Display recommendations
    if overall_analysis["recommendations"]:
        console.print("\n[bold cyan]Recommendations:[/]")
        for i, recommendation in enumerate(overall_analysis["recommendations"], 1):
            console.print(f"[yellow]{i}. {recommendation}[/]")
    
    # Overall assessment
    console.print("\n[bold cyan]Overall Assessment:[/]")
    
    if peak_memory < 200 and avg_cpu < 50 and overall_analysis["resource_usage"]["memory_leak_risk"] == "Low":
        console.print("[bold green]The scanner has excellent resource efficiency.[/]")
    elif peak_memory < 500 and avg_cpu < 80 and overall_analysis["resource_usage"]["memory_leak_risk"] == "Low":
        console.print("[bold green]The scanner has good resource efficiency.[/]")
    elif overall_analysis["resource_usage"]["memory_leak_risk"] == "High":
        console.print("[bold red]The scanner shows potential memory leaks that should be investigated.[/]")
    elif peak_memory > 1000 or avg_cpu > 90:
        console.print("[bold yellow]The scanner has high resource usage that could be optimized.[/]")
    else:
        console.print("[bold yellow]The scanner has acceptable resource usage but could be improved.[/]")


if __name__ == "__main__":
    import random  # Required for project generation
    logging.basicConfig(level=logging.INFO)
    results = run_test(duration=120)
    print(json.dumps(results, indent=2))
