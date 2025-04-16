"""
Chaos engineering tests for ossv-scanner.

This module implements chaos engineering principles to assess how the scanner
performs under unexpected conditions and failure scenarios.
"""

import os
import time
import logging
import tempfile
import json
import yaml
import shutil
import subprocess
import random
import signal
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import platform

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Chaos test scenarios
CHAOS_SCENARIOS = [
    {
        "id": "chaos-01",
        "name": "Corrupt Dependency Files",
        "description": "Test behavior when dependency files are corrupted mid-scan",
        "preparation": "create_normal_project",
        "chaos_action": "corrupt_files",
        "expected_behavior": "graceful_failure"
    },
    {
        "id": "chaos-02",
        "name": "Network Interruption",
        "description": "Test behavior when network connectivity is lost during scanning",
        "preparation": "create_normal_project",
        "chaos_action": "interrupt_network",
        "expected_behavior": "retry_or_cache"
    },
    {
        "id": "chaos-03", 
        "name": "Memory Pressure",
        "description": "Test behavior under memory pressure",
        "preparation": "create_large_project",
        "chaos_action": "memory_pressure",
        "expected_behavior": "complete_scan"
    },
    {
        "id": "chaos-04",
        "name": "CPU Contention",
        "description": "Test behavior under CPU contention",
        "preparation": "create_normal_project",
        "chaos_action": "cpu_contention",
        "expected_behavior": "slower_completion"
    },
    {
        "id": "chaos-05",
        "name": "Process Interruption",
        "description": "Test behavior when scanner process is interrupted",
        "preparation": "create_normal_project",
        "chaos_action": "signal_interrupt",
        "expected_behavior": "graceful_exit"
    },
    {
        "id": "chaos-06",
        "name": "File System Errors",
        "description": "Test behavior when file system errors occur",
        "preparation": "create_normal_project",
        "chaos_action": "filesystem_errors",
        "expected_behavior": "report_errors"
    },
    {
        "id": "chaos-07",
        "name": "Slow Disk I/O",
        "description": "Test behavior when disk I/O is very slow",
        "preparation": "create_normal_project",
        "chaos_action": "slow_disk_io",
        "expected_behavior": "complete_scan"
    },
    {
        "id": "chaos-08",
        "name": "Malformed Package Entries",
        "description": "Test behavior with malformed package entries in dependency files",
        "preparation": "create_malformed_project",
        "chaos_action": "none",
        "expected_behavior": "partial_results"
    }
]

# Reference data for creating test projects
TEST_NPM_PACKAGES = [
    {"name": "lodash", "version": "4.17.15"},
    {"name": "express", "version": "4.17.1"},
    {"name": "react", "version": "17.0.2"},
    {"name": "moment", "version": "2.29.1"},
    {"name": "axios", "version": "0.21.1"},
    {"name": "jquery", "version": "3.5.1"},
    {"name": "chalk", "version": "4.1.2"}
]

TEST_PYTHON_PACKAGES = [
    {"name": "requests", "version": "2.25.1"},
    {"name": "django", "version": "3.2.5"},
    {"name": "flask", "version": "2.0.1"},
    {"name": "numpy", "version": "1.20.3"},
    {"name": "pandas", "version": "1.3.0"}
]

TEST_JAVA_PACKAGES = [
    {"name": "org.springframework:spring-core", "version": "5.3.9"},
    {"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.12.4"},
    {"name": "org.apache.commons:commons-lang3", "version": "3.12.0"},
    {"name": "junit:junit", "version": "4.13.2"}
]


def create_normal_project(base_dir: Path, scenario_id: str) -> Path:
    """
    Create a normal test project with typical dependencies.
    
    Args:
        base_dir: Base directory for test projects.
        scenario_id: Scenario identifier.
        
    Returns:
        Path to the created project.
    """
    project_dir = base_dir / scenario_id
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package.json
    deps = {pkg["name"]: pkg["version"] for pkg in random.sample(TEST_NPM_PACKAGES, 5)}
    package_json = {
        "name": f"chaos-test-{scenario_id}",
        "version": "1.0.0",
        "description": "Chaos test project",
        "dependencies": deps
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create requirements.txt
    requirements = [f"{pkg['name']}=={pkg['version']}" for pkg in random.sample(TEST_PYTHON_PACKAGES, 3)]
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("\n".join(requirements))
    
    # Create pom.xml
    java_deps = random.sample(TEST_JAVA_PACKAGES, 2)
    dep_xml = []
    for pkg in java_deps:
        group_id, artifact_id = pkg["name"].split(":")
        dep_xml.append(f"""        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
            <version>{pkg['version']}</version>
        </dependency>""")
    
    pom_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>chaos-test-{scenario_id}</artifactId>
    <version>1.0.0</version>

    <dependencies>
{os.linesep.join(dep_xml)}
    </dependencies>
</project>"""
    
    with open(project_dir / "pom.xml", "w") as f:
        f.write(pom_xml)
    
    return project_dir


def create_large_project(base_dir: Path, scenario_id: str) -> Path:
    """
    Create a large test project with many dependencies.
    
    Args:
        base_dir: Base directory for test projects.
        scenario_id: Scenario identifier.
        
    Returns:
        Path to the created project.
    """
    project_dir = base_dir / scenario_id
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate many random dependencies
    npm_deps = {}
    for i in range(200):
        name = f"package-{i}"
        version = f"{random.randint(1, 10)}.{random.randint(0, 20)}.{random.randint(0, 99)}"
        npm_deps[name] = version
    
    # Add some real packages too
    for pkg in TEST_NPM_PACKAGES:
        npm_deps[pkg["name"]] = pkg["version"]
    
    # Create package.json
    package_json = {
        "name": f"chaos-test-large-{scenario_id}",
        "version": "1.0.0", 
        "description": "Large chaos test project",
        "dependencies": npm_deps
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create large requirements.txt
    requirements = []
    for i in range(100):
        name = f"python-package-{i}"
        version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 99)}"
        requirements.append(f"{name}=={version}")
    
    # Add some real packages too
    for pkg in TEST_PYTHON_PACKAGES:
        requirements.append(f"{pkg['name']}=={pkg['version']}")
    
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("\n".join(requirements))
    
    return project_dir


def create_malformed_project(base_dir: Path, scenario_id: str) -> Path:
    """
    Create a project with malformed package entries.
    
    Args:
        base_dir: Base directory for test projects.
        scenario_id: Scenario identifier.
        
    Returns:
        Path to the created project.
    """
    project_dir = base_dir / scenario_id
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create package.json with malformed entries
    package_json = {
        "name": f"chaos-test-malformed-{scenario_id}",
        "version": "1.0.0",
        "description": "Project with malformed package entries",
        "dependencies": {
            "lodash": "4.17.15",  # Valid
            "express": None,       # Invalid - null version
            "react": "",           # Invalid - empty version
            "axios": {"version": "0.21.1"},  # Invalid - object instead of string
            "jquery@3.5.1": "latest",  # Invalid - @ in package name
            True: "1.0.0",         # Invalid - boolean as key
            "moment": "~>2.29.1"   # Invalid version format
        }
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create requirements.txt with malformed entries
    requirements = [
        "requests==2.25.1",        # Valid
        "django=3.2.5",            # Invalid - single equals
        "flask==",                 # Invalid - missing version
        "numpy==1.20.3; python_version>='3.7'",  # Environment marker
        "pandas==>1.3.0",          # Invalid - wrong operator
        "==1.1.0",                 # Invalid - missing package name
        "@invalid-package==1.0.0", # Invalid - @ in package name
        "package-with spaces==1.0.0"  # Invalid - spaces in name
    ]
    
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("\n".join(requirements))
    
    # Create malformed pom.xml
    pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>chaos-test-malformed</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <!-- Valid dependency -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.9</version>
        </dependency>
        <!-- Invalid - missing artifact ID -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <version>2.12.4</version>
        </dependency>
        <!-- Invalid - missing version -->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
        </dependency>
        <!-- Invalid - malformed version -->
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>x.y.z</version>
        </dependency>
    </dependencies>
</project>"""
    
    with open(project_dir / "pom.xml", "w") as f:
        f.write(pom_xml)
    
    return project_dir


def corrupt_files(project_dir: Path) -> None:
    """
    Corrupt dependency files mid-scan.
    
    Args:
        project_dir: Project directory.
    """
    # Target files to corrupt
    targets = [
        project_dir / "package.json",
        project_dir / "requirements.txt",
        project_dir / "pom.xml"
    ]
    
    # Corrupt a random file after a delay
    target = random.choice([t for t in targets if t.exists()])
    
    def _corrupt_file():
        time.sleep(0.5)  # Wait for scan to start
        
        try:
            # Read current content
            with open(target, "r") as f:
                content = f.read()
            
            # Corrupt the file
            corrupt_content = content[:len(content)//2] + "<<<CORRUPTED>>>" + content[len(content)//2:]
            
            # Write corrupted content
            with open(target, "w") as f:
                f.write(corrupt_content)
                
            logger.info(f"Corrupted file: {target}")
        except Exception as e:
            logger.error(f"Error corrupting file: {str(e)}")
    
    # Start corruption in a separate thread
    thread = threading.Thread(target=_corrupt_file)
    thread.daemon = True
    thread.start()


def interrupt_network(project_dir: Path) -> None:
    """
    Simulate network interruption during scan.
    
    Args:
        project_dir: Project directory.
    """
    # This is a simplified simulation since we can't actually control the network
    # In a real implementation, you might use tools like netem or firewall rules
    
    # For this simulation, we'll create a file that the scanner can check
    # to determine if network is available
    network_file = project_dir / ".network_status"
    
    with open(network_file, "w") as f:
        f.write("online")
    
    def _interrupt_network():
        time.sleep(0.5)  # Wait for scan to start
        
        try:
            # Simulate network interruption
            with open(network_file, "w") as f:
                f.write("offline")
            
            logger.info("Simulated network interruption")
            
            # Restore network after a delay
            time.sleep(2.0)
            
            with open(network_file, "w") as f:
                f.write("online")
                
            logger.info("Restored network connection")
        except Exception as e:
            logger.error(f"Error simulating network interruption: {str(e)}")
    
    # Start interruption in a separate thread
    thread = threading.Thread(target=_interrupt_network)
    thread.daemon = True
    thread.start()


def memory_pressure(project_dir: Path) -> None:
    """
    Create memory pressure during the scan.
    
    Args:
        project_dir: Project directory.
    """
    def _create_memory_pressure():
        time.sleep(0.5)  # Wait for scan to start
        
        # Create memory pressure by allocating large arrays
        try:
            logger.info("Creating memory pressure")
            
            # Allocate memory in chunks to avoid crashing the system
            memory_hogs = []
            for _ in range(10):
                # Each array is ~100MB
                memory_hogs.append(bytearray(100 * 1024 * 1024))
                time.sleep(0.2)
            
            logger.info("Memory pressure applied, holding for scan duration")
            
            # Hold memory pressure for a while
            time.sleep(10.0)
            
            # Release memory
            memory_hogs.clear()
            logger.info("Released memory pressure")
            
        except Exception as e:
            logger.error(f"Error creating memory pressure: {str(e)}")
    
    # Start memory pressure in a separate thread
    thread = threading.Thread(target=_create_memory_pressure)
    thread.daemon = True
    thread.start()


def cpu_contention(project_dir: Path) -> None:
    """
    Create CPU contention during the scan.
    
    Args:
        project_dir: Project directory.
    """
    def _create_cpu_load():
        time.sleep(0.5)  # Wait for scan to start
        
        try:
            logger.info("Creating CPU contention")
            
            # Determine number of CPUs to use (leave at least one for the scanner)
            num_cpus = max(1, os.cpu_count() - 1) if os.cpu_count() else 1
            
            # Create CPU-intensive threads
            cpu_threads = []
            for _ in range(num_cpus):
                cpu_thread = threading.Thread(target=_cpu_intensive_task)
                cpu_thread.daemon = True
                cpu_threads.append(cpu_thread)
                cpu_thread.start()
            
            # Run CPU contention for a while
            time.sleep(8.0)
            
            # Signal threads to stop
            global _stop_cpu_tasks
            _stop_cpu_tasks = True
            
            # Wait for threads to finish
            for thread in cpu_threads:
                thread.join(timeout=1.0)
                
            logger.info("Released CPU contention")
            
        except Exception as e:
            logger.error(f"Error creating CPU contention: {str(e)}")
    
    # CPU-intensive task for threads
    global _stop_cpu_tasks
    _stop_cpu_tasks = False
    
    def _cpu_intensive_task():
        while not _stop_cpu_tasks:
            # Perform CPU-intensive calculation
            _ = [i**2 for i in range(100000)]
    
    # Start CPU contention in a separate thread
    thread = threading.Thread(target=_create_cpu_load)
    thread.daemon = True
    thread.start()


def signal_interrupt(project_dir: Path) -> None:
    """
    Send interrupt signal to scanner process mid-scan.
    
    Args:
        project_dir: Project directory.
    """
    def _interrupt_process(process):
        time.sleep(1.0)  # Wait for scan to start
        
        try:
            logger.info(f"Sending interrupt signal to process {process.pid}")
            
            # Send interrupt signal
            if platform.system() == "Windows":
                # On Windows, use CTRL_C_EVENT
                os.kill(process.pid, signal.CTRL_C_EVENT)
            else:
                # On Unix-like systems, use SIGINT
                os.kill(process.pid, signal.SIGINT)
            
            logger.info("Interrupt signal sent")
            
        except Exception as e:
            logger.error(f"Error sending interrupt signal: {str(e)}")
    
    # The actual signal will be sent from the run_scanner function
    # This function just defines the behavior
    return _interrupt_process


def filesystem_errors(project_dir: Path) -> None:
    """
    Simulate filesystem errors during scan.
    
    Args:
        project_dir: Project directory.
    """
    # Create a file that will be accessed during scan, then make it unreadable
    test_file = project_dir / "test_file.txt"
    
    with open(test_file, "w") as f:
        f.write("Test file for filesystem errors")
    
    def _create_filesystem_errors():
        time.sleep(0.5)  # Wait for scan to start
        
        try:
            logger.info("Creating filesystem errors")
            
            # Make file unreadable
            if platform.system() != "Windows":
                # On Unix-like systems, use chmod
                os.chmod(test_file, 0o000)
                
                # Also create a directory with the same name as a file the scanner might create
                results_dir = project_dir / "results"
                results_dir.mkdir(exist_ok=True)
                
                # Create a file with the same name as a potential output file
                scanner_output = project_dir / "scan-results.json"
                if not scanner_output.exists():
                    with open(scanner_output, "w") as f:
                        f.write("{}")
                    
                    # Make it unwritable
                    os.chmod(scanner_output, 0o400)
            else:
                # On Windows, this is trickier, but we'll do what we can
                # Create a file with the same name as a potential output file
                scanner_output = project_dir / "scan-results.json"
                if not scanner_output.exists():
                    with open(scanner_output, "w") as f:
                        f.write("{}")
                    
                    # Try to make it read-only
                    os.chmod(scanner_output, 0o444)
            
            logger.info("Filesystem errors created")
            
            # Restore permissions after a delay
            time.sleep(5.0)
            
            if platform.system() != "Windows":
                os.chmod(test_file, 0o644)
                if scanner_output.exists():
                    os.chmod(scanner_output, 0o644)
            else:
                if scanner_output.exists():
                    os.chmod(scanner_output, 0o644)
                    
            logger.info("Restored filesystem permissions")
            
        except Exception as e:
            logger.error(f"Error creating filesystem errors: {str(e)}")
    
    # Start filesystem errors in a separate thread
    thread = threading.Thread(target=_create_filesystem_errors)
    thread.daemon = True
    thread.start()


def slow_disk_io(project_dir: Path) -> None:
    """
    Simulate slow disk I/O during scan.
    
    Args:
        project_dir: Project directory.
    """
    def _create_disk_load():
        time.sleep(0.5)  # Wait for scan to start
        
        try:
            logger.info("Creating disk I/O load")
            
            # Create a large file with random data to force disk I/O
            temp_file = project_dir / "large_temp_file.bin"
            
            # Create multiple files to increase I/O pressure
            files = []
            for i in range(5):
                file_path = project_dir / f"large_temp_file_{i}.bin"
                files.append(file_path)
                
                # Create a disk-intensive thread for each file
                disk_thread = threading.Thread(target=_disk_intensive_task, args=(file_path,))
                disk_thread.daemon = True
                disk_thread.start()
            
            # Run disk I/O for a while
            time.sleep(8.0)
            
            # Signal threads to stop
            global _stop_disk_tasks
            _stop_disk_tasks = True
            
            # Clean up temp files
            for file_path in files:
                if file_path.exists():
                    try:
                        file_path.unlink()
                    except:
                        pass
                    
            logger.info("Released disk I/O load")
            
        except Exception as e:
            logger.error(f"Error creating disk I/O load: {str(e)}")
    
    # Disk-intensive task
    global _stop_disk_tasks
    _stop_disk_tasks = False
    
    def _disk_intensive_task(file_path):
        try:
            with open(file_path, "wb") as f:
                # Write in small chunks to extend I/O time
                chunk_size = 1024 * 1024  # 1MB
                for _ in range(100):  # 100MB total
                    if _stop_disk_tasks:
                        break
                    f.write(os.urandom(chunk_size))
                    f.flush()
                    os.fsync(f.fileno())  # Force disk write
                    time.sleep(0.05)
                    
            # Read the file back
            with open(file_path, "rb") as f:
                while not _stop_disk_tasks:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    time.sleep(0.05)
        except Exception as e:
            logger.debug(f"Disk task error: {str(e)}")
    
    # Start disk I/O load in a separate thread
    thread = threading.Thread(target=_create_disk_load)
    thread.daemon = True
    thread.start()


def run_scanner(project_dir: Path, output_dir: Path, chaos_action: Optional[str] = None) -> Tuple[Path, Dict[str, Any]]:
    """
    Run ossv-scanner on a project with optional chaos actions.
    
    Args:
        project_dir: Path to the project.
        output_dir: Directory to save scanner output.
        chaos_action: Name of chaos action to perform.
        
    Returns:
        Tuple of (result_path, metrics).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-results.json"
    
    metrics = {
        "start_time": time.time(),
        "end_time": 0,
        "duration": 0,
        "exit_code": None,
        "success": False,
        "error": None,
        "stdout": "",
        "stderr": "",
        "chaos_action": chaos_action
    }
    
    # Set up chaos action function
    chaos_func = None
    if chaos_action:
        if chaos_action == "corrupt_files":
            chaos_func = corrupt_files
        elif chaos_action == "interrupt_network":
            chaos_func = interrupt_network
        elif chaos_action == "memory_pressure":
            chaos_func = memory_pressure
        elif chaos_action == "cpu_contention":
            chaos_func = cpu_contention
        elif chaos_action == "signal_interrupt":
            chaos_func = signal_interrupt
        elif chaos_action == "filesystem_errors":
            chaos_func = filesystem_errors
        elif chaos_action == "slow_disk_io":
            chaos_func = slow_disk_io
    
    try:
        # Run the scanner
        logger.info(f"Running ossv-scanner on {project_dir} with chaos: {chaos_action}")
        
        scan_cmd = [
            "ossv-scan",
            "--output-format", "json",
            "--output-path", str(output_path),
            str(project_dir)
        ]
        
        try:
            # Try to run as installed package
            if chaos_action == "signal_interrupt":
                # For signal interruption, we need to handle the process differently
                process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                interrupt_func = chaos_func(project_dir)
                interrupt_func(process)
                stdout, stderr = process.communicate()
                metrics["stdout"] = stdout.decode("utf-8")
                metrics["stderr"] = stderr.decode("utf-8")
                metrics["exit_code"] = process.returncode
            else:
                # Apply chaos action if specified
                if chaos_func:
                    chaos_func(project_dir)
                
                # Run the scanner
                process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                metrics["stdout"] = stdout.decode("utf-8")
                metrics["stderr"] = stderr.decode("utf-8")
                metrics["exit_code"] = process.returncode
                
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            scan_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_dir)
            ]
            
            if chaos_action == "signal_interrupt":
                # For signal interruption
                process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                interrupt_func = chaos_func(project_dir)
                interrupt_func(process)
                stdout, stderr = process.communicate()
                metrics["stdout"] = stdout.decode("utf-8")
                metrics["stderr"] = stderr.decode("utf-8")
                metrics["exit_code"] = process.returncode
            else:
                # Apply chaos action if specified
                if chaos_func:
                    chaos_func(project_dir)
                
                # Run the scanner
                process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                metrics["stdout"] = stdout.decode("utf-8")
                metrics["stderr"] = stderr.decode("utf-8")
                metrics["exit_code"] = process.returncode
        
        # Record end time and duration
        metrics["end_time"] = time.time()
        metrics["duration"] = metrics["end_time"] - metrics["start_time"]
        
        # Check if scan was successful based on exit code and output file
        metrics["success"] = (metrics["exit_code"] == 0 and output_path.exists())
        
        logger.info(f"Scanner completed with exit code {metrics['exit_code']}. Results at {output_path}")
        
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


def analyze_results(test_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze chaos test results.
    
    Args:
        test_results: Dictionary of test results by scenario ID.
        
    Returns:
        Analysis results.
    """
    analysis = {
        "overall": {
            "total_tests": len(test_results),
            "successful_tests": 0,
            "gracefully_handled": 0,
            "crashes": 0,
            "hangs": 0,
            "avg_duration": 0.0
        },
        "by_category": {},
        "resilience_score": 0.0,
        "recommendations": []
    }
    
    # Count outcomes by category
    test_durations = []
    by_action = {}
    
    for scenario_id, result in test_results.items():
        scenario = result["scenario"]
        metrics = result["metrics"]
        chaos_action = scenario["chaos_action"]
        
        # Add to category counts
        if chaos_action not in by_action:
            by_action[chaos_action] = {
                "tests": 0,
                "success": 0,
                "graceful_failure": 0,
                "crash": 0,
                "hang": 0
            }
        
        by_action[chaos_action]["tests"] += 1
        
        # Determine outcome
        if metrics["success"]:
            analysis["overall"]["successful_tests"] += 1
            by_action[chaos_action]["success"] += 1
            test_durations.append(metrics["duration"])
        elif metrics["exit_code"] is not None:
            # Exited with non-zero code, but didn't crash
            analysis["overall"]["gracefully_handled"] += 1
            by_action[chaos_action]["graceful_failure"] += 1
        elif "hang" in metrics.get("error", "").lower() or metrics["duration"] > 30:
            # Potential hang
            analysis["overall"]["hangs"] += 1
            by_action[chaos_action]["hang"] += 1
        else:
            # Crash or other unexpected failure
            analysis["overall"]["crashes"] += 1
            by_action[chaos_action]["crash"] += 1
    
    # Calculate average duration
    if test_durations:
        analysis["overall"]["avg_duration"] = sum(test_durations) / len(test_durations)
    
    # Set category results
    analysis["by_category"] = by_action
    
    # Calculate resilience score (0-100)
    # Successful tests and gracefully handled failures contribute to resilience
    if analysis["overall"]["total_tests"] > 0:
        resilience_score = (
            (analysis["overall"]["successful_tests"] * 1.0 + 
             analysis["overall"]["gracefully_handled"] * 0.7) / 
            analysis["overall"]["total_tests"]
        ) * 100
        
        analysis["resilience_score"] = resilience_score
    
    # Generate recommendations
    if analysis["overall"]["crashes"] > 0:
        analysis["recommendations"].append(
            "Improve error handling to prevent crashes during unexpected failures"
        )
    
    if analysis["overall"]["hangs"] > 0:
        analysis["recommendations"].append(
            "Implement proper timeouts and cancellation to prevent hangs"
        )
    
    # Check specific issues
    for action, metrics in by_action.items():
        if metrics["tests"] > 0 and metrics["success"] + metrics["graceful_failure"] == 0:
            analysis["recommendations"].append(
                f"Improve resilience against {action} scenarios"
            )
    
    return analysis


def generate_plots(analysis: Dict[str, Any], test_results: Dict[str, Dict[str, Any]], output_dir: Path) -> Dict[str, Path]:
    """
    Generate plots for chaos test results.
    
    Args:
        analysis: Analysis results.
        test_results: Dictionary of test results by scenario ID.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # 1. Outcomes by Chaos Action
    plt.figure(figsize=(12, 6))
    
    # Prepare data
    actions = []
    successes = []
    graceful_failures = []
    crashes = []
    hangs = []
    
    for action, metrics in analysis["by_category"].items():
        actions.append(action)
        successes.append(metrics["success"])
        graceful_failures.append(metrics["graceful_failure"])
        crashes.append(metrics["crash"])
        hangs.append(metrics["hang"])
    
    # Create stacked bar chart
    width = 0.6
    fig, ax = plt.subplots(figsize=(12, 6))
    
    ax.bar(actions, successes, width, label='Success', color='green')
    ax.bar(actions, graceful_failures, width, bottom=successes, label='Graceful Failure', color='yellow')
    ax.bar(actions, crashes, width, bottom=[sum(x) for x in zip(successes, graceful_failures)], 
           label='Crash', color='red')
    ax.bar(actions, hangs, width, bottom=[sum(x) for x in zip(successes, graceful_failures, crashes)], 
           label='Hang', color='purple')
    
    ax.set_title('Outcomes by Chaos Action')
    ax.set_xlabel('Chaos Action')
    ax.set_ylabel('Count')
    ax.legend()
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    outcomes_path = output_dir / "outcomes_by_action.png"
    plt.savefig(outcomes_path)
    plt.close()
    plots["outcomes_by_action"] = outcomes_path
    
    # 2. Resilience Score Gauge Chart
    plt.figure(figsize=(8, 8))
    
    # Create gauge chart
    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw={'projection': 'polar'})
    
    # Convert resilience score to radians (0-100 to 0-pi)
    resilience = analysis["resilience_score"]
    theta = np.pi * resilience / 100.0
    
    # Color based on score
    if resilience >= 80:
        color = 'green'
    elif resilience >= 50:
        color = 'yellow'
    else:
        color = 'red'
    
    # Draw gauge
    ax.bar(0, 1, width=theta, bottom=0.0, color=color, alpha=0.8)
    
    # Customize polar plot to look like a gauge
    ax.set_thetamin(0)
    ax.set_thetamax(180)
    ax.set_theta_zero_location("S")
    ax.set_theta_direction(-1)
    ax.set_rlim(0, 1)
    ax.set_rticks([])
    
    # Add score text
    ax.text(0, 0, f"{resilience:.1f}%", ha='center', va='center', fontsize=24, 
            fontweight='bold', color='black')
    
    # Add title
    plt.title('Resilience Score', pad=20, fontsize=16)
    
    # Add score categories
    ax.text(np.pi/2, 1.15, 'Poor', ha='center', va='center', fontsize=12, color='red')
    ax.text(np.pi/4, 1.15, 'Good', ha='center', va='center', fontsize=12, color='yellow')
    ax.text(0, 1.15, 'Excellent', ha='center', va='center', fontsize=12, color='green')
    
    resilience_path = output_dir / "resilience_score.png"
    plt.savefig(resilience_path)
    plt.close()
    plots["resilience_score"] = resilience_path
    
    # 3. Execution Time Comparison
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    scenario_names = []
    durations = []
    colors = []
    
    for scenario_id, result in test_results.items():
        scenario = result["scenario"]
        metrics = result["metrics"]
        
        scenario_names.append(scenario["name"])
        durations.append(metrics["duration"])
        
        # Color based on success
        if metrics["success"]:
            colors.append('green')
        elif metrics["exit_code"] is not None:
            colors.append('yellow')
        else:
            colors.append('red')
    
    # Create bar chart
    plt.bar(scenario_names, durations, color=colors)
    plt.title('Execution Time by Scenario')
    plt.xlabel('Scenario')
    plt.ylabel('Duration (seconds)')
    
    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    duration_path = output_dir / "execution_time.png"
    plt.savefig(duration_path)
    plt.close()
    plots["execution_time"] = duration_path
    
    return plots


def run_test(duration: int = 60, basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run chaos engineering tests on the scanner.
    
    Args:
        duration: Maximum test duration in seconds (approximate).
        basic: Whether to run a basic subset of tests.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting chaos engineering tests")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-chaos-tests-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    plots_dir = base_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Select scenarios to test
    if basic:
        # Use a minimal set for basic testing
        selected_scenarios = [
            CHAOS_SCENARIOS[0],  # Corrupt Files
            CHAOS_SCENARIOS[4]   # Process Interruption
        ]
    elif comprehensive:
        # Use all scenarios for comprehensive testing
        selected_scenarios = CHAOS_SCENARIOS
    else:
        # Use a standard set
        selected_scenarios = [
            CHAOS_SCENARIOS[0],  # Corrupt Files
            CHAOS_SCENARIOS[1],  # Network Interruption
            CHAOS_SCENARIOS[3],  # CPU Contention
            CHAOS_SCENARIOS[4],  # Process Interruption
            CHAOS_SCENARIOS[7]   # Malformed Package Entries
        ]
    
    # Adjust based on duration
    if duration < 30 and not basic:
        logger.info(f"Short duration ({duration}s) - reducing test set")
        selected_scenarios = selected_scenarios[:2]  # Use only two scenarios
    elif duration > 300 and not comprehensive:
        logger.info(f"Long duration ({duration}s) - including more scenarios")
        if len(selected_scenarios) < len(CHAOS_SCENARIOS):
            additional = [s for s in CHAOS_SCENARIOS if s not in selected_scenarios][:2]
            selected_scenarios.extend(additional)
    
    test_results = {}
    
    with Progress() as progress:
        task1 = progress.add_task("[green]Creating test projects...", total=len(selected_scenarios))
        task2 = progress.add_task("[cyan]Running chaos tests...", total=len(selected_scenarios))
        
        # Start timing
        start_time = time.time()
        
        # Test each scenario
        for scenario in selected_scenarios:
            logger.info(f"Testing scenario: {scenario['name']} ({scenario['id']})")
            
            # Create test project based on scenario
            if scenario["preparation"] == "create_normal_project":
                project_dir = create_normal_project(base_dir, scenario["id"])
            elif scenario["preparation"] == "create_large_project":
                project_dir = create_large_project(base_dir, scenario["id"])
            elif scenario["preparation"] == "create_malformed_project":
                project_dir = create_malformed_project(base_dir, scenario["id"])
            else:
                logger.warning(f"Unknown preparation method: {scenario['preparation']}")
                project_dir = create_normal_project(base_dir, scenario["id"])
            
            progress.update(task1, advance=1)
            
            # Run scanner with chaos action
            chaos_action = None if scenario["chaos_action"] == "none" else scenario["chaos_action"]
            
            output_path, metrics = run_scanner(project_dir, output_dir, chaos_action)
            
            # Store test results
            test_results[scenario["id"]] = {
                "scenario": scenario,
                "project_dir": str(project_dir),
                "output_path": str(output_path),
                "metrics": metrics
            }
            
            progress.update(task2, advance=1)
            
            # Check if we've exceeded the duration limit
            elapsed = time.time() - start_time
            if elapsed > duration and len(test_results) >= 2:  # Ensure we have at least 2 data points
                logger.info(f"Duration limit reached ({elapsed:.1f}s > {duration}s), stopping tests")
                break
    
    # Analyze results
    logger.info("Analyzing test results")
    analysis = analyze_results(test_results)
    
    # Generate plots
    logger.info("Generating analysis plots")
    plots = generate_plots(analysis, test_results, plots_dir)
    
    # Combine results
    final_results = {
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir),
            "plots_dir": str(plots_dir)
        },
        "scenarios": selected_scenarios,
        "test_results": test_results,
        "analysis": analysis,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "num_scenarios": len(selected_scenarios),
            "actual_duration": time.time() - start_time
        }
    }
    
    # Display summary
    display_summary(analysis, test_results)
    
    logger.info("Chaos testing completed")
    return final_results


def display_summary(analysis: Dict[str, Any], test_results: Dict[str, Dict[str, Any]]) -> None:
    """
    Display a summary of chaos test results.
    
    Args:
        analysis: Analysis results.
        test_results: Dictionary of test results by scenario ID.
    """
    console.print("\n[bold cyan]Chaos Engineering Test Summary[/]")
    
    # Create overall summary table
    table = Table(title="Chaos Test Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Tests", str(analysis["overall"]["total_tests"]))
    table.add_row("Successful Tests", str(analysis["overall"]["successful_tests"]))
    table.add_row("Gracefully Handled Failures", str(analysis["overall"]["gracefully_handled"]))
    table.add_row("Crashes", str(analysis["overall"]["crashes"]))
    table.add_row("Hangs", str(analysis["overall"]["hangs"]))
    table.add_row("Average Duration", f"{analysis['overall']['avg_duration']:.2f} seconds")
    table.add_row("Resilience Score", f"{analysis['resilience_score']:.1f}%")
    
    console.print(table)
    
    # Create results by scenario table
    console.print("\n[bold cyan]Results by Scenario[/]")
    scenario_table = Table()
    scenario_table.add_column("Scenario", style="cyan")
    scenario_table.add_column("Chaos Action", style="yellow")
    scenario_table.add_column("Result", style="green")
    scenario_table.add_column("Duration (s)", style="blue")
    
    for scenario_id, result in test_results.items():
        scenario = result["scenario"]
        metrics = result["metrics"]
        
        # Determine result string and style
        if metrics["success"]:
            result_str = "Success"
            result_style = "green"
        elif metrics["exit_code"] is not None:
            result_str = f"Graceful Failure (Exit Code: {metrics['exit_code']})"
            result_style = "yellow"
        elif "hang" in metrics.get("error", "").lower() or metrics["duration"] > 30:
            result_str = "Hang"
            result_style = "red"
        else:
            result_str = "Crash"
            result_style = "red"
        
        scenario_table.add_row(
            scenario["name"],
            scenario["chaos_action"],
            f"[{result_style}]{result_str}[/{result_style}]",
            f"{metrics['duration']:.2f}"
        )
    
    console.print(scenario_table)
    
    # Display recommendations
    if analysis["recommendations"]:
        console.print("\n[bold cyan]Recommendations:[/]")
        for i, recommendation in enumerate(analysis["recommendations"], 1):
            console.print(f"[yellow]{i}. {recommendation}[/]")
    
    # Overall assessment
    console.print("\n[bold cyan]Overall Assessment:[/]")
    if analysis["resilience_score"] >= 80:
        console.print("[bold green]The scanner demonstrates excellent resilience to chaos conditions.[/]")
    elif analysis["resilience_score"] >= 50:
        console.print("[bold yellow]The scanner shows moderate resilience, but has room for improvement.[/]")
    else:
        console.print("[bold red]The scanner needs significant improvement in handling unexpected conditions.[/]")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_test(duration=120)
    print(json.dumps(results, indent=2))
