"""
API integration testing for ossv-scanner.

This module tests the API integration capabilities of ossv-scanner, verifying
that it correctly interacts with external APIs and services.
"""

import os
import time
import logging
import tempfile
import json
import requests
import subprocess
import sys
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import threading
from urllib.parse import urljoin

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# API test configurations
API_TEST_CONFIGS = [
    {
        "id": "basic-api",
        "name": "Basic API Integration",
        "description": "Basic tests for scanner API functionality",
        "api_endpoint": "http://localhost:8080/api/v1/scan",
        "test_files": ["package.json", "requirements.txt"],
        "expected_status": 200,
        "verify_fields": ["vulnerabilities", "dependencies", "scan_time"]
    },
    {
        "id": "async-api",
        "name": "Asynchronous API",
        "description": "Test asynchronous scanning via API",
        "api_endpoint": "http://localhost:8080/api/v1/scan/async",
        "test_files": ["package.json", "pom.xml"],
        "expected_status": 202,
        "verify_fields": ["task_id"]
    },
    {
        "id": "sbom-api",
        "name": "SBOM Generation API",
        "description": "Test SBOM generation via API",
        "api_endpoint": "http://localhost:8080/api/v1/sbom",
        "test_files": ["package.json"],
        "expected_status": 200,
        "verify_fields": ["bomFormat", "specVersion", "components"]
    },
    {
        "id": "webhook-api",
        "name": "Webhook Notification",
        "description": "Test webhook notification for scan completion",
        "api_endpoint": "http://localhost:8080/api/v1/scan/webhook",
        "webhook_endpoint": "http://localhost:9090/webhook",
        "test_files": ["package.json"],
        "expected_status": 202,
        "verify_fields": ["task_id"]
    }
]

# Test project files
TEST_FILES = {
    "package.json": {
        "name": "api-test-project",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.15",  # Known vulnerability
            "express": "4.17.1",   # Potentially vulnerable dependencies
            "axios": "0.21.1"      # Known vulnerability
        }
    },
    "requirements.txt": "\n".join([
        "Django==2.2.8",  # Known vulnerability
        "Flask==0.12.2"   # Known vulnerability
    ]),
    "pom.xml": """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>api-test</artifactId>
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
    </dependencies>
</project>"""
}

def create_test_project(test_config: Dict[str, Any], base_dir: Path) -> Path:
    """
    Create a test project for API testing.
    
    Args:
        test_config: Test configuration.
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created project.
    """
    project_dir = base_dir / test_config["id"]
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create test files
    for filename in test_config["test_files"]:
        if filename in TEST_FILES:
            file_path = project_dir / filename
            content = TEST_FILES[filename]
            
            if isinstance(content, dict):
                with open(file_path, "w") as f:
                    json.dump(content, f, indent=2)
            else:
                with open(file_path, "w") as f:
                    f.write(content)
    
    return project_dir

def start_mock_api_server(port: int = 8080) -> subprocess.Popen:
    """
    Start a mock API server for testing.
    
    In a real implementation, this would either use the actual ossv-scanner API
    or a more sophisticated mock. For testing purposes, we'll use a simple
    Flask-based mock server.
    
    Args:
        port: Port for the mock server.
        
    Returns:
        Subprocess of the mock server.
    """
    # Create temporary script for mock server
    temp_dir = Path(tempfile.mkdtemp(prefix="ossv-api-mock-"))
    server_script = temp_dir / "mock_server.py"
    
    with open(server_script, "w") as f:
        f.write("""
import flask
import time
import json
import uuid
import threading
import sys

app = flask.Flask(__name__)
pending_tasks = {}

@app.route('/api/v1/scan', methods=['POST'])
def handle_scan():
    # Simulate scanning
    time.sleep(1)
    
    # Return mock results
    return flask.jsonify({
        'vulnerabilities': {
            'lodash@4.17.15': [
                {'cve_id': 'CVE-2019-10744', 'severity': 'HIGH'}
            ],
            'axios@0.21.1': [
                {'cve_id': 'CVE-2021-3749', 'severity': 'HIGH'}
            ],
            'Django@2.2.8': [
                {'cve_id': 'CVE-2019-19844', 'severity': 'HIGH'}
            ]
        },
        'dependencies': ['lodash@4.17.15', 'express@4.17.1', 'axios@0.21.1', 'Django@2.2.8'],
        'scan_time': 1.2
    })

@app.route('/api/v1/scan/async', methods=['POST'])
def handle_async_scan():
    # Generate task ID
    task_id = str(uuid.uuid4())
    
    # Start background task
    def background_task():
        time.sleep(3)  # Simulate processing time
        pending_tasks[task_id] = {
            'status': 'completed',
            'result': {
                'vulnerabilities': {
                    'lodash@4.17.15': [
                        {'cve_id': 'CVE-2019-10744', 'severity': 'HIGH'}
                    ]
                },
                'dependencies': ['lodash@4.17.15', 'express@4.17.1']
            }
        }
    
    threading.Thread(target=background_task).start()
    pending_tasks[task_id] = {'status': 'pending'}
    
    return flask.jsonify({'task_id': task_id}), 202

@app.route('/api/v1/scan/status/<task_id>', methods=['GET'])
def handle_task_status(task_id):
    if task_id not in pending_tasks:
        return flask.jsonify({'error': 'Task not found'}), 404
    
    return flask.jsonify(pending_tasks[task_id])

@app.route('/api/v1/sbom', methods=['POST'])
def handle_sbom():
    # Simulate SBOM generation
    time.sleep(1)
    
    # Return mock SBOM
    return flask.jsonify({
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'components': [
            {'name': 'lodash', 'version': '4.17.15', 'purl': 'pkg:npm/lodash@4.17.15'},
            {'name': 'express', 'version': '4.17.1', 'purl': 'pkg:npm/express@4.17.1'},
        ]
    })

@app.route('/api/v1/scan/webhook', methods=['POST'])
def handle_webhook():
    # Get webhook URL from request
    data = flask.request.json
    webhook_url = data.get('webhook_url')
    
    if not webhook_url:
        return flask.jsonify({'error': 'Missing webhook_url parameter'}), 400
    
    # Generate task ID
    task_id = str(uuid.uuid4())
    
    # Start background task with webhook notification
    def background_task_webhook():
        time.sleep(2)  # Simulate processing time
        
        # Send webhook notification
        import requests
        try:
            requests.post(webhook_url, json={
                'task_id': task_id,
                'status': 'completed',
                'result': {
                    'vulnerabilities': {
                        'lodash@4.17.15': [
                            {'cve_id': 'CVE-2019-10744', 'severity': 'HIGH'}
                        ]
                    }
                }
            })
        except Exception as e:
            print(f"Webhook notification failed: {e}")
    
    threading.Thread(target=background_task_webhook).start()
    
    return flask.jsonify({'task_id': task_id}), 202

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    app.run(host='0.0.0.0', port=port)
""")
    
    # Start the mock server
    server_process = subprocess.Popen(
        [sys.executable, str(server_script), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for server to start
    time.sleep(2)
    
    return server_process

def start_webhook_receiver(port: int = 9090) -> Tuple[subprocess.Popen, Path]:
    """
    Start a webhook receiver for testing webhook notifications.
    
    Args:
        port: Port for the webhook receiver.
        
    Returns:
        Tuple of (server process, results file path).
    """
    # Create temporary script and results file
    temp_dir = Path(tempfile.mkdtemp(prefix="ossv-webhook-"))
    server_script = temp_dir / "webhook_receiver.py"
    results_file = temp_dir / "webhook_results.json"
    
    with open(server_script, "w") as f:
        f.write(f"""
import flask
import json
import sys
import time

app = flask.Flask(__name__)
results_file = "{str(results_file).replace('\\', '\\\\')}"

@app.route('/webhook', methods=['POST'])
def webhook():
    # Save webhook payload
    data = flask.request.json
    with open(results_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    return flask.jsonify({{'received': True}})

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    app.run(host='0.0.0.0', port=port)
""")
    
    # Start the webhook receiver
    server_process = subprocess.Popen(
        [sys.executable, str(server_script), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for server to start
    time.sleep(2)
    
    return server_process, results_file

def run_api_test(test_config: Dict[str, Any], project_dir: Path) -> Dict[str, Any]:
    """
    Run an API test according to the provided configuration.
    
    Args:
        test_config: Test configuration.
        project_dir: Path to the test project.
        
    Returns:
        Test results.
    """
    results = {
        "test_id": test_config["id"],
        "name": test_config["name"],
        "success": False,
        "status_code": None,
        "response": None,
        "error": None,
        "webhook_result": None,
        "verification": {}
    }
    
    try:
        # Prepare files for upload
        files = {}
        for filename in test_config["test_files"]:
            file_path = project_dir / filename
            if file_path.exists():
                files[filename] = open(file_path, "rb")
        
        # Prepare API request based on test type
        if test_config["id"] == "webhook-api":
            # Webhook test requires additional webhook URL
            data = {
                "webhook_url": test_config["webhook_endpoint"]
            }
            response = requests.post(
                test_config["api_endpoint"],
                files=files,
                data=data
            )
        else:
            # Standard API request
            response = requests.post(
                test_config["api_endpoint"],
                files=files
            )
        
        # Close file handles
        for f in files.values():
            f.close()
        
        # Record response
        results["status_code"] = response.status_code
        results["success"] = response.status_code == test_config["expected_status"]
        
        try:
            results["response"] = response.json()
        except:
            results["response"] = response.text
        
        # Verify expected fields
        for field in test_config["verify_fields"]:
            if isinstance(results["response"], dict):
                results["verification"][field] = field in results["response"]
        
        # Special handling for async API to check task status
        if test_config["id"] == "async-api" and results["success"]:
            task_id = results["response"].get("task_id")
            if task_id:
                # Wait briefly for task to complete
                time.sleep(3)
                
                # Check task status
                status_url = urljoin(test_config["api_endpoint"], f"../status/{task_id}")
                status_response = requests.get(status_url)
                if status_response.status_code == 200:
                    results["task_status"] = status_response.json()
                    results["task_completed"] = results["task_status"].get("status") == "completed"
        
    except Exception as e:
        results["success"] = False
        results["error"] = str(e)
    
    return results

def wait_for_webhook_result(webhook_results_file: Path, timeout: int = 30) -> Dict[str, Any]:
    """
    Wait for webhook notification result.
    
    Args:
        webhook_results_file: Path to the webhook results file.
        timeout: Maximum time to wait in seconds.
        
    Returns:
        Webhook result data or empty dict if timeout.
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if webhook_results_file.exists():
            try:
                with open(webhook_results_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                # File might be in the process of being written
                pass
        
        time.sleep(0.5)
    
    return {}

def run_tests(basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run API integration tests.
    
    Args:
        basic: Whether to run a basic subset of tests.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting API integration tests")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-api-tests-"))
    results_dir = base_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Select test configurations
    if basic:
        # Use a minimal set of tests for basic testing
        selected_configs = [API_TEST_CONFIGS[0]]  # Just the basic API test
    elif comprehensive:
        # Use all test configurations
        selected_configs = API_TEST_CONFIGS
    else:
        # Default to the first two tests
        selected_configs = API_TEST_CONFIGS[:2]
    
    # Start mock API server
    logger.info("Starting mock API server")
    api_server = start_mock_api_server()
    
    # Start webhook receiver if needed
    webhook_server = None
    webhook_results_file = None
    if any(config["id"] == "webhook-api" for config in selected_configs):
        logger.info("Starting webhook receiver")
        webhook_server, webhook_results_file = start_webhook_receiver()
    
    # Run tests
    test_results = {}
    
    with Progress() as progress:
        task = progress.add_task("[green]Running API tests...", total=len(selected_configs))
        
        for config in selected_configs:
            logger.info(f"Testing {config['name']} ({config['id']})")
            
            # Create test project
            project_dir = create_test_project(config, base_dir)
            
            # Run test
            result = run_api_test(config, project_dir)
            
            # Special handling for webhook test
            if config["id"] == "webhook-api" and result["success"] and webhook_results_file:
                # Wait for webhook notification
                webhook_result = wait_for_webhook_result(webhook_results_file)
                result["webhook_result"] = webhook_result
                
                # Check if webhook contains expected data
                if webhook_result:
                    result["webhook_success"] = all(
                        key in webhook_result for key in ["task_id", "status", "result"]
                    )
                else:
                    result["webhook_success"] = False
            
            # Store results
            test_results[config["id"]] = result
            
            progress.update(task, advance=1)
    
    # Shutdown mock servers
    if api_server:
        logger.info("Shutting down mock API server")
        api_server.terminate()
    
    if webhook_server:
        logger.info("Shutting down webhook receiver")
        webhook_server.terminate()
    
    # Calculate summary metrics
    successful_tests = sum(1 for result in test_results.values() if result["success"])
    total_tests = len(test_results)
    
    summary = {
        "total_tests": total_tests,
        "successful_tests": successful_tests,
        "failed_tests": total_tests - successful_tests,
        "success_rate": successful_tests / total_tests if total_tests > 0 else 0
    }
    
    # Prepare final results
    final_results = {
        "base_dir": str(base_dir),
        "results_dir": str(results_dir),
        "test_results": test_results,
        "summary": summary,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard"
        }
    }
    
    # Display summary
    display_summary(summary, test_results)
    
    logger.info("API integration tests completed")
    return final_results

def display_summary(summary: Dict[str, Any], test_results: Dict[str, Dict[str, Any]]) -> None:
    """
    Display a summary of API test results.
    
    Args:
        summary: Summary metrics.
        test_results: Detailed test results.
    """
    console.print("\n[bold cyan]API Integration Test Summary[/]")
    
    # Create a summary table
    table = Table(title="API Test Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Percentage", style="yellow")
    
    table.add_row(
        "Total Tests",
        str(summary["total_tests"]),
        ""
    )
    table.add_row(
        "Successful Tests",
        str(summary["successful_tests"]),
        f"{summary['success_rate']:.1%}"
    )
    table.add_row(
        "Failed Tests",
        str(summary["failed_tests"]),
        f"{1 - summary['success_rate']:.1%}"
    )
    
    console.print(table)
    
    # Create a detailed results table
    detail_table = Table(title="Detailed Test Results")
    detail_table.add_column("Test", style="cyan")
    detail_table.add_column("Endpoint", style="blue")
    detail_table.add_column("Status", style="green")
    detail_table.add_column("Status Code", style="yellow")
    detail_table.add_column("Notes", style="magenta")
    
    for test_id, result in test_results.items():
        config = next((c for c in API_TEST_CONFIGS if c["id"] == test_id), None)
        if not config:
            continue
            
        status = "[green]PASS[/green]" if result["success"] else "[red]FAIL[/red]"
        status_code = str(result["status_code"]) if result["status_code"] else "N/A"
        
        notes = []
        if result.get("error"):
            notes.append(f"Error: {result['error']}")
        
        if "webhook_success" in result:
            webhook_status = "received" if result["webhook_success"] else "not received"
            notes.append(f"Webhook: {webhook_status}")
        
        if "task_completed" in result:
            task_status = "completed" if result["task_completed"] else "pending"
            notes.append(f"Task: {task_status}")
        
        detail_table.add_row(
            result["name"],
            config["api_endpoint"],
            status,
            status_code,
            ", ".join(notes) if notes else ""
        )
    
    console.print(detail_table)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import sys
    results = run_tests()
    sys.exit(0 if results["summary"]["failed_tests"] == 0 else 1)