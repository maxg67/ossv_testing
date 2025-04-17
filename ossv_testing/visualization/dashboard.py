"""
Dashboard generator for ossv-scanner test results.

This module creates interactive dashboards to visualize and explore
the results of ossv-scanner tests, with performance metrics, coverage analysis,
and interactive filtering.
"""

import os
import time
import logging
import tempfile
import json
import subprocess
import webbrowser
import types
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles non-serializable objects."""
    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, (types.FunctionType, types.BuiltinFunctionType, types.MethodType)):
            return f"<function {obj.__name__}>"
        elif callable(obj):
            return "<callable object>"
        elif hasattr(obj, '__dict__'):
            return f"<{obj.__class__.__name__} object>"
        return super().default(obj)
    
def safe_json_dump(data, file_path):
    """Safely dump data to JSON, handling non-serializable objects."""
    with open(file_path, 'w') as f:
        json.dump(data, f, cls=CustomJSONEncoder, indent=2)

def safe_json_dumps(data):
    """Safely convert data to JSON string, handling non-serializable objects."""
    return json.dumps(data, cls=CustomJSONEncoder)

# Monkey patch the json module to use our custom encoder
_original_dumps = json.dumps
_original_dump = json.dump

def safe_dumps(*args, **kwargs):
    if 'cls' not in kwargs:
        kwargs['cls'] = CustomJSONEncoder
    return _original_dumps(*args, **kwargs)

def safe_dump(*args, **kwargs):
    if 'cls' not in kwargs:
        kwargs['cls'] = CustomJSONEncoder
    return _original_dump(*args, **kwargs)

json.dumps = safe_dumps
json.dump = safe_dump

# Add this after the imports
def convert_paths(results):
    """
    Recursively convert any Path objects to strings for JSON serialization.
    Also handles non-serializable types like functions.
    
    Args:
        results: Object to convert (can be dict, list, Path, or other type).
        
    Returns:
        Object with all Path objects converted to strings and non-serializable objects converted to their string representation.
    """
    import types
    from pathlib import Path
    
    if isinstance(results, dict):
        return {key: convert_paths(value) for key, value in results.items()}
    elif isinstance(results, list):
        return [convert_paths(item) for item in results]
    elif isinstance(results, Path):
        return str(results)  # Convert Path object to string
    elif isinstance(results, (types.FunctionType, types.BuiltinFunctionType, types.MethodType)):
        return f"<function {results.__name__}>"  # Convert function to string representation
    elif hasattr(results, '__dict__'):  # Handle custom objects
        return f"<{results.__class__.__name__} object>"
    return results

logger = logging.getLogger(__name__)
console = Console()

# HTML template for the dashboard
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSSV Scanner Test Results Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        body { padding: 20px; }
        .dashboard-header { margin-bottom: 30px; }
        .metric-card { 
            margin-bottom: 20px; 
            transition: transform 0.3s;
        }
        .metric-card:hover { 
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .metric-value { 
            font-size: 2rem; 
            font-weight: bold;
        }
        .chart-container {
            height: 300px;
            margin-bottom: 30px;
        }
        .data-table {
            font-size: 0.9rem;
            margin-top: 30px;
        }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 0.8rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row dashboard-header">
            <div class="col-md-12">
                <h1>OSSV Scanner Test Results Dashboard</h1>
                <p class="lead">Test results generated on {{ metadata.timestamp }}</p>
            </div>
        </div>
        
        <!-- Summary Metrics -->
        <div class="row">
            <div class="col-md-3">
                <div class="card metric-card bg-light">
                    <div class="card-body text-center">
                        <h5 class="card-title">Overall Detection Rate</h5>
                        <div class="metric-value text-success">{{ '%.1f' % (summary.detection_rate * 100) }}%</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card bg-light">
                    <div class="card-body text-center">
                        <h5 class="card-title">False Positive Rate</h5>
                        <div class="metric-value text-{{ 'success' if summary.false_positive_rate < 0.1 else 'warning' if summary.false_positive_rate < 0.2 else 'danger' }}">
                            {{ '%.1f' % (summary.false_positive_rate * 100) }}%
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card bg-light">
                    <div class="card-body text-center">
                        <h5 class="card-title">Average Scan Time</h5>
                        <div class="metric-value text-primary">{{ '%.2f' % summary.avg_scan_time }}s</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card bg-light">
                    <div class="card-body text-center">
                        <h5 class="card-title">Total Tests Run</h5>
                        <div class="metric-value text-info">{{ summary.total_tests }}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Detection Rate by Ecosystem
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="ecosystemChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Detection by Severity
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Performance Metrics
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="performanceChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Test Success Rate
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="successRateChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Tables -->
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <div class="d-flex justify-content-between align-items-center">
                            <span>Detailed Test Results</span>
                            <div>
                                <input type="text" id="tableSearch" class="form-control form-control-sm" placeholder="Search...">
                            </div>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover data-table" id="resultsTable">
                                <thead>
                                    <tr>
                                        <th>Test ID</th>
                                        <th>Test Type</th>
                                        <th>Ecosystem</th>
                                        <th>True Positives</th>
                                        <th>False Negatives</th>
                                        <th>False Positives</th>
                                        <th>Detection Rate</th>
                                        <th>Scan Time (s)</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for test in detailed_results %}
                                    <tr>
                                        <td>{{ test.id }}</td>
                                        <td>{{ test.type }}</td>
                                        <td>{{ test.ecosystem }}</td>
                                        <td>{{ test.true_positives }}</td>
                                        <td>{{ test.false_negatives }}</td>
                                        <td>{{ test.false_positives }}</td>
                                        <td>{{ '%.1f' % (test.detection_rate * 100) }}%</td>
                                        <td>{{ '%.2f' % test.scan_time }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer text-center">
            <p>Generated by OSSV Testing Framework - Version {{ metadata.version }}</p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Initialize charts
        document.addEventListener('DOMContentLoaded', function() {
            // Ecosystem Chart
            const ecosystemCtx = document.getElementById('ecosystemChart').getContext('2d');
            const ecosystemChart = new Chart(ecosystemCtx, {
                type: 'bar',
                data: {
                    labels: {{ ecosystem_data.labels | tojson }},
                    datasets: [{
                        label: 'Detection Rate (%)',
                        data: {{ ecosystem_data.values | tojson }},
                        backgroundColor: 'rgba(54, 162, 235, 0.6)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            title: {
                                display: true,
                                text: 'Detection Rate (%)'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Ecosystem'
                            }
                        }
                    }
                }
            });

            // Severity Chart
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            const severityChart = new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: {{ severity_data.labels | tojson }},
                    datasets: [{
                        data: {{ severity_data.values | tojson }},
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(255, 159, 64, 0.7)',
                            'rgba(255, 205, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)',
                        ],
                        borderColor: [
                            'rgb(255, 99, 132)',
                            'rgb(255, 159, 64)',
                            'rgb(255, 205, 86)',
                            'rgb(75, 192, 192)',
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                        },
                        title: {
                            display: true,
                            text: 'Vulnerabilities by Severity'
                        }
                    }
                }
            });

            // Performance Chart
            const perfCtx = document.getElementById('performanceChart').getContext('2d');
            const perfChart = new Chart(perfCtx, {
                type: 'line',
                data: {
                    labels: {{ performance_data.labels | tojson }},
                    datasets: [{
                        label: 'Scan Time (s)',
                        data: {{ performance_data.scan_time | tojson }},
                        borderColor: 'rgba(75, 192, 192, 1)',
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        tension: 0.1,
                        yAxisID: 'y'
                    }, {
                        label: 'Memory (MB)',
                        data: {{ performance_data.memory | tojson }},
                        borderColor: 'rgba(153, 102, 255, 1)',
                        backgroundColor: 'rgba(153, 102, 255, 0.2)',
                        tension: 0.1,
                        yAxisID: 'y1'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            type: 'linear',
                            display: true,
                            position: 'left',
                            title: {
                                display: true,
                                text: 'Scan Time (s)'
                            }
                        },
                        y1: {
                            type: 'linear',
                            display: true,
                            position: 'right',
                            grid: {
                                drawOnChartArea: false,
                            },
                            title: {
                                display: true,
                                text: 'Memory (MB)'
                            }
                        }
                    }
                }
            });
            
            // Success Rate Chart
            const successCtx = document.getElementById('successRateChart').getContext('2d');
            const successChart = new Chart(successCtx, {
                type: 'pie',
                data: {
                    labels: ['Successful Tests', 'Failed Tests'],
                    datasets: [{
                        data: [
                            {{ summary.successful_tests }},
                            {{ summary.total_tests - summary.successful_tests }}
                        ],
                        backgroundColor: [
                            'rgba(75, 192, 192, 0.7)',
                            'rgba(255, 99, 132, 0.7)'
                        ],
                        borderColor: [
                            'rgb(75, 192, 192)',
                            'rgb(255, 99, 132)'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                        },
                        title: {
                            display: true,
                            text: 'Test Success Rate'
                        }
                    }
                }
            });

            // Table search functionality
            document.getElementById('tableSearch').addEventListener('keyup', function() {
                const searchTerm = this.value.toLowerCase();
                const table = document.getElementById('resultsTable');
                const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
                
                Array.from(rows).forEach(row => {
                    let found = false;
                    Array.from(row.getElementsByTagName('td')).forEach(cell => {
                        if (cell.textContent.toLowerCase().indexOf(searchTerm) > -1) {
                            found = true;
                        }
                    });
                    row.style.display = found ? '' : 'none';
                });
            });
        });
    </script>
</body>
</html>
"""


def load_test_results(input_dir: Path) -> Dict[str, Any]:
    """
    Load test results from the specified directory.
    
    Args:
        input_dir: Directory containing test results.
        
    Returns:
        Consolidated test results.
    """
    """Load test results from the specified directory."""
    logger.info(f"Loading results from: {input_dir} (exists: {input_dir.exists()})")
    
    # List all files in directory
    if input_dir.exists():
        all_files = list(input_dir.glob('**/*.json'))
        logger.info(f"Found {len(all_files)} JSON files")
        if len(all_files) > 0:
            logger.info(f"Sample files: {all_files[:5]}")
            
    results = {
        "controlled": {},
        "benchmark": {},
        "performance": {},
        "comparative": {},
        "statistics": {}
    }
    
    # Check if directory exists
    if not input_dir.exists():
        logger.warning(f"Input directory {input_dir} does not exist")
        return results
    
    # Load results from subdirectories
    for category in results:
        category_dir = input_dir / category
        if category_dir.exists() and category_dir.is_dir():
            for result_file in category_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        data = json.load(f)
                        results[category][result_file.stem] = data
                except Exception as e:
                    logger.warning(f"Error loading {result_file}: {str(e)}")
    
    # Also check for top-level result files
    for result_file in input_dir.glob("*.json"):
        try:
            with open(result_file, "r") as f:
                data = json.load(f)
                # Determine category based on file name or content
                if "benchmark" in result_file.stem:
                    results["benchmark"][result_file.stem] = data
                elif "controlled" in result_file.stem:
                    results["controlled"][result_file.stem] = data
                elif "performance" in result_file.stem:
                    results["performance"][result_file.stem] = data
                elif "comparative" in result_file.stem:
                    results["comparative"][result_file.stem] = data
                elif "statistics" in result_file.stem:
                    results["statistics"][result_file.stem] = data
        except Exception as e:
            logger.warning(f"Error loading {result_file}: {str(e)}")
    
    # Sanitize loaded results to handle non-serializable objects
    return sanitize_for_json(results)


def extract_dashboard_data(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and process data for dashboard visualization.
    
    Args:
        results: Consolidated test results.
        
    Returns:
        Processed data for dashboard.
    """
    # First, sanitize the input results to handle any non-serializable objects
    results = sanitize_for_json(results)
    
    dashboard_data = {
        "summary": {
            "total_tests": 0,
            "successful_tests": 0,
            "detection_rate": 0.0,
            "false_positive_rate": 0.0,
            "avg_scan_time": 0.0,
        },
        "detailed_results": [],
        "ecosystem_data": {
            "labels": [],
            "values": []
        },
        "severity_data": {
            "labels": ["Critical", "High", "Medium", "Low"],
            "values": [0, 0, 0, 0]
        },
        "performance_data": {
            "labels": [],
            "scan_time": [],
            "memory": []
        },
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "version": "0.1.0"
        }
    }
    
    # Track totals for averages
    total_true_positives = 0
    total_false_negatives = 0
    total_false_positives = 0
    total_scan_time = 0
    scan_time_count = 0
    ecosystem_counts = {}
    ecosystem_detected = {}
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }
    
    # Extract data from controlled tests
    for test_id, test_data in results.get("controlled", {}).items():
        if "test_cases" in test_data:
            for case_id, case in test_data["test_cases"].items():
                if "analysis" not in case:
                    continue
                
                analysis = case["analysis"]
                metrics = analysis.get("metrics", {})
                
                # Add to detailed results
                dashboard_data["detailed_results"].append({
                    "id": case_id,
                    "type": "controlled",
                    "ecosystem": case.get("ecosystem", "Unknown"),
                    "true_positives": metrics.get("true_positives", 0),
                    "false_negatives": metrics.get("false_negatives", 0),
                    "false_positives": metrics.get("false_positives", 0),
                    "detection_rate": metrics.get("true_positives", 0) / 
                                  (metrics.get("true_positives", 0) + metrics.get("false_negatives", 0))
                                  if (metrics.get("true_positives", 0) + metrics.get("false_negatives", 0)) > 0 else 0,
                    "scan_time": 0  # No scan time in controlled tests
                })
                
                # Update totals
                total_true_positives += metrics.get("true_positives", 0)
                total_false_negatives += metrics.get("false_negatives", 0)
                total_false_positives += metrics.get("false_positives", 0)
                
                # Update ecosystem data
                ecosystem = case.get("ecosystem", "Unknown")
                if ecosystem not in ecosystem_counts:
                    ecosystem_counts[ecosystem] = 0
                    ecosystem_detected[ecosystem] = 0
                
                expected_vulns = metrics.get("true_positives", 0) + metrics.get("false_negatives", 0)
                ecosystem_counts[ecosystem] += expected_vulns
                ecosystem_detected[ecosystem] += metrics.get("true_positives", 0)
                
                # Update severity data (if available)
                for vuln in analysis.get("detected_vulns", []):
                    severity = vuln.get("expected", {}).get("severity", "Unknown")
                    if severity.upper() == "CRITICAL":
                        severity_counts["Critical"] += 1
                    elif severity.upper() == "HIGH":
                        severity_counts["High"] += 1
                    elif severity.upper() == "MEDIUM":
                        severity_counts["Medium"] += 1
                    elif severity.upper() == "LOW":
                        severity_counts["Low"] += 1
    
    # Extract data from benchmark tests
    for test_id, test_data in results.get("benchmark", {}).items():
        if "scanner_results" in test_data:
            scanner_results = test_data["scanner_results"]
            
            # Add to detailed results
            dashboard_data["detailed_results"].append({
                "id": test_id,
                "type": "benchmark",
                "ecosystem": "Mixed",  # Benchmarks typically cover multiple ecosystems
                "true_positives": scanner_results.get("detected_vulns", 0),
                "false_negatives": scanner_results.get("missed_vulns", 0),
                "false_positives": 0,  # May not be available in all benchmarks
                "detection_rate": scanner_results.get("detection_rate", 0),
                "scan_time": scanner_results.get("scan_time", 0)
            })
            
            # Update totals
            total_true_positives += scanner_results.get("detected_vulns", 0)
            total_false_negatives += scanner_results.get("missed_vulns", 0)
            if "scan_time" in scanner_results:
                total_scan_time += scanner_results["scan_time"]
                scan_time_count += 1
    
    # Extract data from performance tests
    for test_id, test_data in results.get("performance", {}).items():
        if "test_results" in test_data:
            # Get sorted project sizes for x-axis
            try:
                projects = sorted(
                    [(k, v) for k, v in test_data["test_results"].items()],
                    key=lambda x: x[1].get("config", {}).get("npm_deps", 0) + 
                                x[1].get("config", {}).get("python_deps", 0) + 
                                x[1].get("config", {}).get("java_deps", 0)
                )
            except Exception as e:
                logger.warning(f"Error sorting performance projects: {str(e)}")
                projects = list(test_data["test_results"].items())
            
            for project_id, project_data in projects:
                # Skip if no metrics
                if "metrics" not in project_data:
                    continue
                
                metrics = project_data["metrics"]
                config = project_data.get("config", {})
                
                # Add to performance data
                size = config.get("npm_deps", 0) + config.get("python_deps", 0) + config.get("java_deps", 0)
                dashboard_data["performance_data"]["labels"].append(str(size))
                dashboard_data["performance_data"]["scan_time"].append(metrics.get("duration", 0))
                dashboard_data["performance_data"]["memory"].append(metrics.get("memory_usage", 0))
                
                # Add to detailed results
                dashboard_data["detailed_results"].append({
                    "id": project_id,
                    "type": "performance",
                    "ecosystem": "Mixed",
                    "true_positives": 0,  # Not applicable for performance tests
                    "false_negatives": 0,
                    "false_positives": 0,
                    "detection_rate": 0,
                    "scan_time": metrics.get("duration", 0)
                })
                
                # Update totals
                if "duration" in metrics:
                    total_scan_time += metrics["duration"]
                    scan_time_count += 1
                
                # Update success count
                if metrics.get("success", False):
                    dashboard_data["summary"]["successful_tests"] += 1
    
    # Calculate ecosystem detection rates
    for ecosystem, total in ecosystem_counts.items():
        if total > 0:
            dashboard_data["ecosystem_data"]["labels"].append(ecosystem)
            detection_rate = (ecosystem_detected[ecosystem] / total) * 100
            dashboard_data["ecosystem_data"]["values"].append(detection_rate)
    
    # Update severity data
    dashboard_data["severity_data"]["values"] = [
        severity_counts["Critical"],
        severity_counts["High"],
        severity_counts["Medium"],
        severity_counts["Low"]
    ]
    
    # Set summary metrics
    dashboard_data["summary"]["total_tests"] = len(dashboard_data["detailed_results"])
    
    total_expected = total_true_positives + total_false_negatives
    if total_expected > 0:
        dashboard_data["summary"]["detection_rate"] = total_true_positives / total_expected
    
    total_detected = total_true_positives + total_false_positives
    if total_detected > 0:
        dashboard_data["summary"]["false_positive_rate"] = total_false_positives / total_detected
    
    if scan_time_count > 0:
        dashboard_data["summary"]["avg_scan_time"] = total_scan_time / scan_time_count
    
    # Final sanitization to ensure all data is JSON-serializable
    return sanitize_for_json(dashboard_data)

def sanitize_for_json(obj):
    """Recursively sanitize an object for JSON serialization."""
    import types
    from pathlib import Path
    
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(item) for item in obj]
    elif isinstance(obj, (types.FunctionType, types.BuiltinFunctionType, types.MethodType)):
        return f"<function {obj.__name__}>"
    elif callable(obj):
        return "<callable object>"
    elif isinstance(obj, Path):
        return str(obj)
    elif hasattr(obj, '__dict__') and not isinstance(obj, (str, int, float, bool, type(None))):
        return f"<{obj.__class__.__name__} object>"
    return obj


def generate_dashboard(input_dir: Path, output_dir: Path) -> Path:
    """
    Generate an interactive HTML dashboard from test results.
    
    Args:
        input_dir: Directory containing test results.
        output_dir: Directory to save the dashboard.
        
    Returns:
        Path to the generated dashboard HTML file.
    """
    logger.info(f"Generating dashboard from results in {input_dir}")
    
    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load test results
        logger.debug("Loading test results...")
        results = load_test_results(input_dir)
        
        # Extract and process data for dashboard
        logger.debug("Extracting dashboard data...")
        dashboard_data = extract_dashboard_data(results)
        
        # Test JSON serialization before rendering
        try:
            logger.debug("Testing JSON serialization...")
            test_json = safe_json_dumps(dashboard_data)
        except Exception as e:
            logger.warning(f"Data serialization test failed: {str(e)}")
            # Apply deeper sanitization
            logger.debug("Applying deeper sanitization...")
            dashboard_data = sanitize_for_json(dashboard_data)
        
        # Generate HTML dashboard
        logger.debug("Generating HTML dashboard...")
        env = Environment(
            loader=FileSystemLoader("/"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        try:
            template = env.from_string(HTML_TEMPLATE)
            dashboard_html = template.render(**dashboard_data)
        except Exception as e:
            logger.error(f"Error rendering template: {str(e)}")
            raise
        
        # Write dashboard to file
        dashboard_path = output_dir / "dashboard.html"
        with open(dashboard_path, "w") as f:
            f.write(dashboard_html)
        
        logger.info(f"Dashboard generated at {dashboard_path}")
        
        # Try to open the dashboard in a browser
        try:
            webbrowser.open(dashboard_path.as_uri())
        except Exception as e:
            logger.warning(f"Could not open dashboard in browser: {str(e)}")
        
        return dashboard_path
        
    except Exception as e:
        logger.error(f"Error generating dashboard: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
        raise

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Use a default input directory for testing
    input_dir = Path(tempfile.gettempdir()) / "ossv-testing-results"
    output_dir = Path(tempfile.gettempdir()) / "ossv-dashboard"
    
    generate_dashboard(input_dir, output_dir)