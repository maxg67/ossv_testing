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
    
    return results


def extract_dashboard_data(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and process data for dashboard visualization.
    
    Args:
        results: Consolidated test results.
        
    Returns:
        Processed data for dashboard.
    """
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
            projects = sorted(
                [(k, v) for k, v in test_data["test_results"].items()],
                key=lambda x: x[1].get("config", {}).get("npm_deps", 0) + 
                              x[1].get("config", {}).get("python_deps", 0) + 
                              x[1].get("config", {}).get("java_deps", 0)
            )
            
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
    
    return dashboard_data


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
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load test results
    results = load_test_results(input_dir)
    
    # Extract and process data for dashboard
    dashboard_data = extract_dashboard_data(results)
    
    # Generate HTML dashboard
    dashboard_html = Environment(
        loader=FileSystemLoader(searchpath="/"),
        autoescape=select_autoescape(['html', 'xml'])
    ).from_string(HTML_TEMPLATE).render(**dashboard_data)
    
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Use a default input directory for testing
    input_dir = Path(tempfile.gettempdir()) / "ossv-testing-results"
    output_dir = Path(tempfile.gettempdir()) / "ossv-dashboard"
    
    generate_dashboard(input_dir, output_dir)
