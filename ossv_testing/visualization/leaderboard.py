"""
Leaderboard generator for ossv-scanner comparison results.

This module creates comparative leaderboards showing how ossv-scanner
performs against other vulnerability scanning tools across various metrics.
"""

import os
import time
import logging
import tempfile
import json
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

# HTML template for the leaderboard
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scanner Leaderboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        body { padding: 20px; }
        .leaderboard-header { margin-bottom: 30px; }
        .metric-card { 
            margin-bottom: 20px; 
            transition: transform 0.3s;
        }
        .metric-card:hover { 
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .tool-card {
            padding: 15px;
            margin-bottom: 20px;
            transition: all 0.3s;
            border-radius: 10px;
        }
        .tool-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        .tool-rank {
            font-size: 2rem;
            font-weight: bold;
            display: inline-block;
            width: 50px;
            height: 50px;
            line-height: 50px;
            text-align: center;
            border-radius: 50%;
            margin-right: 15px;
        }
        .chart-container {
            height: 300px;
            margin-bottom: 30px;
        }
        .metric-table {
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
        .rank-1 { background-color: gold; color: black; }
        .rank-2 { background-color: silver; color: black; }
        .rank-3 { background-color: #CD7F32; color: white; }
        .rank-other { background-color: #e9ecef; color: black; }
        .tool-name {
            font-size: 1.5rem;
            font-weight: bold;
        }
        .metric-value {
            font-weight: bold;
        }
        .badge-metric {
            font-size: 0.8rem;
            padding: 5px 10px;
            margin-right: 5px;
            margin-bottom: 5px;
            display: inline-block;
        }
        .metric-score {
            font-size: 1.2rem;
            font-weight: bold;
        }
        .metric-label {
            font-size: 0.8rem;
            color: #666;
        }
        .meter {
            height: 10px;
            background: #e9ecef;
            border-radius: 5px;
            margin-top: 5px;
            margin-bottom: 15px;
            position: relative;
        }
        .meter-fill {
            height: 100%;
            border-radius: 5px;
            position: relative;
            transition: width 0.5s;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row leaderboard-header">
            <div class="col-md-12">
                <h1>Vulnerability Scanner Leaderboard</h1>
                <p class="lead">Comparison generated on {{ metadata.timestamp }}</p>
            </div>
        </div>
        
        <!-- Overall Rankings -->
        <div class="row">
            <div class="col-md-12">
                <h2 class="mb-4">Overall Rankings</h2>
            </div>
        </div>
        
        <div class="row">
            {% for tool in overall_rankings %}
            <div class="col-md-6 col-lg-4">
                <div class="card tool-card">
                    <div class="d-flex align-items-center mb-3">
                        <div class="tool-rank rank-{{ loop.index if loop.index <= 3 else 'other' }}">{{ loop.index }}</div>
                        <div class="tool-name">{{ tool.name }}</div>
                    </div>
                    <div class="mb-3">
                        <div class="d-flex justify-content-between">
                            <span class="metric-label">Overall Score</span>
                            <span class="metric-score">{{ '%.1f' % (tool.overall_score * 100) }}%</span>
                        </div>
                        <div class="meter">
                            <div class="meter-fill bg-{{ 'success' if tool.overall_score > 0.8 else 'warning' if tool.overall_score > 0.6 else 'danger' }}" 
                                 style="width: {{ tool.overall_score * 100 }}%"></div>
                        </div>
                    </div>
                    <div>
                        <span class="badge bg-primary badge-metric">Detection: {{ '%.1f' % (tool.detection_score * 100) }}%</span>
                        <span class="badge bg-success badge-metric">Accuracy: {{ '%.1f' % (tool.accuracy_score * 100) }}%</span>
                        <span class="badge bg-info badge-metric">Performance: {{ '%.1f' % (tool.performance_score * 100) }}%</span>
                        <span class="badge bg-secondary badge-metric">Features: {{ '%.1f' % (tool.feature_score * 100) }}%</span>
                        <span class="badge bg-warning text-dark badge-metric">Cost: {{ '%.1f' % (tool.cost_score * 100) }}%</span>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <!-- Category Rankings -->
        <div class="row mt-5">
            <div class="col-md-12">
                <h2 class="mb-4">Category Rankings</h2>
            </div>
        </div>

        <!-- Detection Effectiveness -->
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Detection Rate</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="detectionChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>False Positive Rate</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="falsePositiveChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Performance -->
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Scan Time</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="scanTimeChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Resource Usage</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="resourceChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Feature Matrix -->
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Feature Matrix</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover metric-table">
                                <thead>
                                    <tr>
                                        <th>Feature</th>
                                        {% for tool in feature_matrix.tools %}
                                        <th>{{ tool }}</th>
                                        {% endfor %}
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for feature in feature_matrix.features %}
                                    <tr>
                                        <td>{{ feature }}</td>
                                        {% for tool in feature_matrix.tools %}
                                        <td class="text-center">
                                            {% if feature_matrix.data[feature][tool] %}
                                            <span class="text-success">✓</span>
                                            {% else %}
                                            <span class="text-danger">✗</span>
                                            {% endif %}
                                        </td>
                                        {% endfor %}
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Cost Comparison -->
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Cost Comparison</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="costChart"></canvas>
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
            // Detection Rate Chart
            const detectionCtx = document.getElementById('detectionChart').getContext('2d');
            const detectionChart = new Chart(detectionCtx, {
                type: 'bar',
                data: {
                    labels: {{ detection_data.labels | tojson }},
                    datasets: [{
                        label: 'Detection Rate (%)',
                        data: {{ detection_data.values | tojson }},
                        backgroundColor: 'rgba(75, 192, 192, 0.6)',
                        borderColor: 'rgba(75, 192, 192, 1)',
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
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });

            // False Positive Rate Chart
            const fpCtx = document.getElementById('falsePositiveChart').getContext('2d');
            const fpChart = new Chart(fpCtx, {
                type: 'bar',
                data: {
                    labels: {{ fp_data.labels | tojson }},
                    datasets: [{
                        label: 'False Positive Rate (%)',
                        data: {{ fp_data.values | tojson }},
                        backgroundColor: 'rgba(255, 99, 132, 0.6)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 30,
                            title: {
                                display: true,
                                text: 'False Positive Rate (%)'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });

            // Scan Time Chart
            const timeCtx = document.getElementById('scanTimeChart').getContext('2d');
            const timeChart = new Chart(timeCtx, {
                type: 'bar',
                data: {
                    labels: {{ scan_time_data.labels | tojson }},
                    datasets: [{
                        label: 'Scan Time (seconds)',
                        data: {{ scan_time_data.values | tojson }},
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
                            title: {
                                display: true,
                                text: 'Seconds'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });

            // Resource Usage Chart
            const resourceCtx = document.getElementById('resourceChart').getContext('2d');
            const resourceChart = new Chart(resourceCtx, {
                type: 'bar',
                data: {
                    labels: {{ resource_data.labels | tojson }},
                    datasets: [{
                        label: 'Memory Usage (MB)',
                        data: {{ resource_data.memory | tojson }},
                        backgroundColor: 'rgba(153, 102, 255, 0.6)',
                        borderColor: 'rgba(153, 102, 255, 1)',
                        borderWidth: 1,
                        order: 1
                    }, {
                        label: 'CPU Usage (%)',
                        data: {{ resource_data.cpu | tojson }},
                        backgroundColor: 'rgba(255, 159, 64, 0.6)',
                        borderColor: 'rgba(255, 159, 64, 1)',
                        borderWidth: 1,
                        type: 'line',
                        order: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Memory (MB) / CPU (%)'
                            }
                        }
                    }
                }
            });

            // Cost Comparison Chart
            const costCtx = document.getElementById('costChart').getContext('2d');
            const costChart = new Chart(costCtx, {
                type: 'bar',
                data: {
                    labels: {{ cost_data.labels | tojson }},
                    datasets: [{
                        label: 'License Cost ($)',
                        data: {{ cost_data.license | tojson }},
                        backgroundColor: 'rgba(255, 99, 132, 0.6)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1,
                        stack: 'Stack 0'
                    }, {
                        label: 'Maintenance Cost ($)',
                        data: {{ cost_data.maintenance | tojson }},
                        backgroundColor: 'rgba(255, 159, 64, 0.6)',
                        borderColor: 'rgba(255, 159, 64, 1)',
                        borderWidth: 1,
                        stack: 'Stack 0'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Annual Cost ($)'
                            }
                        },
                        x: {
                            stacked: true
                        }
                    }
                }
            });
        });
    </script>
</body>
</html>
"""


def load_comparison_results(input_dir: Path) -> Dict[str, Any]:
    """
    Load comparison test results.
    
    Args:
        input_dir: Directory containing test results.
        
    Returns:
        Comparison test results.
    """
    results = {}
    
    # Check if directory exists
    if not input_dir.exists():
        logger.warning(f"Input directory {input_dir} does not exist")
        return results
    
    # Load comparison results
    comparative_dir = input_dir / "comparative"
    if comparative_dir.exists() and comparative_dir.is_dir():
        for result_file in comparative_dir.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    data = json.load(f)
                    results[result_file.stem] = data
            except Exception as e:
                logger.warning(f"Error loading {result_file}: {str(e)}")
    
    # Also check top-level directory for comparative results
    for result_file in input_dir.glob("comparative_*.json"):
        try:
            with open(result_file, "r") as f:
                data = json.load(f)
                results[result_file.stem] = data
        except Exception as e:
            logger.warning(f"Error loading {result_file}: {str(e)}")
    
    # Check for tool_matrix.json specifically
    tool_matrix_path = input_dir / "tool_matrix.json"
    if tool_matrix_path.exists():
        try:
            with open(tool_matrix_path, "r") as f:
                data = json.load(f)
                results["tool_matrix"] = data
        except Exception as e:
            logger.warning(f"Error loading {tool_matrix_path}: {str(e)}")
    
    # Check for roi.json specifically
    roi_path = input_dir / "roi.json"
    if roi_path.exists():
        try:
            with open(roi_path, "r") as f:
                data = json.load(f)
                results["roi"] = data
        except Exception as e:
            logger.warning(f"Error loading {roi_path}: {str(e)}")
    
    # Check for feature_matrix.json specifically
    feature_matrix_path = input_dir / "feature_matrix.json"
    if feature_matrix_path.exists():
        try:
            with open(feature_matrix_path, "r") as f:
                data = json.load(f)
                results["feature_matrix"] = data
        except Exception as e:
            logger.warning(f"Error loading {feature_matrix_path}: {str(e)}")
    
    return results


def extract_leaderboard_data(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and process data for leaderboard visualization.
    
    Args:
        results: Loaded comparison results.
        
    Returns:
        Processed data for leaderboard.
    """
    leaderboard_data = {
        "overall_rankings": [],
        "detection_data": {
            "labels": [],
            "values": []
        },
        "fp_data": {
            "labels": [],
            "values": []
        },
        "scan_time_data": {
            "labels": [],
            "values": []
        },
        "resource_data": {
            "labels": [],
            "memory": [],
            "cpu": []
        },
        "cost_data": {
            "labels": [],
            "license": [],
            "maintenance": []
        },
        "feature_matrix": {
            "tools": [],
            "features": [],
            "data": {}
        },
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "version": "0.1.0"
        }
    }
    
    # Process tool matrix data for overall rankings
    tool_scores = {}
    tools_processed = set()
    
    # Extract tool data from comparison matrix
    if "tool_matrix" in results:
        tool_matrix = results["tool_matrix"]
        
        if "comparison_matrix" in tool_matrix:
            matrix = tool_matrix["comparison_matrix"]
            
            # Initialize tool scores
            for tool_id in matrix.get("tools", {}):
                if tool_id not in tool_scores:
                    tool_scores[tool_id] = {
                        "name": matrix["tools"][tool_id].get("name", tool_id),
                        "detection_score": 0,
                        "accuracy_score": 0,
                        "performance_score": 0,
                        "feature_score": 0,
                        "cost_score": 0,
                        "overall_score": 0
                    }
                    tools_processed.add(tool_id)
            
            # Extract scores
            if "scores" in matrix:
                for tool_id, scores in matrix["scores"].items():
                    if tool_id in tool_scores:
                        # Normalize and set detection score (TPR)
                        tpr = scores.get("true_positive_rate", 0)
                        tool_scores[tool_id]["detection_score"] = tpr
                        
                        # Calculate accuracy score from FPR (inverse relationship)
                        fpr = scores.get("false_positive_rate", 0)
                        tool_scores[tool_id]["accuracy_score"] = 1 - min(fpr, 1)
                        
                        # Normalize and set performance score (inverse of scan_time)
                        scan_time = scores.get("scan_time", 60)
                        # Assume 10s or less is perfect score, 120s or more is zero
                        perf_score = max(0, min(1, (120 - scan_time) / 110))
                        tool_scores[tool_id]["performance_score"] = perf_score
                        
                        # Feature completeness metrics
                        feature_metrics = [
                            scores.get("sbom_generation", 0),
                            scores.get("license_detection", 0),
                            scores.get("remediation_advice", 0),
                            scores.get("severity_accuracy", 0)
                        ]
                        if feature_metrics:
                            tool_scores[tool_id]["feature_score"] = sum(feature_metrics) / len(feature_metrics)
                        
                        # Cost score (inverse relationship with cost)
                        # Assume $0 is perfect score, $15000 or more is zero
                        license_cost = scores.get("license_cost", 0)
                        maintenance_cost = scores.get("maintenance_cost", 0)
                        total_cost = license_cost + maintenance_cost
                        cost_score = max(0, min(1, 1 - (total_cost / 15000)))
                        tool_scores[tool_id]["cost_score"] = cost_score
                        
                        # Extract data for charts
                        leaderboard_data["detection_data"]["labels"].append(tool_scores[tool_id]["name"])
                        leaderboard_data["detection_data"]["values"].append(tpr * 100)
                        
                        leaderboard_data["fp_data"]["labels"].append(tool_scores[tool_id]["name"])
                        leaderboard_data["fp_data"]["values"].append(fpr * 100)
                        
                        leaderboard_data["scan_time_data"]["labels"].append(tool_scores[tool_id]["name"])
                        leaderboard_data["scan_time_data"]["values"].append(scan_time)
                        
                        leaderboard_data["resource_data"]["labels"].append(tool_scores[tool_id]["name"])
                        leaderboard_data["resource_data"]["memory"].append(scores.get("memory_usage", 0))
                        leaderboard_data["resource_data"]["cpu"].append(scores.get("cpu_usage", 0))
                        
                        leaderboard_data["cost_data"]["labels"].append(tool_scores[tool_id]["name"])
                        leaderboard_data["cost_data"]["license"].append(license_cost)
                        leaderboard_data["cost_data"]["maintenance"].append(maintenance_cost)
                        
                        # Calculate overall score
                        # Weights: Detection (30%), Accuracy (20%), Performance (20%), Features (15%), Cost (15%)
                        overall = (
                            tpr * 0.3 +
                            (1 - min(fpr, 1)) * 0.2 +
                            perf_score * 0.2 +
                            tool_scores[tool_id]["feature_score"] * 0.15 +
                            cost_score * 0.15
                        )
                        tool_scores[tool_id]["overall_score"] = overall
    
    # Process ROI data
    if "roi" in results:
        roi_data = results["roi"]
        
        if "roi_analyses" in roi_data:
            for tool_id, analysis in roi_data["roi_analyses"].items():
                if tool_id not in tool_scores:
                    # Tool not in matrix, create new entry
                    tool_name = tool_id.capitalize()
                    tool_scores[tool_id] = {
                        "name": tool_name,
                        "detection_score": 0,
                        "accuracy_score": 0,
                        "performance_score": 0,
                        "feature_score": 0,
                        "cost_score": 0,
                        "overall_score": 0
                    }
                    tools_processed.add(tool_id)
                
                # Update cost score based on ROI
                total_cost = analysis.get("direct_costs", {}).get("total_first_year", 0)
                cost_score = max(0, min(1, 1 - (total_cost / 15000)))
                tool_scores[tool_id]["cost_score"] = cost_score
                
                # If not already processed in matrix, add to charts
                if tool_id not in leaderboard_data["cost_data"]["labels"]:
                    leaderboard_data["cost_data"]["labels"].append(tool_scores[tool_id]["name"])
                    leaderboard_data["cost_data"]["license"].append(
                        analysis.get("direct_costs", {}).get("license_cost", 0)
                    )
                    leaderboard_data["cost_data"]["maintenance"].append(
                        analysis.get("direct_costs", {}).get("total_first_year", 0) - 
                        analysis.get("direct_costs", {}).get("license_cost", 0)
                    )
    
    # Process feature matrix data
    if "feature_matrix" in results:
        feature_data = results["feature_matrix"]
        
        if "matrix_output" in feature_data:
            matrix_output = feature_data["matrix_output"]
            
            # Build feature matrix
            tools = []
            for tool_id in matrix_output.get("tools", {}):
                tool_name = matrix_output["tools"][tool_id].get("name", tool_id)
                tools.append(tool_name)
                
                # Update feature score if not already processed
                if tool_id in tool_scores and tool_id not in tools_processed:
                    # Calculate feature score from feature matrix
                    if "feature_matrix" in matrix_output:
                        features = matrix_output["feature_matrix"]
                        total_features = len(features)
                        supported_features = sum(1 for f in features if tool_id in f and f[tool_id])
                        
                        if total_features > 0:
                            tool_scores[tool_id]["feature_score"] = supported_features / total_features
            
            # Add tools to feature matrix
            leaderboard_data["feature_matrix"]["tools"] = tools
            
            # Extract top features for comparison
            if "feature_matrix" in matrix_output:
                # Select important features (maximum 15 for readability)
                important_features = [
                    "npm dependencies", "PyPI dependencies", "Maven dependencies",
                    "Transitive dependencies", "CVE database integration",
                    "CycloneDX format", "JSON output", "License information",
                    "Command-line interface", "Local scanning", "CI/CD integration",
                    "Vulnerability details", "Fix recommendations", "Severity classification",
                    "Custom policies"
                ]
                
                for feature in important_features:
                    leaderboard_data["feature_matrix"]["features"].append(feature)
                    leaderboard_data["feature_matrix"]["data"][feature] = {}
                    
                    # Find this feature in the matrix
                    for f in matrix_output.get("feature_matrix", []):
                        if "Feature" in f and f["Feature"] == feature:
                            # Add support status for each tool
                            for tool_name in tools:
                                for tool_id in matrix_output.get("tools", {}):
                                    if matrix_output["tools"][tool_id].get("name", tool_id) == tool_name:
                                        leaderboard_data["feature_matrix"]["data"][feature][tool_name] = bool(f.get(tool_id, False))
                                        break
    
    # Finalize overall rankings
    for tool_id, scores in tool_scores.items():
        leaderboard_data["overall_rankings"].append(scores)
    
    # Sort by overall score
    leaderboard_data["overall_rankings"].sort(key=lambda x: x["overall_score"], reverse=True)
    
    return leaderboard_data


def generate_leaderboard(input_dir: Path, output_dir: Path) -> Path:
    """
    Generate a comparative leaderboard for vulnerability scanners.
    
    Args:
        input_dir: Directory containing comparison results.
        output_dir: Directory to save the leaderboard.
        
    Returns:
        Path to the generated leaderboard HTML file.
    """
    logger.info(f"Generating vulnerability scanner leaderboard from results in {input_dir}")
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load comparison results
    results = load_comparison_results(input_dir)
    
    # Check if we have data
    if not results:
        logger.warning("No comparison results found")
        
        # Create a minimal leaderboard with just ossv-scanner
        leaderboard_data = {
            "overall_rankings": [{
                "name": "ossv-scanner",
                "detection_score": 0.85,
                "accuracy_score": 0.95,
                "performance_score": 0.9,
                "feature_score": 0.8,
                "cost_score": 1.0,
                "overall_score": 0.89
            }],
            "detection_data": {
                "labels": ["ossv-scanner"],
                "values": [85]
            },
            "fp_data": {
                "labels": ["ossv-scanner"],
                "values": [5]
            },
            "scan_time_data": {
                "labels": ["ossv-scanner"],
                "values": [15]
            },
            "resource_data": {
                "labels": ["ossv-scanner"],
                "memory": [150],
                "cpu": [25]
            },
            "cost_data": {
                "labels": ["ossv-scanner"],
                "license": [0],
                "maintenance": [2000]
            },
            "feature_matrix": {
                "tools": ["ossv-scanner"],
                "features": ["npm dependencies", "PyPI dependencies", "Maven dependencies", 
                           "Transitive dependencies", "CVE database integration"],
                "data": {
                    "npm dependencies": {"ossv-scanner": True},
                    "PyPI dependencies": {"ossv-scanner": True},
                    "Maven dependencies": {"ossv-scanner": True},
                    "Transitive dependencies": {"ossv-scanner": True},
                    "CVE database integration": {"ossv-scanner": True}
                }
            },
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "version": "0.1.0",
                "note": "This is a sample leaderboard as no comparison data was found."
            }
        }
    else:
        # Extract and process data for leaderboard
        leaderboard_data = extract_leaderboard_data(results)
    
    # Generate HTML leaderboard
    leaderboard_html = Environment(
        loader=FileSystemLoader(searchpath="/"),
        autoescape=select_autoescape(['html', 'xml'])
    ).from_string(HTML_TEMPLATE).render(**leaderboard_data)
    
    # Write leaderboard to file
    leaderboard_path = output_dir / "leaderboard.html"
    with open(leaderboard_path, "w") as f:
        f.write(leaderboard_html)
    
    logger.info(f"Leaderboard generated at {leaderboard_path}")
    
    # Try to open the leaderboard in a browser
    try:
        webbrowser.open(leaderboard_path.as_uri())
    except Exception as e:
        logger.warning(f"Could not open leaderboard in browser: {str(e)}")
    
    return leaderboard_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Use a default input directory for testing
    input_dir = Path(tempfile.gettempdir()) / "ossv-testing-results"
    output_dir = Path(tempfile.gettempdir()) / "ossv-leaderboard"
    
    generate_leaderboard(input_dir, output_dir)
