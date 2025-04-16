"""
Report generator for ossv-scanner test results.

This module creates detailed PDF reports from test results, including
comprehensive analysis, visualizations, statistics, and recommendations.
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
from datetime import datetime
import io

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, ListFlowable, ListItem
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from rich.console import Console
from rich.progress import Progress

logger = logging.getLogger(__name__)
console = Console()


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


def extract_report_data(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and process data for report generation.
    
    Args:
        results: Consolidated test results.
        
    Returns:
        Processed data for report.
    """
    report_data = {
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
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "0.1.0"
        },
        "recommendations": []
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
                report_data["detailed_results"].append({
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
            report_data["detailed_results"].append({
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
                
        # Extract data from NIST benchmark
        if "compliance" in test_data:
            compliance = test_data["compliance"]
            
            # Add compliance scores to report data (if not already present)
            if "compliance_scores" not in report_data:
                report_data["compliance_scores"] = {}
            
            for practice, data in compliance.items():
                if practice != "overall":
                    report_data["compliance_scores"][practice] = {
                        "score": data.get("score", 0),
                        "status": data.get("status", "Unknown"),
                        "details": data.get("details", "")
                    }
    
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
                report_data["performance_data"]["labels"].append(str(size))
                report_data["performance_data"]["scan_time"].append(metrics.get("duration", 0))
                report_data["performance_data"]["memory"].append(metrics.get("memory_usage", 0))
                
                # Add to detailed results
                report_data["detailed_results"].append({
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
                    report_data["summary"]["successful_tests"] += 1
    
    # Extract data from comparative tests
    for test_id, test_data in results.get("comparative", {}).items():
        if "comparison_matrix" in test_data:
            # Add comparison data to report
            if "tool_comparison" not in report_data:
                report_data["tool_comparison"] = {}
            
            matrix = test_data["comparison_matrix"]
            
            # Extract tool comparison data
            if "scores" in matrix:
                for tool_id, scores in matrix["scores"].items():
                    if tool_id not in report_data["tool_comparison"]:
                        report_data["tool_comparison"][tool_id] = {}
                    
                    for metric, value in scores.items():
                        report_data["tool_comparison"][tool_id][metric] = value
    
    # Extract data from statistical analysis
    for test_id, test_data in results.get("statistics", {}).items():
        # If it's Monte Carlo simulation
        if "monte_carlo" in test_id and "analysis" in test_data:
            if "monte_carlo" not in report_data:
                report_data["monte_carlo"] = {}
            
            report_data["monte_carlo"] = test_data["analysis"]
        
        # If it's correlation analysis
        if "correlation" in test_id and "correlation_results" in test_data:
            if "correlation" not in report_data:
                report_data["correlation"] = {}
            
            # Extract significant correlations
            report_data["correlation"]["significant_correlations"] = test_data["correlation_results"].get("significant_correlations", [])
    
    # Calculate ecosystem detection rates
    for ecosystem, total in ecosystem_counts.items():
        if total > 0:
            report_data["ecosystem_data"]["labels"].append(ecosystem)
            detection_rate = (ecosystem_detected[ecosystem] / total) * 100
            report_data["ecosystem_data"]["values"].append(detection_rate)
    
    # Update severity data
    report_data["severity_data"]["values"] = [
        severity_counts["Critical"],
        severity_counts["High"],
        severity_counts["Medium"],
        severity_counts["Low"]
    ]
    
    # Set summary metrics
    report_data["summary"]["total_tests"] = len(report_data["detailed_results"])
    
    total_expected = total_true_positives + total_false_negatives
    if total_expected > 0:
        report_data["summary"]["detection_rate"] = total_true_positives / total_expected
    
    total_detected = total_true_positives + total_false_positives
    if total_detected > 0:
        report_data["summary"]["false_positive_rate"] = total_false_positives / total_detected
    
    if scan_time_count > 0:
        report_data["summary"]["avg_scan_time"] = total_scan_time / scan_time_count
    
    # Generate recommendations based on results
    recommendations = []
    
    # Detection rate recommendation
    if report_data["summary"]["detection_rate"] < 0.7:
        recommendations.append(
            "Improve vulnerability detection capabilities. Current detection rate is below 70%."
        )
    
    # False positive recommendation
    if report_data["summary"]["false_positive_rate"] > 0.1:
        recommendations.append(
            "Reduce false positive rate. Current false positive rate exceeds 10%."
        )
    
    # Ecosystem-specific recommendations
    for i, ecosystem in enumerate(report_data["ecosystem_data"]["labels"]):
        detection_rate = report_data["ecosystem_data"]["values"][i] / 100  # Convert back to 0-1 scale
        if detection_rate < 0.6:
            recommendations.append(
                f"Enhance detection capabilities for {ecosystem} ecosystem. Current detection rate is {detection_rate:.1%}."
            )
    
    # Performance recommendations
    if report_data["summary"]["avg_scan_time"] > 10:
        recommendations.append(
            f"Optimize scanner performance. Average scan time of {report_data['summary']['avg_scan_time']:.2f} seconds is higher than target."
        )
    
    # Add recommendations to report data
    report_data["recommendations"] = recommendations
    
    return report_data


def create_charts_for_report(report_data: Dict[str, Any], charts_dir: Path) -> Dict[str, Path]:
    """
    Create charts for the PDF report.
    
    Args:
        report_data: Processed report data.
        charts_dir: Directory to save charts.
        
    Returns:
        Dictionary mapping chart names to file paths.
    """
    charts_dir.mkdir(parents=True, exist_ok=True)
    charts = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    plt.rcParams.update({'font.size': 12})
    
    # 1. Ecosystem Detection Rate Chart
    if report_data["ecosystem_data"]["labels"]:
        plt.figure(figsize=(8, 6))
        
        x = report_data["ecosystem_data"]["labels"]
        y = report_data["ecosystem_data"]["values"]
        
        bars = plt.bar(x, y, color='skyblue')
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 1,
                    f"{height:.1f}%", ha='center')
        
        plt.title('Detection Rate by Ecosystem')
        plt.xlabel('Ecosystem')
        plt.ylabel('Detection Rate (%)')
        plt.ylim(0, max(y) * 1.1 if y else 100)  # Add some space for labels
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        ecosystem_chart_path = charts_dir / "ecosystem_detection.png"
        plt.savefig(ecosystem_chart_path)
        plt.close()
        charts["ecosystem_detection"] = ecosystem_chart_path
    
    # 2. Severity Distribution Pie Chart
    plt.figure(figsize=(8, 6))
    
    labels = report_data["severity_data"]["labels"]
    values = report_data["severity_data"]["values"]
    
    # Filter out zero values
    non_zero_labels = []
    non_zero_values = []
    
    for label, value in zip(labels, values):
        if value > 0:
            non_zero_labels.append(label)
            non_zero_values.append(value)
    
    if non_zero_values:
        colors = ['#ff6666', '#ffcc99', '#ffff99', '#99cc99']
        plt.pie(non_zero_values, labels=non_zero_labels, autopct='%1.1f%%', 
               startangle=90, colors=colors)
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.title('Vulnerabilities by Severity')
        
        severity_chart_path = charts_dir / "severity_distribution.png"
        plt.savefig(severity_chart_path)
        plt.close()
        charts["severity_distribution"] = severity_chart_path
    
    # 3. Performance Line Chart
    if report_data["performance_data"]["labels"]:
        plt.figure(figsize=(10, 6))
        
        labels = report_data["performance_data"]["labels"]
        scan_times = report_data["performance_data"]["scan_time"]
        
        plt.plot(labels, scan_times, marker='o', linestyle='-', color='#3498db', label='Scan Time (s)')
        
        # Add memory usage if available
        if report_data["performance_data"]["memory"]:
            memory = report_data["performance_data"]["memory"]
            
            # Create twin axis for memory
            ax2 = plt.twinx()
            ax2.plot(labels, memory, marker='s', linestyle='--', color='#e74c3c', label='Memory Usage (MB)')
            ax2.set_ylabel('Memory Usage (MB)', color='#e74c3c')
            ax2.tick_params(axis='y', labelcolor='#e74c3c')
        
        plt.title('Performance Metrics by Project Size')
        plt.xlabel('Project Size (Dependencies)')
        plt.ylabel('Scan Time (seconds)')
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45, ha='right')
        
        # Handle legend for both axes
        lines1, labels1 = plt.gca().get_legend_handles_labels()
        if report_data["performance_data"]["memory"]:
            lines2, labels2 = ax2.get_legend_handles_labels()
            plt.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
        else:
            plt.legend(loc='upper left')
        
        plt.tight_layout()
        
        performance_chart_path = charts_dir / "performance_metrics.png"
        plt.savefig(performance_chart_path)
        plt.close()
        charts["performance_metrics"] = performance_chart_path
    
    # 4. Detection Metrics Summary
    plt.figure(figsize=(8, 6))
    
    metrics = ['Detection Rate', 'False Positive Rate']
    values = [report_data["summary"]["detection_rate"] * 100, 
              report_data["summary"]["false_positive_rate"] * 100]
    
    bars = plt.bar(metrics, values, color=['#2ecc71', '#e74c3c'])
    
    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 1,
                f"{height:.1f}%", ha='center')
    
    plt.title('Detection Summary')
    plt.ylabel('Percentage (%)')
    plt.ylim(0, 100)
    plt.grid(True, axis='y', alpha=0.3)
    
    summary_chart_path = charts_dir / "detection_summary.png"
    plt.savefig(summary_chart_path)
    plt.close()
    charts["detection_summary"] = summary_chart_path
    
    # 5. Tool Comparison Chart (if data is available)
    if "tool_comparison" in report_data and report_data["tool_comparison"]:
        plt.figure(figsize=(12, 8))
        
        # Select key metrics for comparison
        metrics = ['true_positive_rate', 'false_positive_rate', 'scan_time']
        metric_labels = ['True Positive Rate', 'False Positive Rate', 'Scan Time (s)']
        
        # Get tools and their scores
        tools = list(report_data["tool_comparison"].keys())
        
        # Set up a figure with subplots
        fig, axes = plt.subplots(len(metrics), 1, figsize=(10, 4 * len(metrics)))
        
        for i, (metric, label) in enumerate(zip(metrics, metric_labels)):
            ax = axes[i]
            
            # Get values for this metric
            values = []
            for tool in tools:
                if metric in report_data["tool_comparison"][tool]:
                    values.append(report_data["tool_comparison"][tool][metric])
                else:
                    values.append(0)
            
            # For rates, multiply by 100 to show as percentage
            if 'rate' in metric:
                values = [v * 100 for v in values]
            
            # Create bar chart
            bars = ax.bar(tools, values, color=sns.color_palette("husl", len(tools)))
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + (max(values) * 0.02),
                        f"{height:.1f}" + ("%" if 'rate' in metric else ""),
                        ha='center', va='bottom')
            
            ax.set_title(label)
            ax.set_ylabel('Value' + (" (%)" if 'rate' in metric else ""))
            ax.set_ylim(0, max(values) * 1.1 if values else 1)
            ax.grid(True, axis='y', alpha=0.3)
        
        plt.tight_layout()
        
        comparison_chart_path = charts_dir / "tool_comparison.png"
        plt.savefig(comparison_chart_path)
        plt.close()
        charts["tool_comparison"] = comparison_chart_path
    
    return charts


def generate_pdf_report(report_data: Dict[str, Any], charts: Dict[str, Path], output_file: Path) -> None:
    """
    Generate PDF report from processed data and charts.
    
    Args:
        report_data: Processed report data.
        charts: Dictionary of chart file paths.
        output_file: Output PDF file path.
    """
    # Set up PDF document
    doc = SimpleDocTemplate(
        str(output_file),
        pagesize=letter,
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Create custom styles
    styles.add(ParagraphStyle(name='Title',
                            parent=styles['Title'],
                            fontSize=20,
                            leading=24,
                            spaceAfter=16))
    
    styles.add(ParagraphStyle(name='Heading1',
                            parent=styles['Heading1'],
                            fontSize=16,
                            leading=20,
                            spaceAfter=12,
                            spaceBefore=12))
    
    styles.add(ParagraphStyle(name='Heading2',
                            parent=styles['Heading2'],
                            fontSize=14,
                            leading=18,
                            spaceAfter=10,
                            spaceBefore=10))
    
    styles.add(ParagraphStyle(name='Normal',
                            parent=styles['Normal'],
                            fontSize=10,
                            leading=14,
                            spaceAfter=8))
    
    # Create story (list of elements to add to the PDF)
    story = []
    
    # Title
    story.append(Paragraph("OSSV Scanner Test Results Report", styles['Title']))
    story.append(Paragraph(f"Generated on {report_data['metadata']['timestamp']}", styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading1']))
    
    summary_text = [
        f"This report presents the results of comprehensive testing of the OSSV Scanner. ",
        f"A total of {report_data['summary']['total_tests']} tests were executed across multiple test types. ",
        f"The scanner demonstrated an overall vulnerability detection rate of {report_data['summary']['detection_rate']*100:.1f}% ",
        f"with a false positive rate of {report_data['summary']['false_positive_rate']*100:.1f}%. ",
        f"Average scan time was {report_data['summary']['avg_scan_time']:.2f} seconds."
    ]
    
    story.append(Paragraph("".join(summary_text), styles['Normal']))
    story.append(Spacer(1, 0.1*inch))
    
    # Key Findings
    story.append(Paragraph("Key Findings", styles['Heading2']))
    
    # Create a table for key metrics
    key_metrics_data = [
        ["Metric", "Value"],
        ["Total Tests", str(report_data['summary']['total_tests'])],
        ["Successful Tests", str(report_data['summary']['successful_tests'])],
        ["Detection Rate", f"{report_data['summary']['detection_rate']*100:.1f}%"],
        ["False Positive Rate", f"{report_data['summary']['false_positive_rate']*100:.1f}%"],
        ["Average Scan Time", f"{report_data['summary']['avg_scan_time']:.2f} seconds"]
    ]
    
    key_metrics_table = Table(key_metrics_data, colWidths=[2.5*inch, 2.5*inch])
    key_metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
    ]))
    
    story.append(key_metrics_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Add Detection Summary Chart if available
    if "detection_summary" in charts:
        story.append(Paragraph("Detection Performance", styles['Heading2']))
        img = Image(str(charts["detection_summary"]), width=6*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.1*inch))
    
    # Add recommendations
    if report_data["recommendations"]:
        story.append(Paragraph("Recommendations", styles['Heading2']))
        
        recommendations_list = []
        for rec in report_data["recommendations"]:
            recommendations_list.append(ListItem(Paragraph(rec, styles['Normal'])))
        
        story.append(ListFlowable(recommendations_list, bulletType='bullet', start=None))
        story.append(Spacer(1, 0.2*inch))
    
    # Add page break before detailed results
    story.append(PageBreak())
    
    # Detailed Results
    story.append(Paragraph("Detailed Results", styles['Heading1']))
    
    # Detection Results by Ecosystem
    story.append(Paragraph("Detection by Ecosystem", styles['Heading2']))
    
    if "ecosystem_detection" in charts:
        img = Image(str(charts["ecosystem_detection"]), width=6*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.1*inch))
    
    ecosystem_text = "The scanner's detection capabilities vary across different ecosystems. "
    
    if report_data["ecosystem_data"]["labels"]:
        best_ecosystem_idx = np.argmax(report_data["ecosystem_data"]["values"])
        worst_ecosystem_idx = np.argmin(report_data["ecosystem_data"]["values"])
        
        best_ecosystem = report_data["ecosystem_data"]["labels"][best_ecosystem_idx]
        best_rate = report_data["ecosystem_data"]["values"][best_ecosystem_idx]
        
        worst_ecosystem = report_data["ecosystem_data"]["labels"][worst_ecosystem_idx]
        worst_rate = report_data["ecosystem_data"]["values"][worst_ecosystem_idx]
        
        ecosystem_text += f"The strongest detection was observed in the {best_ecosystem} ecosystem "
        ecosystem_text += f"with a detection rate of {best_rate:.1f}%. "
        ecosystem_text += f"The weakest detection was in the {worst_ecosystem} ecosystem "
        ecosystem_text += f"with a detection rate of {worst_rate:.1f}%."
    
    story.append(Paragraph(ecosystem_text, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Vulnerability Severity Distribution
    story.append(Paragraph("Vulnerability Severity Distribution", styles['Heading2']))
    
    if "severity_distribution" in charts:
        img = Image(str(charts["severity_distribution"]), width=5*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.1*inch))
    
    severity_text = "The scanner detected vulnerabilities across multiple severity levels. "
    
    total_vulns = sum(report_data["severity_data"]["values"])
    if total_vulns > 0:
        critical_pct = report_data["severity_data"]["values"][0] / total_vulns * 100
        high_pct = report_data["severity_data"]["values"][1] / total_vulns * 100
        
        severity_text += f"Critical and high severity vulnerabilities account for "
        severity_text += f"{critical_pct + high_pct:.1f}% of all detected vulnerabilities."
    
    story.append(Paragraph(severity_text, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Performance Analysis
    story.append(PageBreak())
    story.append(Paragraph("Performance Analysis", styles['Heading1']))
    
    if "performance_metrics" in charts:
        img = Image(str(charts["performance_metrics"]), width=6.5*inch, height=4*inch)
        story.append(img)
        story.append(Spacer(1, 0.1*inch))
    
    performance_text = "The scanner's performance was measured across projects of varying sizes. "
    
    if report_data["performance_data"]["scan_time"]:
        max_time_idx = np.argmax(report_data["performance_data"]["scan_time"])
        max_time = report_data["performance_data"]["scan_time"][max_time_idx]
        max_size = report_data["performance_data"]["labels"][max_time_idx]
        
        performance_text += f"The longest scan time was {max_time:.2f} seconds "
        performance_text += f"for a project with {max_size} dependencies. "
    
    if report_data["performance_data"]["memory"]:
        max_mem_idx = np.argmax(report_data["performance_data"]["memory"])
        max_mem = report_data["performance_data"]["memory"][max_mem_idx]
        max_mem_size = report_data["performance_data"]["labels"][max_mem_idx]
        
        performance_text += f"Peak memory consumption was {max_mem:.1f} MB "
        performance_text += f"for a project with {max_mem_size} dependencies."
    
    story.append(Paragraph(performance_text, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Comparative Analysis (if available)
    if "tool_comparison" in report_data and "tool_comparison" in charts:
        story.append(Paragraph("Comparative Analysis", styles['Heading1']))
        
        img = Image(str(charts["tool_comparison"]), width=7*inch, height=6*inch)
        story.append(img)
        story.append(Spacer(1, 0.1*inch))
        
        comparison_text = "The scanner was compared against other vulnerability scanning tools. "
        
        # Add comparison insights
        if "ossv-scanner" in report_data["tool_comparison"]:
            ossv_tpr = report_data["tool_comparison"]["ossv-scanner"].get("true_positive_rate", 0)
            
            # Find the best tool for true positive rate
            best_tool = max(report_data["tool_comparison"].keys(), 
                           key=lambda x: report_data["tool_comparison"][x].get("true_positive_rate", 0))
            best_tpr = report_data["tool_comparison"][best_tool].get("true_positive_rate", 0)
            
            if best_tool == "ossv-scanner":
                comparison_text += "OSSV Scanner demonstrated the best detection capabilities "
                comparison_text += f"with a true positive rate of {ossv_tpr*100:.1f}%. "
            else:
                comparison_text += f"OSSV Scanner's detection rate of {ossv_tpr*100:.1f}% "
                comparison_text += f"compared to the best performer ({best_tool}) "
                comparison_text += f"with {best_tpr*100:.1f}%. "
            
            # Compare scan times
            ossv_time = report_data["tool_comparison"]["ossv-scanner"].get("scan_time", 0)
            fastest_tool = min(report_data["tool_comparison"].keys(),
                              key=lambda x: report_data["tool_comparison"][x].get("scan_time", float('inf')))
            fastest_time = report_data["tool_comparison"][fastest_tool].get("scan_time", 0)
            
            comparison_text += f"In terms of performance, "
            if fastest_tool == "ossv-scanner":
                comparison_text += "OSSV Scanner was the fastest tool "
                comparison_text += f"with an average scan time of {ossv_time:.2f} seconds."
            else:
                comparison_text += f"OSSV Scanner completed scans in {ossv_time:.2f} seconds on average, "
                comparison_text += f"compared to {fastest_time:.2f} seconds for the fastest tool ({fastest_tool})."
        
        story.append(Paragraph(comparison_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
    
    # Detailed Test Results Table
    story.append(PageBreak())
    story.append(Paragraph("Detailed Test Results", styles['Heading1']))
    
    # Create table from detailed results
    if report_data["detailed_results"]:
        # Limit to top 20 results if there are too many
        results_to_show = report_data["detailed_results"][:20] if len(report_data["detailed_results"]) > 20 else report_data["detailed_results"]
        
        table_data = [["ID", "Type", "Ecosystem", "TP", "FN", "FP", "Detection Rate", "Scan Time (s)"]]
        
        for result in results_to_show:
            table_data.append([
                result["id"],
                result["type"],
                result["ecosystem"],
                str(result["true_positives"]),
                str(result["false_negatives"]),
                str(result["false_positives"]),
                f"{result['detection_rate']*100:.1f}%",
                f"{result['scan_time']:.2f}" if result['scan_time'] > 0 else "N/A"
            ])
        
        results_table = Table(table_data, colWidths=[1*inch, 1*inch, 1*inch, 0.5*inch, 0.5*inch, 0.5*inch, 1*inch, 1*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (3, 1), (7, -1), 'CENTER'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]))
        
        story.append(results_table)
        
        if len(report_data["detailed_results"]) > 20:
            story.append(Paragraph(f"Showing 20 of {len(report_data['detailed_results'])} test results.", styles['Normal']))
    else:
        story.append(Paragraph("No detailed test results available.", styles['Normal']))
    
    # Conclusion
    story.append(PageBreak())
    story.append(Paragraph("Conclusion", styles['Heading1']))
    
    conclusion_text = [
        "Based on the comprehensive testing conducted, the OSSV Scanner has demonstrated ",
        f"a detection rate of {report_data['summary']['detection_rate']*100:.1f}% ",
        f"with a false positive rate of {report_data['summary']['false_positive_rate']*100:.1f}%. ",
        "This indicates a solid foundation for vulnerability detection capabilities. "
    ]
    
    # Add strength/weakness based on detection rate
    if report_data["summary"]["detection_rate"] >= 0.8:
        conclusion_text.append("The scanner exhibits strong detection capabilities across various ecosystems. ")
    elif report_data["summary"]["detection_rate"] >= 0.6:
        conclusion_text.append("The scanner demonstrates moderate detection capabilities with room for improvement. ")
    else:
        conclusion_text.append("The scanner's detection capabilities need significant enhancement. ")
    
    # Add strength/weakness based on false positive rate
    if report_data["summary"]["false_positive_rate"] <= 0.05:
        conclusion_text.append("Its low false positive rate indicates high precision in vulnerability identification. ")
    elif report_data["summary"]["false_positive_rate"] <= 0.15:
        conclusion_text.append("The false positive rate is at an acceptable level but could be improved. ")
    else:
        conclusion_text.append("The high false positive rate requires attention to improve scanner reliability. ")
    
    # Add performance commentary
    if report_data["summary"]["avg_scan_time"] <= 5:
        conclusion_text.append("The scanner demonstrates excellent performance with quick scan times. ")
    elif report_data["summary"]["avg_scan_time"] <= 15:
        conclusion_text.append("The scanner performs reasonably well with acceptable scan times. ")
    else:
        conclusion_text.append("The scanner's performance could be optimized to reduce scan times. ")
    
    # Final remarks
    conclusion_text.append("Implementing the recommendations provided in this report will help enhance the scanner's effectiveness and reliability in identifying vulnerabilities across different software ecosystems.")
    
    story.append(Paragraph("".join(conclusion_text), styles['Normal']))
    
    # Build the PDF
    doc.build(story)


def generate_report(input_dir: Path, output_dir: Path) -> Path:
    """
    Generate a comprehensive PDF report from test results.
    
    Args:
        input_dir: Directory containing test results.
        output_dir: Directory to save the report.
        
    Returns:
        Path to the generated report.
    """
    logger.info(f"Generating report from results in {input_dir}")
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a temporary directory for charts
    charts_dir = output_dir / "charts"
    charts_dir.mkdir(exist_ok=True)
    
    # Load test results
    with Progress() as progress:
        task1 = progress.add_task("[green]Loading test results...", total=1)
        results = load_test_results(input_dir)
        progress.update(task1, completed=1)
        
        # Extract and process data for report
        task2 = progress.add_task("[cyan]Processing data...", total=1)
        report_data = extract_report_data(results)
        progress.update(task2, completed=1)
        
        # Create charts for report
        task3 = progress.add_task("[magenta]Creating charts...", total=1)
        charts = create_charts_for_report(report_data, charts_dir)
        progress.update(task3, completed=1)
        
        # Generate PDF report
        task4 = progress.add_task("[yellow]Generating PDF report...", total=1)
        report_path = output_dir / "ossv_scanner_test_report.pdf"
        generate_pdf_report(report_data, charts, report_path)
        progress.update(task4, completed=1)
    
    logger.info(f"Report generated at {report_path}")
    
    # Try to open the report
    try:
        if os.name == 'nt':  # Windows
            os.startfile(report_path)
        elif os.name == 'posix':  # Linux/macOS
            os.system(f"xdg-open {report_path} || open {report_path}")
    except Exception as e:
        logger.warning(f"Could not open report: {str(e)}")
    
    return report_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Use a default input directory for testing
    input_dir = Path(tempfile.gettempdir()) / "ossv-testing-results"
    output_dir = Path(tempfile.gettempdir()) / "ossv-report"
    
    generate_report(input_dir, output_dir)
