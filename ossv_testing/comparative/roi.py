"""
Return on Investment (ROI) analysis for ossv-scanner.

This module evaluates the ROI of using ossv-scanner compared to other vulnerability
scanning tools, factoring in direct costs, operational costs, and security benefits.
"""

import os
import time
import logging
import tempfile
import json
import yaml
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
import statistics

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Cost assumptions for ROI calculation
DEFAULT_COST_ASSUMPTIONS = {
    # Direct costs
    "developer_hourly_rate": 75,          # Cost per hour for developers
    "security_hourly_rate": 100,          # Cost per hour for security engineers
    "overhead_multiplier": 1.5,           # Overhead cost multiplier
    
    # Tool costs
    "tool_costs": {
        "ossv-scanner": {
            "license_annual": 0,          # Free open source
            "implementation_hours": 4,     # Hours to implement
            "training_hours": 2,           # Hours for training
            "maintenance_monthly_hours": 1 # Hours per month for maintenance
        },
        "snyk": {
            "license_annual": 15000,       # Enterprise tier
            "implementation_hours": 8,      # Hours to implement
            "training_hours": 4,            # Hours for training
            "maintenance_monthly_hours": 2  # Hours per month for maintenance
        },
        "dependabot": {
            "license_annual": 0,            # Free with GitHub
            "implementation_hours": 2,       # Hours to implement
            "training_hours": 1,             # Hours for training
            "maintenance_monthly_hours": 1   # Hours per month for maintenance
        },
        "owasp-dependency-check": {
            "license_annual": 0,             # Free open source
            "implementation_hours": 16,       # Hours to implement
            "training_hours": 8,              # Hours for training
            "maintenance_monthly_hours": 4    # Hours per month for maintenance
        },
        "npm-audit": {
            "license_annual": 0,              # Free with npm
            "implementation_hours": 1,         # Hours to implement
            "training_hours": 0.5,             # Hours for training
            "maintenance_monthly_hours": 0.5   # Hours per month for maintenance
        },
        "safety": {
            "license_annual": 0,               # Free open source
            "implementation_hours": 2,          # Hours to implement
            "training_hours": 1,                # Hours for training
            "maintenance_monthly_hours": 1      # Hours per month for maintenance
        }
    },
    
    # Security incident costs
    "average_vulnerability_remediation_hours": 8,   # Hours to fix a vulnerability
    "average_breach_cost": 4240000,                 # Average cost of a security breach (IBM report)
    "breach_probability_per_vulnerability": 0.01,   # Probability of a breach from one vulnerability
    
    # Operational factors
    "false_positive_investigation_hours": 2,       # Hours spent investigating a false positive
    "ci_cd_frequency_daily": 10,                   # Number of CI/CD builds per day
    "scan_interruption_cost": 50,                  # Cost of interrupting development for a scan
    
    # Project parameters
    "number_of_applications": 10,                  # Number of applications to scan
    "average_dependencies_per_app": 75,            # Average number of dependencies per application
    "annual_vulnerability_discovery_rate": 0.15,   # Percentage of dependencies with vulnerabilities discovered annually
    "estimated_scale_factor": 1.0                  # Scale factor for estimating costs
}


def calculate_tool_costs(tool_id: str, assumptions: Dict[str, Any]) -> Dict[str, float]:
    """
    Calculate direct costs of implementing and using a vulnerability scanning tool.
    
    Args:
        tool_id: Tool identifier.
        assumptions: Cost assumptions dictionary.
        
    Returns:
        Dictionary of cost breakdowns.
    """
    tool_costs = assumptions["tool_costs"].get(tool_id, {})
    
    # Calculate labor costs
    dev_rate = assumptions["developer_hourly_rate"]
    overhead = assumptions["overhead_multiplier"]
    
    implementation_cost = tool_costs.get("implementation_hours", 0) * dev_rate * overhead
    training_cost = tool_costs.get("training_hours", 0) * dev_rate * overhead
    monthly_maintenance = tool_costs.get("maintenance_monthly_hours", 0) * dev_rate * overhead
    annual_maintenance = monthly_maintenance * 12
    
    # Annual license cost
    license_cost = tool_costs.get("license_annual", 0)
    
    # Total first year cost
    total_first_year = license_cost + implementation_cost + training_cost + annual_maintenance
    
    # Annual recurring cost
    annual_recurring = license_cost + annual_maintenance
    
    # Total five year cost
    total_five_year = license_cost * 5 + implementation_cost + training_cost + annual_maintenance * 5
    
    return {
        "implementation_cost": implementation_cost,
        "training_cost": training_cost,
        "annual_maintenance": annual_maintenance,
        "license_cost": license_cost,
        "total_first_year": total_first_year,
        "annual_recurring": annual_recurring,
        "total_five_year": total_five_year
    }


def calculate_operational_costs(tool_effectiveness: Dict[str, Any], assumptions: Dict[str, Any]) -> Dict[str, float]:
    """
    Calculate operational costs based on tool effectiveness metrics.
    
    Args:
        tool_effectiveness: Tool effectiveness metrics.
        assumptions: Cost assumptions dictionary.
        
    Returns:
        Dictionary of operational costs.
    """
    # Extract effectiveness metrics
    false_positive_rate = tool_effectiveness.get("false_positive_rate", 0.2)
    true_positive_rate = tool_effectiveness.get("true_positive_rate", 0.8)
    scan_time = tool_effectiveness.get("scan_time", 60)  # seconds
    
    # Calculate costs
    dev_rate = assumptions["developer_hourly_rate"]
    security_rate = assumptions["security_hourly_rate"]
    overhead = assumptions["overhead_multiplier"]
    
    # Number of applications and dependencies
    num_apps = assumptions["number_of_applications"]
    deps_per_app = assumptions["average_dependencies_per_app"]
    total_deps = num_apps * deps_per_app
    
    # Annual vulnerability discovery rate
    vuln_rate = assumptions["annual_vulnerability_discovery_rate"]
    
    # Expected number of vulnerabilities per year
    expected_vulns = total_deps * vuln_rate
    
    # False positives per year
    detected_vulns = expected_vulns * true_positive_rate
    false_positives = detected_vulns * false_positive_rate / (1 - false_positive_rate)
    
    # Missed vulnerabilities
    missed_vulns = expected_vulns * (1 - true_positive_rate)
    
    # Cost of investigating false positives
    false_positive_cost = false_positives * assumptions["false_positive_investigation_hours"] * dev_rate * overhead
    
    # Cost of remediating detected vulnerabilities
    remediation_cost = detected_vulns * assumptions["average_vulnerability_remediation_hours"] * dev_rate * overhead
    
    # Cost of scanning (CI/CD integration)
    days_per_year = 260  # business days
    scans_per_year = days_per_year * assumptions["ci_cd_frequency_daily"] * num_apps
    
    # Convert scan time to hours
    scan_time_hours = scan_time / 3600
    
    # Cost of scanning in terms of development time
    scan_cost = scans_per_year * scan_time_hours * assumptions["scan_interruption_cost"] * overhead
    
    # Total operational cost
    total_operational_cost = false_positive_cost + remediation_cost + scan_cost
    
    return {
        "false_positive_cost": false_positive_cost,
        "remediation_cost": remediation_cost,
        "scan_cost": scan_cost,
        "total_operational_cost": total_operational_cost,
        "detected_vulnerabilities": detected_vulns,
        "false_positives": false_positives,
        "missed_vulnerabilities": missed_vulns,
    }


def calculate_security_benefit(tool_effectiveness: Dict[str, Any], assumptions: Dict[str, Any]) -> Dict[str, float]:
    """
    Calculate security benefits from using the tool.
    
    Args:
        tool_effectiveness: Tool effectiveness metrics.
        assumptions: Cost assumptions dictionary.
        
    Returns:
        Dictionary of security benefits.
    """
    # Extract effectiveness metrics
    true_positive_rate = tool_effectiveness.get("true_positive_rate", 0.8)
    
    # Number of applications and dependencies
    num_apps = assumptions["number_of_applications"]
    deps_per_app = assumptions["average_dependencies_per_app"]
    total_deps = num_apps * deps_per_app
    
    # Annual vulnerability discovery rate
    vuln_rate = assumptions["annual_vulnerability_discovery_rate"]
    
    # Expected number of vulnerabilities per year
    expected_vulns = total_deps * vuln_rate
    
    # Detected vulnerabilities
    detected_vulns = expected_vulns * true_positive_rate
    
    # Cost of a breach
    breach_cost = assumptions["average_breach_cost"]
    
    # Probability of a breach from a vulnerability
    breach_prob = assumptions["breach_probability_per_vulnerability"]
    
    # Expected cost without the tool (all vulnerabilities pose risk)
    expected_breach_cost_without_tool = expected_vulns * breach_prob * breach_cost
    
    # Expected cost with the tool (only missed vulnerabilities pose risk)
    missed_vulns = expected_vulns * (1 - true_positive_rate)
    expected_breach_cost_with_tool = missed_vulns * breach_prob * breach_cost
    
    # Benefit is the difference
    security_benefit = expected_breach_cost_without_tool - expected_breach_cost_with_tool
    
    return {
        "expected_breach_cost_without_tool": expected_breach_cost_without_tool,
        "expected_breach_cost_with_tool": expected_breach_cost_with_tool,
        "security_benefit": security_benefit,
        "breaches_prevented": detected_vulns * breach_prob
    }


def calculate_roi(tool_id: str, tool_effectiveness: Dict[str, Any], assumptions: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate Return on Investment for a vulnerability scanning tool.
    
    Args:
        tool_id: Tool identifier.
        tool_effectiveness: Tool effectiveness metrics.
        assumptions: Cost assumptions dictionary.
        
    Returns:
        ROI analysis results.
    """
    # Calculate direct costs
    direct_costs = calculate_tool_costs(tool_id, assumptions)
    
    # Calculate operational costs
    operational_costs = calculate_operational_costs(tool_effectiveness, assumptions)
    
    # Calculate security benefits
    security_benefits = calculate_security_benefit(tool_effectiveness, assumptions)
    
    # Calculate ROI
    total_first_year_cost = direct_costs["total_first_year"] + operational_costs["total_operational_cost"]
    annual_benefit = security_benefits["security_benefit"]
    
    # Simple ROI calculation
    simple_roi = (annual_benefit / total_first_year_cost - 1) * 100 if total_first_year_cost > 0 else float('inf')
    
    # Calculate payback period (in years)
    payback_period = total_first_year_cost / annual_benefit if annual_benefit > 0 else float('inf')
    
    # Calculate 5-year ROI
    five_year_cost = direct_costs["total_five_year"] + operational_costs["total_operational_cost"] * 5
    five_year_benefit = annual_benefit * 5
    five_year_roi = (five_year_benefit / five_year_cost - 1) * 100 if five_year_cost > 0 else float('inf')
    
    # Return comprehensive ROI analysis
    return {
        "direct_costs": direct_costs,
        "operational_costs": operational_costs,
        "security_benefits": security_benefits,
        "total_first_year_cost": total_first_year_cost,
        "annual_benefit": annual_benefit,
        "simple_roi": simple_roi,
        "payback_period_years": payback_period,
        "five_year_cost": five_year_cost,
        "five_year_benefit": five_year_benefit,
        "five_year_roi": five_year_roi
    }


def generate_roi_plots(roi_analyses: Dict[str, Dict[str, Any]], output_dir: Path) -> Dict[str, Path]:
    """
    Generate ROI visualization plots.
    
    Args:
        roi_analyses: Dictionary mapping tool IDs to ROI analysis results.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # 1. Cost Comparison
    plt.figure(figsize=(12, 8))
    
    # Prepare data
    tools = []
    license_costs = []
    implementation_costs = []
    maintenance_costs = []
    
    for tool_id, analysis in roi_analyses.items():
        tools.append(tool_id)
        license_costs.append(analysis["direct_costs"]["license_cost"])
        implementation_costs.append(analysis["direct_costs"]["implementation_cost"] + analysis["direct_costs"]["training_cost"])
        maintenance_costs.append(analysis["direct_costs"]["annual_maintenance"])
    
    # Create stacked bar chart
    x = np.arange(len(tools))
    width = 0.6
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Plot stacked bars
    p1 = ax.bar(x, license_costs, width, label='License Cost')
    p2 = ax.bar(x, implementation_costs, width, bottom=license_costs, label='Implementation & Training')
    
    # Calculate the bottom position for maintenance costs
    bottoms = [a + b for a, b in zip(license_costs, implementation_costs)]
    p3 = ax.bar(x, maintenance_costs, width, bottom=bottoms, label='Annual Maintenance')
    
    # Add total labels
    for i, (l, i, m) in enumerate(zip(license_costs, implementation_costs, maintenance_costs)):
        total = l + i + m
        ax.annotate(f'${total:,.0f}',
                    xy=(i, total),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    # Add labels and legend
    ax.set_ylabel('Cost ($)')
    ax.set_title('First Year Cost Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    
    plt.tight_layout()
    
    cost_comparison_path = output_dir / "cost_comparison.png"
    plt.savefig(cost_comparison_path)
    plt.close()
    plots["cost_comparison"] = cost_comparison_path
    
    # 2. ROI Comparison
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    simple_roi = [analysis["simple_roi"] for analysis in roi_analyses.values()]
    payback_periods = [min(analysis["payback_period_years"], 5) for analysis in roi_analyses.values()]  # Cap at 5 years
    
    # For infinite values, cap the ROI at 1000% for visualization
    simple_roi = [min(roi, 1000) if roi != float('inf') else 1000 for roi in simple_roi]
    
    # Create a figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Plot ROI
    bars = ax1.bar(tools, simple_roi, color='skyblue')
    ax1.set_ylabel('First Year ROI (%)')
    ax1.set_title('Return on Investment')
    ax1.set_ylim(bottom=min(0, min(simple_roi) - 10))
    
    # Add value labels
    for bar, roi in zip(bars, simple_roi):
        if roi == 1000:
            label = "∞"
        else:
            label = f"{roi:.1f}%"
        
        height = bar.get_height()
        ax1.annotate(label,
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    # Plot Payback Period
    bars = ax2.bar(tools, payback_periods, color='lightgreen')
    ax2.set_ylabel('Payback Period (Years)')
    ax2.set_title('Time to Recoup Investment')
    ax2.set_ylim(0, 5.5)
    
    # Add horizontal line at 1 year
    ax2.axhline(y=1, color='r', linestyle='--', alpha=0.3)
    
    # Add value labels
    for bar, period in zip(bars, payback_periods):
        if period == 5:
            label = ">5"
        else:
            label = f"{period:.1f}"
        
        height = bar.get_height()
        ax2.annotate(label,
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    plt.tight_layout()
    
    roi_comparison_path = output_dir / "roi_comparison.png"
    plt.savefig(roi_comparison_path)
    plt.close()
    plots["roi_comparison"] = roi_comparison_path
    
    # 3. 5-Year Cost-Benefit Analysis
    plt.figure(figsize=(12, 8))
    
    # Prepare data
    costs = [analysis["five_year_cost"] for analysis in roi_analyses.values()]
    benefits = [analysis["five_year_benefit"] for analysis in roi_analyses.values()]
    net_benefits = [b - c for b, c in zip(benefits, costs)]
    
    # Create grouped bar chart
    x = np.arange(len(tools))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Plot grouped bars
    ax.bar(x - width, costs, width, label='5-Year Cost')
    ax.bar(x, benefits, width, label='5-Year Benefit')
    ax.bar(x + width, net_benefits, width, label='Net Benefit')
    
    # Add labels and legend
    ax.set_ylabel('Value ($)')
    ax.set_title('5-Year Cost-Benefit Analysis')
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    
    # Add gridlines
    ax.grid(True, axis='y', alpha=0.3)
    
    plt.tight_layout()
    
    cost_benefit_path = output_dir / "cost_benefit_analysis.png"
    plt.savefig(cost_benefit_path)
    plt.close()
    plots["cost_benefit_analysis"] = cost_benefit_path
    
    # 4. Operational Cost Breakdown
    plt.figure(figsize=(12, 8))
    
    # Prepare data
    false_positive_costs = [analysis["operational_costs"]["false_positive_cost"] for analysis in roi_analyses.values()]
    remediation_costs = [analysis["operational_costs"]["remediation_cost"] for analysis in roi_analyses.values()]
    scan_costs = [analysis["operational_costs"]["scan_cost"] for analysis in roi_analyses.values()]
    
    # Create stacked bar chart
    x = np.arange(len(tools))
    width = 0.6
    
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Plot stacked bars
    p1 = ax.bar(x, false_positive_costs, width, label='False Positive Investigation')
    p2 = ax.bar(x, remediation_costs, width, bottom=false_positive_costs, label='Vulnerability Remediation')
    
    # Calculate the bottom position for scan costs
    bottoms = [a + b for a, b in zip(false_positive_costs, remediation_costs)]
    p3 = ax.bar(x, scan_costs, width, bottom=bottoms, label='Scanning Overhead')
    
    # Add total labels
    for i, (fp, r, s) in enumerate(zip(false_positive_costs, remediation_costs, scan_costs)):
        total = fp + r + s
        ax.annotate(f'${total:,.0f}',
                    xy=(i, total),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
    
    # Add labels and legend
    ax.set_ylabel('Annual Cost ($)')
    ax.set_title('Operational Cost Breakdown')
    ax.set_xticks(x)
    ax.set_xticklabels(tools)
    ax.legend()
    
    plt.tight_layout()
    
    operational_cost_path = output_dir / "operational_cost_breakdown.png"
    plt.savefig(operational_cost_path)
    plt.close()
    plots["operational_cost_breakdown"] = operational_cost_path
    
    # 5. Security Effectiveness vs. Cost
    plt.figure(figsize=(10, 8))
    
    # Prepare data
    detection_rates = [roi_analyses[tool]["security_benefits"]["breaches_prevented"] for tool in tools]
    total_costs = [roi_analyses[tool]["total_first_year_cost"] for tool in tools]
    
    # Create scatter plot
    plt.figure(figsize=(10, 8))
    
    # Plot points
    plt.scatter(total_costs, detection_rates, s=100)
    
    # Add tool labels
    for i, tool in enumerate(tools):
        plt.annotate(tool, (total_costs[i], detection_rates[i]),
                    xytext=(5, 5), textcoords='offset points')
    
    # Add labels
    plt.xlabel('Total First Year Cost ($)')
    plt.ylabel('Expected Breaches Prevented')
    plt.title('Security Effectiveness vs. Cost')
    
    # Add grid
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    effectiveness_cost_path = output_dir / "effectiveness_vs_cost.png"
    plt.savefig(effectiveness_cost_path)
    plt.close()
    plots["effectiveness_vs_cost"] = effectiveness_cost_path
    
    return plots


def analyze_roi(tools: List[str] = None, custom_assumptions: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Analyze ROI for ossv-scanner and comparison tools.
    
    Args:
        tools: List of tool IDs to analyze. If None, uses default tools.
        custom_assumptions: Custom cost assumptions to override defaults.
        
    Returns:
        ROI analysis results.
    """
    logger.info("Starting ROI analysis")
    
    # Prepare output directory
    output_dir = Path(tempfile.mkdtemp(prefix="ossv-roi-analysis-"))
    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Merge custom assumptions with defaults
    assumptions = DEFAULT_COST_ASSUMPTIONS.copy()
    if custom_assumptions:
        # Recursively update assumptions
        def update_dict(d, u):
            for k, v in u.items():
                if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                    d[k] = update_dict(d[k].copy(), v)
                else:
                    d[k] = v
            return d
        
        assumptions = update_dict(assumptions, custom_assumptions)
    
    # Select tools to analyze
    if not tools:
        tools = ["ossv-scanner", "snyk", "dependabot", "owasp-dependency-check"]
    
    # Define simulated effectiveness metrics based on previous analyses
    tool_effectiveness = {
        "ossv-scanner": {
            "true_positive_rate": 0.85,
            "false_positive_rate": 0.05,
            "scan_time": 45,  # seconds
        },
        "snyk": {
            "true_positive_rate": 0.92,
            "false_positive_rate": 0.08,
            "scan_time": 60,  # seconds
        },
        "dependabot": {
            "true_positive_rate": 0.80,
            "false_positive_rate": 0.03,
            "scan_time": 30,  # seconds
        },
        "owasp-dependency-check": {
            "true_positive_rate": 0.75,
            "false_positive_rate": 0.15,
            "scan_time": 120,  # seconds
        },
        "npm-audit": {
            "true_positive_rate": 0.70,
            "false_positive_rate": 0.10,
            "scan_time": 20,  # seconds
        },
        "safety": {
            "true_positive_rate": 0.65,
            "false_positive_rate": 0.07,
            "scan_time": 15,  # seconds
        }
    }
    
    # Calculate ROI for each tool
    roi_analyses = {}
    
    with Progress() as progress:
        task = progress.add_task("[green]Analyzing ROI...", total=len(tools))
        
        for tool_id in tools:
            if tool_id not in tool_effectiveness:
                logger.warning(f"No effectiveness data for {tool_id}, skipping")
                progress.update(task, advance=1)
                continue
            
            logger.info(f"Calculating ROI for {tool_id}")
            
            # Calculate ROI
            roi_analysis = calculate_roi(tool_id, tool_effectiveness[tool_id], assumptions)
            roi_analyses[tool_id] = roi_analysis
            
            progress.update(task, advance=1)
    
    # Generate plots
    logger.info("Generating ROI plots")
    plots = generate_roi_plots(roi_analyses, plots_dir)
    
    # Build ROI summary
    roi_summary = {
        "assumptions": assumptions,
        "roi_analyses": roi_analyses,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tools_analyzed": list(roi_analyses.keys())
        }
    }
    
    # Display summary
    display_roi_summary(roi_analyses)
    
    logger.info("ROI analysis completed")
    return roi_summary


def display_roi_summary(roi_analyses: Dict[str, Dict[str, Any]]) -> None:
    """
    Display a summary of ROI analysis results.
    
    Args:
        roi_analyses: Dictionary mapping tool IDs to ROI analysis results.
    """
    console.print("\n[bold cyan]ROI Analysis Summary[/]")
    
    # Create first year cost table
    cost_table = Table(title="First Year Cost Summary")
    cost_table.add_column("Tool", style="cyan")
    cost_table.add_column("License", style="green")
    cost_table.add_column("Implementation", style="green")
    cost_table.add_column("Operational", style="green")
    cost_table.add_column("Total", style="yellow")
    
    for tool_id, analysis in roi_analyses.items():
        cost_table.add_row(
            tool_id,
            f"${analysis['direct_costs']['license_cost']:,.0f}",
            f"${analysis['direct_costs']['implementation_cost'] + analysis['direct_costs']['training_cost']:,.0f}",
            f"${analysis['operational_costs']['total_operational_cost']:,.0f}",
            f"${analysis['total_first_year_cost']:,.0f}"
        )
    
    console.print(cost_table)
    
    # Create security benefit table
    benefit_table = Table(title="Security Benefits")
    benefit_table.add_column("Tool", style="cyan")
    benefit_table.add_column("Detected Vulns", style="green")
    benefit_table.add_column("Missed Vulns", style="red")
    benefit_table.add_column("False Positives", style="yellow")
    benefit_table.add_column("Annual Benefit", style="green")
    
    for tool_id, analysis in roi_analyses.items():
        benefit_table.add_row(
            tool_id,
            f"{analysis['operational_costs']['detected_vulnerabilities']:.1f}",
            f"{analysis['operational_costs']['missed_vulnerabilities']:.1f}",
            f"{analysis['operational_costs']['false_positives']:.1f}",
            f"${analysis['annual_benefit']:,.0f}"
        )
    
    console.print(benefit_table)
    
    # Create ROI table
    roi_table = Table(title="ROI Summary")
    roi_table.add_column("Tool", style="cyan")
    roi_table.add_column("1st Year ROI", style="green")
    roi_table.add_column("Payback Period", style="yellow")
    roi_table.add_column("5-Year ROI", style="green")
    roi_table.add_column("5-Year Net Benefit", style="green")
    
    for tool_id, analysis in roi_analyses.items():
        # Format ROI values
        if analysis["simple_roi"] == float('inf'):
            simple_roi = "∞"
        else:
            simple_roi = f"{analysis['simple_roi']:.1f}%"
        
        if analysis["payback_period_years"] == float('inf'):
            payback = "Never"
        elif analysis["payback_period_years"] > 5:
            payback = ">5 years"
        else:
            payback = f"{analysis['payback_period_years']:.1f} years"
        
        if analysis["five_year_roi"] == float('inf'):
            five_year_roi = "∞"
        else:
            five_year_roi = f"{analysis['five_year_roi']:.1f}%"
        
        net_benefit = analysis["five_year_benefit"] - analysis["five_year_cost"]
        
        roi_table.add_row(
            tool_id,
            simple_roi,
            payback,
            five_year_roi,
            f"${net_benefit:,.0f}"
        )
    
    console.print(roi_table)
    
    # Display interpretation
    console.print("\n[bold cyan]Interpretation:[/]")
    
    # Find best ROI
    best_roi_tool = max(roi_analyses.items(), key=lambda x: x[1]["simple_roi"])
    best_payback_tool = min(roi_analyses.items(), key=lambda x: x[1]["payback_period_years"])
    
    console.print(f"[green]• {best_roi_tool[0]}[/] offers the best first-year ROI at [bold]{simple_roi}[/]")
    
    if best_payback_tool[1]["payback_period_years"] != float('inf'):
        console.print(f"[green]• {best_payback_tool[0]}[/] has the shortest payback period at [bold]{payback}[/]")
    
    # Compare ossv-scanner
    if "ossv-scanner" in roi_analyses:
        ossv = roi_analyses["ossv-scanner"]
        ossv_roi = ossv["simple_roi"]
        
        if ossv_roi == float('inf'):
            console.print("[green]• ossv-scanner provides an extremely high ROI due to no license costs[/]")
        elif ossv_roi > 0:
            console.print(f"[green]• ossv-scanner provides a positive ROI of [bold]{ossv_roi:.1f}%[/][/]")
        else:
            console.print(f"[yellow]• ossv-scanner provides a negative first-year ROI of [bold]{ossv_roi:.1f}%[/][/]")
        
        # Compare 5-year ROI
        ossv_5yr_roi = ossv["five_year_roi"]
        if ossv_5yr_roi > 0:
            console.print(f"[green]• Over a 5-year period, ossv-scanner's ROI improves to [bold]{ossv_5yr_roi:.1f}%[/][/]")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = analyze_roi()
    print("ROI analysis completed")
