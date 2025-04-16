"""
Monte Carlo simulation for vulnerability detection.

This module implements Monte Carlo simulations to estimate the probability
of vulnerability detection and risk over time for different scanning strategies.
"""

import os
import time
import logging
import tempfile
import json
import random
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Default simulation parameters
DEFAULT_SIMULATION_PARAMS = {
    "num_simulations": 1000,   # Number of Monte Carlo iterations
    "time_period": 365,        # Days to simulate
    "vulnerability_rate": 0.02,  # Daily probability of new vulnerability appearing
    "detection_probability": {
        "ossv-scanner": 0.85,  # Probability of detection with ossv-scanner
        "manual-review": 0.40, # Probability of detection with manual reviews
        "no-scanning": 0.05    # Probability of detection with no active scanning
    },
    "vulnerability_severity": {
        "critical": 0.15,      # Probability of critical severity
        "high": 0.35,          # Probability of high severity
        "medium": 0.40,        # Probability of medium severity
        "low": 0.10            # Probability of low severity
    },
    "scanning_frequency": {
        "ossv-scanner": 1,     # Days between scans
        "manual-review": 30,   # Days between manual reviews
        "no-scanning": 90      # Days between passive discoveries
    },
    "breach_probability": {
        "critical": 0.10,      # Daily probability of breach from critical vuln
        "high": 0.03,          # Daily probability of breach from high vuln
        "medium": 0.01,        # Daily probability of breach from medium vuln
        "low": 0.001           # Daily probability of breach from low vuln
    },
    "breach_cost": {
        "critical": 5000000,   # Cost of critical breach
        "high": 1000000,       # Cost of high severity breach
        "medium": 250000,      # Cost of medium severity breach
        "low": 50000           # Cost of low severity breach
    },
    "scanning_cost": {
        "ossv-scanner": 100,    # Daily cost of using ossv-scanner
        "manual-review": 2000,  # Daily cost of manual reviews
        "no-scanning": 0        # Cost of no scanning
    }
}


def run_single_simulation(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run a single Monte Carlo simulation.
    
    Args:
        params: Simulation parameters.
        
    Returns:
        Simulation results.
    """
    # Initialize results
    results = {
        "vulnerabilities": {
            "ossv-scanner": [],
            "manual-review": [],
            "no-scanning": []
        },
        "detected": {
            "ossv-scanner": [],
            "manual-review": [],
            "no-scanning": []
        },
        "breaches": {
            "ossv-scanner": [],
            "manual-review": [],
            "no-scanning": []
        },
        "costs": {
            "ossv-scanner": 0,
            "manual-review": 0,
            "no-scanning": 0
        }
    }
    
    # Generate vulnerability timeline
    vulnerabilities = []
    for day in range(params["time_period"]):
        # Check if a new vulnerability appears this day
        if random.random() < params["vulnerability_rate"]:
            # Determine severity
            severity_rand = random.random()
            if severity_rand < params["vulnerability_severity"]["critical"]:
                severity = "critical"
            elif severity_rand < params["vulnerability_severity"]["critical"] + params["vulnerability_severity"]["high"]:
                severity = "high"
            elif severity_rand < params["vulnerability_severity"]["critical"] + params["vulnerability_severity"]["high"] + params["vulnerability_severity"]["medium"]:
                severity = "medium"
            else:
                severity = "low"
                
            vulnerabilities.append({
                "day": day,
                "severity": severity,
                "detected_by": {
                    "ossv-scanner": False,
                    "manual-review": False,
                    "no-scanning": False
                },
                "breach": {
                    "ossv-scanner": False,
                    "manual-review": False,
                    "no-scanning": False
                },
                "detection_day": {
                    "ossv-scanner": None,
                    "manual-review": None,
                    "no-scanning": None
                }
            })
    
    # For each scanning method, determine when vulnerabilities are detected
    for method in ["ossv-scanner", "manual-review", "no-scanning"]:
        # Days when scanning occurs
        scan_days = list(range(0, params["time_period"], params["scanning_frequency"][method]))
        
        # Check for detection on each scan day
        for scan_day in scan_days:
            # Add scanning cost
            results["costs"][method] += params["scanning_cost"][method]
            
            # Check each vulnerability
            for vuln in vulnerabilities:
                # Only consider vulnerabilities that exist and haven't been detected yet
                if vuln["day"] <= scan_day and not vuln["detected_by"][method]:
                    # Check if vulnerability is detected during this scan
                    if random.random() < params["detection_probability"][method]:
                        vuln["detected_by"][method] = True
                        vuln["detection_day"][method] = scan_day
                        results["detected"][method].append(vuln)
    
    # Calculate breaches
    for vuln in vulnerabilities:
        for method in ["ossv-scanner", "manual-review", "no-scanning"]:
            # Initialize days at risk
            start_day = vuln["day"]
            end_day = params["time_period"]
            
            # If detected, risk ends on detection day
            if vuln["detected_by"][method]:
                end_day = vuln["detection_day"][method]
            
            # Check each day for potential breach
            for day in range(start_day, end_day):
                # Daily probability of breach based on severity
                breach_prob = params["breach_probability"][vuln["severity"]]
                
                # Check if breach occurs
                if random.random() < breach_prob:
                    vuln["breach"][method] = True
                    results["breaches"][method].append({
                        "day": day,
                        "severity": vuln["severity"],
                        "cost": params["breach_cost"][vuln["severity"]]
                    })
                    # Add breach cost
                    results["costs"][method] += params["breach_cost"][vuln["severity"]]
                    break  # Only count one breach per vulnerability
    
    # Store vulnerability timeline
    results["vulnerabilities"] = vulnerabilities
    
    return results


def analyze_simulation_results(simulation_results: List[Dict[str, Any]], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze Monte Carlo simulation results.
    
    Args:
        simulation_results: List of simulation results.
        params: Simulation parameters.
        
    Returns:
        Analysis results.
    """
    analysis = {
        "vulnerability_summary": {
            "avg_vulnerabilities": 0,
            "std_vulnerabilities": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        },
        "detection_summary": {
            "ossv-scanner": {
                "avg_detected": 0,
                "avg_detection_rate": 0,
                "avg_time_to_detect": 0
            },
            "manual-review": {
                "avg_detected": 0,
                "avg_detection_rate": 0,
                "avg_time_to_detect": 0
            },
            "no-scanning": {
                "avg_detected": 0,
                "avg_detection_rate": 0,
                "avg_time_to_detect": 0
            }
        },
        "breach_summary": {
            "ossv-scanner": {
                "avg_breaches": 0,
                "avg_breach_cost": 0,
                "breach_probability": 0
            },
            "manual-review": {
                "avg_breaches": 0,
                "avg_breach_cost": 0,
                "breach_probability": 0
            },
            "no-scanning": {
                "avg_breaches": 0,
                "avg_breach_cost": 0,
                "breach_probability": 0
            }
        },
        "cost_summary": {
            "ossv-scanner": {
                "avg_total_cost": 0,
                "avg_scanning_cost": 0,
                "avg_breach_cost": 0,
                "roi": 0
            },
            "manual-review": {
                "avg_total_cost": 0,
                "avg_scanning_cost": 0,
                "avg_breach_cost": 0,
                "roi": 0
            },
            "no-scanning": {
                "avg_total_cost": 0,
                "avg_scanning_cost": 0,
                "avg_breach_cost": 0
            }
        },
        "confidence_intervals": {
            "ossv-scanner": {
                "detection_rate_95ci": (0, 0),
                "breaches_95ci": (0, 0),
                "cost_95ci": (0, 0)
            },
            "manual-review": {
                "detection_rate_95ci": (0, 0),
                "breaches_95ci": (0, 0),
                "cost_95ci": (0, 0)
            },
            "no-scanning": {
                "detection_rate_95ci": (0, 0),
                "breaches_95ci": (0, 0),
                "cost_95ci": (0, 0)
            }
        }
    }
    
    # Aggregate vulnerability data
    all_vulns = []
    for sim in simulation_results:
        all_vulns.append(len(sim["vulnerabilities"]))
        
        # Count by severity
        for vuln in sim["vulnerabilities"]:
            analysis["vulnerability_summary"]["by_severity"][vuln["severity"]] += 1
    
    # Calculate vulnerability statistics
    analysis["vulnerability_summary"]["avg_vulnerabilities"] = np.mean(all_vulns)
    analysis["vulnerability_summary"]["std_vulnerabilities"] = np.std(all_vulns)
    
    # Normalize severity counts
    num_sims = len(simulation_results)
    for severity in analysis["vulnerability_summary"]["by_severity"]:
        analysis["vulnerability_summary"]["by_severity"][severity] /= num_sims
    
    # Process detection data
    for method in ["ossv-scanner", "manual-review", "no-scanning"]:
        detected_counts = []
        detection_rates = []
        detection_times = []
        
        # Scan costs are fixed per simulation
        scan_cost_per_sim = params["scanning_frequency"][method] * params["scanning_cost"][method]
        total_scan_cost = scan_cost_per_sim * num_sims
        
        breach_counts = []
        breach_costs = []
        total_costs = []
        
        for sim in simulation_results:
            # Detection metrics
            total_vulns = len(sim["vulnerabilities"])
            detected = len(sim["detected"][method])
            detected_counts.append(detected)
            
            detection_rate = detected / total_vulns if total_vulns > 0 else 0
            detection_rates.append(detection_rate)
            
            # Calculate average time to detect
            if detected > 0:
                total_time = sum(vuln["detection_day"][method] - vuln["day"] 
                                for vuln in sim["detected"][method])
                avg_time = total_time / detected
                detection_times.append(avg_time)
            
            # Breach metrics
            breaches = len(sim["breaches"][method])
            breach_counts.append(breaches)
            
            breach_cost = sum(breach["cost"] for breach in sim["breaches"][method])
            breach_costs.append(breach_cost)
            
            # Total cost
            total_cost = sim["costs"][method]
            total_costs.append(total_cost)
        
        # Calculate detection summary
        analysis["detection_summary"][method]["avg_detected"] = np.mean(detected_counts)
        analysis["detection_summary"][method]["avg_detection_rate"] = np.mean(detection_rates)
        if detection_times:
            analysis["detection_summary"][method]["avg_time_to_detect"] = np.mean(detection_times)
        
        # Calculate breach summary
        analysis["breach_summary"][method]["avg_breaches"] = np.mean(breach_counts)
        analysis["breach_summary"][method]["avg_breach_cost"] = np.mean(breach_costs)
        analysis["breach_summary"][method]["breach_probability"] = len([c for c in breach_counts if c > 0]) / num_sims
        
        # Calculate cost summary
        analysis["cost_summary"][method]["avg_total_cost"] = np.mean(total_costs)
        analysis["cost_summary"][method]["avg_scanning_cost"] = scan_cost_per_sim
        analysis["cost_summary"][method]["avg_breach_cost"] = np.mean(breach_costs)
        
        # Calculate 95% confidence intervals
        alpha = 0.05  # 95% confidence
        analysis["confidence_intervals"][method]["detection_rate_95ci"] = (
            np.percentile(detection_rates, alpha/2 * 100),
            np.percentile(detection_rates, (1-alpha/2) * 100)
        )
        analysis["confidence_intervals"][method]["breaches_95ci"] = (
            np.percentile(breach_counts, alpha/2 * 100),
            np.percentile(breach_counts, (1-alpha/2) * 100)
        )
        analysis["confidence_intervals"][method]["cost_95ci"] = (
            np.percentile(total_costs, alpha/2 * 100),
            np.percentile(total_costs, (1-alpha/2) * 100)
        )
    
    # Calculate ROI (compared to no-scanning)
    no_scan_cost = analysis["cost_summary"]["no-scanning"]["avg_total_cost"]
    for method in ["ossv-scanner", "manual-review"]:
        method_cost = analysis["cost_summary"][method]["avg_total_cost"]
        cost_savings = no_scan_cost - method_cost
        investment = analysis["cost_summary"][method]["avg_scanning_cost"]
        
        if investment > 0:
            analysis["cost_summary"][method]["roi"] = cost_savings / investment
        else:
            analysis["cost_summary"][method]["roi"] = float('inf') if cost_savings > 0 else 0
    
    return analysis


def generate_simulation_plots(analysis: Dict[str, Any], output_dir: Path) -> Dict[str, Path]:
    """
    Generate plots from Monte Carlo simulation analysis.
    
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
    
    # 1. Vulnerability Detection Rate Comparison
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    methods = ["ossv-scanner", "manual-review", "no-scanning"]
    detection_rates = [analysis["detection_summary"][m]["avg_detection_rate"] for m in methods]
    confidence_intervals = [analysis["confidence_intervals"][m]["detection_rate_95ci"] for m in methods]
    lower_bounds = [ci[0] for ci in confidence_intervals]
    upper_bounds = [ci[1] for ci in confidence_intervals]
    ci_errors = [[r - l for r, l in zip(detection_rates, lower_bounds)], 
                [u - r for r, u in zip(detection_rates, upper_bounds)]]
    
    # Plot with error bars
    plt.bar(methods, detection_rates, yerr=ci_errors, capsize=10, color='skyblue')
    
    plt.title('Vulnerability Detection Rate Comparison')
    plt.xlabel('Scanning Method')
    plt.ylabel('Average Detection Rate')
    plt.ylim(0, 1.0)
    
    # Add value labels
    for i, v in enumerate(detection_rates):
        plt.text(i, v + 0.02, f"{v:.2f}", ha='center')
    
    detection_plot_path = output_dir / "detection_rate_comparison.png"
    plt.savefig(detection_plot_path)
    plt.close()
    plots["detection_rate_comparison"] = detection_plot_path
    
    # 2. Breach Probability Comparison
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    breach_probs = [analysis["breach_summary"][m]["breach_probability"] for m in methods]
    
    plt.bar(methods, breach_probs, color='salmon')
    
    plt.title('Breach Probability Comparison')
    plt.xlabel('Scanning Method')
    plt.ylabel('Probability of at Least One Breach')
    plt.ylim(0, 1.0)
    
    # Add value labels
    for i, v in enumerate(breach_probs):
        plt.text(i, v + 0.02, f"{v:.2f}", ha='center')
    
    breach_plot_path = output_dir / "breach_probability_comparison.png"
    plt.savefig(breach_plot_path)
    plt.close()
    plots["breach_probability_comparison"] = breach_plot_path
    
    # 3. Cost Comparison
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    scanning_costs = [analysis["cost_summary"][m]["avg_scanning_cost"] for m in methods]
    breach_costs = [analysis["cost_summary"][m]["avg_breach_cost"] for m in methods]
    
    # Create stacked bar chart
    width = 0.8
    plt.bar(methods, scanning_costs, width, label='Scanning Cost', color='lightblue')
    plt.bar(methods, breach_costs, width, bottom=scanning_costs, label='Breach Cost', color='lightcoral')
    
    plt.title('Cost Comparison')
    plt.xlabel('Scanning Method')
    plt.ylabel('Average Cost ($)')
    plt.legend()
    
    # Add total cost labels
    for i, method in enumerate(methods):
        total_cost = analysis["cost_summary"][method]["avg_total_cost"]
        plt.text(i, total_cost + 1000, f"${total_cost:,.0f}", ha='center')
    
    cost_plot_path = output_dir / "cost_comparison.png"
    plt.savefig(cost_plot_path)
    plt.close()
    plots["cost_comparison"] = cost_plot_path
    
    # 4. Return on Investment
    plt.figure(figsize=(10, 6))
    
    # Prepare data
    roi_methods = ["ossv-scanner", "manual-review"]
    roi_values = [analysis["cost_summary"][m]["roi"] for m in roi_methods]
    
    plt.bar(roi_methods, roi_values, color='lightgreen')
    
    plt.title('Return on Investment (Compared to No Scanning)')
    plt.xlabel('Scanning Method')
    plt.ylabel('ROI (Return / Investment)')
    
    # Add horizontal line at ROI = 1.0 (break-even)
    plt.axhline(y=1.0, color='r', linestyle='--', alpha=0.7)
    
    # Add value labels
    for i, v in enumerate(roi_values):
        plt.text(i, v + 0.1, f"{v:.2f}", ha='center')
    
    roi_plot_path = output_dir / "roi_comparison.png"
    plt.savefig(roi_plot_path)
    plt.close()
    plots["roi_comparison"] = roi_plot_path
    
    return plots


def run_simulation(comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run Monte Carlo simulations for vulnerability detection.
    
    Args:
        comprehensive: Whether to run comprehensive simulations.
        
    Returns:
        Simulation results and analysis.
    """
    logger.info("Starting Monte Carlo simulations")
    
    # Set up output directory
    output_dir = Path(tempfile.mkdtemp(prefix="ossv-monte-carlo-"))
    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Set simulation parameters
    params = DEFAULT_SIMULATION_PARAMS.copy()
    
    # Adjust parameters for comprehensive mode
    if comprehensive:
        params["num_simulations"] = 5000
        params["time_period"] = 730  # 2 years
    
    # Run simulations
    simulation_results = []
    
    with Progress() as progress:
        task = progress.add_task("[green]Running Monte Carlo simulations...", total=params["num_simulations"])
        
        for i in range(params["num_simulations"]):
            result = run_single_simulation(params)
            simulation_results.append(result)
            progress.update(task, advance=1)
    
    # Analyze results
    logger.info("Analyzing simulation results")
    analysis = analyze_simulation_results(simulation_results, params)
    
    # Generate plots
    logger.info("Generating visualization plots")
    plots = generate_simulation_plots(analysis, plots_dir)
    
    # Combine results
    final_results = {
        "parameters": params,
        "analysis": analysis,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "simulation_type": "comprehensive" if comprehensive else "standard",
            "num_simulations": params["num_simulations"]
        }
    }
    
    # Display summary
    display_summary(analysis, params)
    
    logger.info("Monte Carlo simulations completed")
    return final_results


def display_summary(analysis: Dict[str, Any], params: Dict[str, Any]) -> None:
    """
    Display a summary of Monte Carlo simulation results.
    
    Args:
        analysis: Analysis results.
        params: Simulation parameters.
    """
    console.print("\n[bold cyan]Monte Carlo Simulation Summary[/]")
    
    # Create vulnerability summary table
    vuln_table = Table(title="Vulnerability Summary")
    vuln_table.add_column("Metric", style="cyan")
    vuln_table.add_column("Value", style="green")
    
    vuln_table.add_row(
        "Average Vulnerabilities",
        f"{analysis['vulnerability_summary']['avg_vulnerabilities']:.2f} ± {analysis['vulnerability_summary']['std_vulnerabilities']:.2f}"
    )
    
    for severity in ["critical", "high", "medium", "low"]:
        vuln_table.add_row(
            f"Average {severity.title()} Vulnerabilities",
            f"{analysis['vulnerability_summary']['by_severity'][severity]:.2f}"
        )
    
    console.print(vuln_table)
    
    # Create detection comparison table
    detect_table = Table(title="Detection Comparison")
    detect_table.add_column("Metric", style="cyan")
    detect_table.add_column("ossv-scanner", style="green")
    detect_table.add_column("manual-review", style="yellow")
    detect_table.add_column("no-scanning", style="red")
    
    detect_table.add_row(
        "Average Detection Rate",
        f"{analysis['detection_summary']['ossv-scanner']['avg_detection_rate']:.2f}",
        f"{analysis['detection_summary']['manual-review']['avg_detection_rate']:.2f}",
        f"{analysis['detection_summary']['no-scanning']['avg_detection_rate']:.2f}"
    )
    
    detect_table.add_row(
        "Average Time to Detect (days)",
        f"{analysis['detection_summary']['ossv-scanner']['avg_time_to_detect']:.2f}",
        f"{analysis['detection_summary']['manual-review']['avg_time_to_detect']:.2f}",
        f"{analysis['detection_summary']['no-scanning']['avg_time_to_detect']:.2f}"
    )
    
    detect_table.add_row(
        "Probability of Breach",
        f"{analysis['breach_summary']['ossv-scanner']['breach_probability']:.2f}",
        f"{analysis['breach_summary']['manual-review']['breach_probability']:.2f}",
        f"{analysis['breach_summary']['no-scanning']['breach_probability']:.2f}"
    )
    
    console.print(detect_table)
    
    # Create cost comparison table
    cost_table = Table(title="Cost Comparison ($)")
    cost_table.add_column("Cost Category", style="cyan")
    cost_table.add_column("ossv-scanner", style="green")
    cost_table.add_column("manual-review", style="yellow")
    cost_table.add_column("no-scanning", style="red")
    
    cost_table.add_row(
        "Scanning Cost",
        f"{analysis['cost_summary']['ossv-scanner']['avg_scanning_cost']:,.2f}",
        f"{analysis['cost_summary']['manual-review']['avg_scanning_cost']:,.2f}",
        f"{analysis['cost_summary']['no-scanning']['avg_scanning_cost']:,.2f}"
    )
    
    cost_table.add_row(
        "Average Breach Cost",
        f"{analysis['cost_summary']['ossv-scanner']['avg_breach_cost']:,.2f}",
        f"{analysis['cost_summary']['manual-review']['avg_breach_cost']:,.2f}",
        f"{analysis['cost_summary']['no-scanning']['avg_breach_cost']:,.2f}"
    )
    
    cost_table.add_row(
        "Total Cost",
        f"{analysis['cost_summary']['ossv-scanner']['avg_total_cost']:,.2f}",
        f"{analysis['cost_summary']['manual-review']['avg_total_cost']:,.2f}",
        f"{analysis['cost_summary']['no-scanning']['avg_total_cost']:,.2f}"
    )
    
    console.print(cost_table)
    
    # Display ROI
    console.print("\n[bold cyan]Return on Investment:[/]")
    console.print(f"[green]ossv-scanner ROI:[/] {analysis['cost_summary']['ossv-scanner']['roi']:.2f}")
    console.print(f"[yellow]manual-review ROI:[/] {analysis['cost_summary']['manual-review']['roi']:.2f}")
    
    # Display conclusion
    console.print("\n[bold cyan]Conclusion:[/]")
    best_roi = max(["ossv-scanner", "manual-review"], key=lambda m: analysis['cost_summary'][m]['roi'])
    lowest_cost = min(["ossv-scanner", "manual-review", "no-scanning"], key=lambda m: analysis['cost_summary'][m]['avg_total_cost'])
    highest_detection = max(["ossv-scanner", "manual-review", "no-scanning"], key=lambda m: analysis['detection_summary'][m]['avg_detection_rate'])
    
    console.print(f"[green]• Best ROI:[/] {best_roi}")
    console.print(f"[green]• Lowest Total Cost:[/] {lowest_cost}")
    console.print(f"[green]• Highest Detection Rate:[/] {highest_detection}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_simulation()
    print("Monte Carlo simulation completed")
