"""
Confidence interval calculations for vulnerability detection metrics.

This module provides functions to calculate and visualize confidence intervals
for various metrics obtained from test results, helping to quantify uncertainty.
"""

import os
import time
import logging
import tempfile
import json
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from scipy import stats
from typing import Dict, Any, List, Optional, Tuple, Union, Callable
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Key performance metrics to calculate confidence intervals for
KEY_METRICS = [
    "true_positive_rate",
    "false_positive_rate",
    "precision",
    "recall",
    "f1_score",
    "scan_time",
    "memory_usage"
]


def bootstrap_ci(data: List[float], confidence: float = 0.95, n_bootstrap: int = 10000, 
                statistic: Callable = np.mean) -> Tuple[float, float]:
    """
    Calculate bootstrap confidence interval.
    
    Args:
        data: Data points.
        confidence: Confidence level (0-1).
        n_bootstrap: Number of bootstrap samples.
        statistic: Statistic function to compute (default: mean).
        
    Returns:
        Tuple of (lower_bound, upper_bound).
    """
    if not data:
        return (0, 0)
    
    # Convert data to numpy array
    data_array = np.array(data)
    
    # Generate bootstrap samples
    bootstrap_samples = np.random.choice(data_array, size=(n_bootstrap, len(data_array)), replace=True)
    
    # Compute statistic for each bootstrap sample
    bootstrap_statistics = np.apply_along_axis(statistic, 1, bootstrap_samples)
    
    # Calculate confidence interval
    alpha = 1 - confidence
    lower_bound = np.percentile(bootstrap_statistics, alpha/2 * 100)
    upper_bound = np.percentile(bootstrap_statistics, (1-alpha/2) * 100)
    
    return (lower_bound, upper_bound)


def parametric_ci(data: List[float], confidence: float = 0.95) -> Tuple[float, float]:
    """
    Calculate parametric confidence interval based on t-distribution.
    
    Args:
        data: Data points.
        confidence: Confidence level (0-1).
        
    Returns:
        Tuple of (lower_bound, upper_bound).
    """
    if len(data) < 2:
        return (0, 0) if not data else (data[0], data[0])
    
    # Calculate mean and standard error
    mean = np.mean(data)
    se = stats.sem(data)
    
    # Calculate confidence interval
    alpha = 1 - confidence
    t_value = stats.t.ppf(1 - alpha/2, len(data) - 1)
    margin_of_error = t_value * se
    
    return (mean - margin_of_error, mean + margin_of_error)


def proportion_ci(successes: int, trials: int, confidence: float = 0.95, 
                 method: str = "wilson") -> Tuple[float, float]:
    """
    Calculate confidence interval for a proportion.
    
    Args:
        successes: Number of successes.
        trials: Number of trials.
        confidence: Confidence level (0-1).
        method: Method to use ('normal', 'wilson', or 'agresti').
        
    Returns:
        Tuple of (lower_bound, upper_bound).
    """
    if trials == 0:
        return (0, 0)
    
    # Calculate proportion
    p = successes / trials
    
    # Calculate confidence interval based on method
    alpha = 1 - confidence
    z = stats.norm.ppf(1 - alpha/2)
    
    if method == "normal":
        # Normal approximation (Wald interval)
        se = np.sqrt(p * (1 - p) / trials)
        lower = max(0, p - z * se)
        upper = min(1, p + z * se)
        
    elif method == "wilson":
        # Wilson score interval
        denominator = 1 + z**2/trials
        center = (p + z**2/(2*trials)) / denominator
        margin = z * np.sqrt(p*(1-p)/trials + z**2/(4*trials**2)) / denominator
        lower = max(0, center - margin)
        upper = min(1, center + margin)
        
    elif method == "agresti":
        # Agresti-Coull interval
        n_tilde = trials + z**2
        p_tilde = (successes + z**2/2) / n_tilde
        se_tilde = np.sqrt(p_tilde * (1 - p_tilde) / n_tilde)
        lower = max(0, p_tilde - z * se_tilde)
        upper = min(1, p_tilde + z * se_tilde)
        
    else:
        raise ValueError(f"Unknown method: {method}")
    
    return (lower, upper)


def extract_metrics_from_results(results_dir: Path) -> Dict[str, Dict[str, List[float]]]:
    """
    Extract metrics from test results for confidence interval calculation.
    
    Args:
        results_dir: Directory containing test results.
        
    Returns:
        Dictionary mapping test types to dictionaries of metric lists.
    """
    metrics = {
        "controlled": {metric: [] for metric in KEY_METRICS},
        "benchmark": {metric: [] for metric in KEY_METRICS},
        "performance": {metric: [] for metric in KEY_METRICS}
    }
    
    try:
        # Check if directory exists
        if not results_dir.exists():
            logger.warning(f"Results directory {results_dir} does not exist")
            return metrics
        
        # Extract metrics from controlled tests
        controlled_dir = results_dir / "controlled"
        if controlled_dir.exists():
            for result_file in controlled_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        test_data = json.load(f)
                        
                        # Extract metrics from test cases
                        if "test_cases" in test_data:
                            for test_id, test_case in test_data["test_cases"].items():
                                if "analysis" in test_case and "metrics" in test_case["analysis"]:
                                    test_metrics = test_case["analysis"]["metrics"]
                                    
                                    # Add available metrics
                                    for metric in KEY_METRICS:
                                        if metric in test_metrics:
                                            metrics["controlled"][metric].append(test_metrics[metric])
                except Exception as e:
                    logger.warning(f"Error processing file {result_file}: {str(e)}")
        
        # Extract metrics from benchmark tests
        benchmark_dir = results_dir / "benchmark"
        if benchmark_dir.exists():
            for result_file in benchmark_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        benchmark_data = json.load(f)
                        
                        # Extract metrics from NIST benchmark
                        if "scanner_results" in benchmark_data:
                            scanner_results = benchmark_data["scanner_results"]
                            
                            if "detection_rate" in scanner_results:
                                metrics["benchmark"]["true_positive_rate"].append(scanner_results["detection_rate"])
                            
                            # Extract other available metrics
                            for metric in ["precision", "recall", "f1_score"]:
                                if metric in scanner_results:
                                    metrics["benchmark"][metric].append(scanner_results[metric])
                        
                        # Extract metrics from OWASP benchmark
                        if "benchmark_score" in benchmark_data and "overall" in benchmark_data["benchmark_score"]:
                            overall = benchmark_data["benchmark_score"]["overall"]
                            
                            if "true_positive_rate" in overall:
                                metrics["benchmark"]["true_positive_rate"].append(overall["true_positive_rate"])
                            
                            if "false_positive_rate" in overall:
                                metrics["benchmark"]["false_positive_rate"].append(overall["false_positive_rate"])
                except Exception as e:
                    logger.warning(f"Error processing file {result_file}: {str(e)}")
        
        # Extract metrics from performance tests
        performance_dir = results_dir / "performance"
        if performance_dir.exists():
            for result_file in performance_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        performance_data = json.load(f)
                        
                        # Extract metrics from test results
                        if "test_results" in performance_data:
                            for test_id, test_result in performance_data["test_results"].items():
                                if "metrics" in test_result:
                                    test_metrics = test_result["metrics"]
                                    
                                    # Add scan time
                                    if "duration" in test_metrics:
                                        metrics["performance"]["scan_time"].append(test_metrics["duration"])
                                    
                                    # Add memory usage
                                    if "memory_usage" in test_metrics:
                                        metrics["performance"]["memory_usage"].append(test_metrics["memory_usage"])
                except Exception as e:
                    logger.warning(f"Error processing file {result_file}: {str(e)}")
        
        return metrics
    
    except Exception as e:
        logger.error(f"Error extracting metrics: {str(e)}")
        return metrics


def calculate_confidence_intervals(metrics: Dict[str, Dict[str, List[float]]], 
                                 confidence: float = 0.95) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    Calculate confidence intervals for metrics.
    
    Args:
        metrics: Dictionary of metrics for different test types.
        confidence: Confidence level (0-1).
        
    Returns:
        Dictionary of confidence intervals for each metric.
    """
    intervals = {}
    
    for test_type, test_metrics in metrics.items():
        intervals[test_type] = {}
        
        for metric, values in test_metrics.items():
            if not values:
                intervals[test_type][metric] = {
                    "mean": 0,
                    "std": 0,
                    "count": 0,
                    "parametric_ci": (0, 0),
                    "bootstrap_ci": (0, 0),
                    "ci_width": 0
                }
                continue
            
            # Calculate statistics
            mean = np.mean(values)
            std = np.std(values)
            count = len(values)
            
            # Calculate confidence intervals
            parametric_ci_result = parametric_ci(values, confidence)
            bootstrap_ci_result = bootstrap_ci(values, confidence)
            
            # Calculate confidence interval width
            ci_width = bootstrap_ci_result[1] - bootstrap_ci_result[0]
            
            intervals[test_type][metric] = {
                "mean": mean,
                "std": std,
                "count": count,
                "parametric_ci": parametric_ci_result,
                "bootstrap_ci": bootstrap_ci_result,
                "ci_width": ci_width
            }
    
    return intervals


def generate_ci_plots(intervals: Dict[str, Dict[str, Dict[str, Any]]], output_dir: Path) -> Dict[str, Path]:
    """
    Generate confidence interval visualization plots.
    
    Args:
        intervals: Confidence interval results.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # 1. Performance Metrics with CIs
    perf_metrics = ["scan_time", "memory_usage"]
    available_perf_metrics = [m for m in perf_metrics if intervals.get("performance", {}).get(m, {}).get("count", 0) > 0]
    
    if available_perf_metrics:
        plt.figure(figsize=(10, 6))
        
        for i, metric in enumerate(available_perf_metrics):
            metric_data = intervals["performance"][metric]
            mean = metric_data["mean"]
            ci = metric_data["bootstrap_ci"]
            
            plt.barh(i, mean, xerr=[[mean - ci[0]], [ci[1] - mean]], 
                    capsize=10, color='skyblue', alpha=0.7, 
                    label=metric if i == 0 else "")
            
            # Add label
            plt.text(mean, i, f" {mean:.2f} ({ci[0]:.2f} - {ci[1]:.2f})", 
                    va='center')
        
        plt.yticks(range(len(available_perf_metrics)), [m.replace("_", " ").title() for m in available_perf_metrics])
        plt.xlabel("Value")
        plt.title("Performance Metrics with Confidence Intervals")
        
        perf_plot_path = output_dir / "performance_metrics_ci.png"
        plt.savefig(perf_plot_path)
        plt.close()
        plots["performance_metrics_ci"] = perf_plot_path
    
    # 2. Detection Metrics with CIs
    detection_metrics = ["true_positive_rate", "false_positive_rate", "precision", "recall", "f1_score"]
    
    for test_type in ["controlled", "benchmark"]:
        available_metrics = [m for m in detection_metrics 
                            if intervals.get(test_type, {}).get(m, {}).get("count", 0) > 0]
        
        if available_metrics:
            plt.figure(figsize=(10, 6))
            
            for i, metric in enumerate(available_metrics):
                metric_data = intervals[test_type][metric]
                mean = metric_data["mean"]
                ci = metric_data["bootstrap_ci"]
                
                plt.barh(i, mean, xerr=[[mean - ci[0]], [ci[1] - mean]], 
                        capsize=10, color='lightgreen', alpha=0.7, 
                        label=metric if i == 0 else "")
                
                # Add label
                plt.text(mean, i, f" {mean:.2f} ({ci[0]:.2f} - {ci[1]:.2f})", 
                        va='center')
            
            plt.yticks(range(len(available_metrics)), [m.replace("_", " ").title() for m in available_metrics])
            plt.xlabel("Value")
            plt.xlim(0, 1.1)
            plt.title(f"{test_type.title()} Detection Metrics with Confidence Intervals")
            
            detection_plot_path = output_dir / f"{test_type}_detection_metrics_ci.png"
            plt.savefig(detection_plot_path)
            plt.close()
            plots[f"{test_type}_detection_metrics_ci"] = detection_plot_path
    
    # 3. Confidence Interval Width Comparison
    plt.figure(figsize=(12, 8))
    
    # Collect metric names and CI widths across test types
    all_metrics = {}
    for test_type, metrics in intervals.items():
        for metric, data in metrics.items():
            if data["count"] > 1:  # Only include metrics with multiple data points
                if metric not in all_metrics:
                    all_metrics[metric] = {}
                all_metrics[metric][test_type] = data["ci_width"]
    
    # Create bar chart
    metric_names = []
    ci_widths = []
    bar_colors = []
    test_type_labels = []
    
    for metric, test_types in all_metrics.items():
        for test_type, width in test_types.items():
            metric_names.append(f"{metric}\n({test_type})")
            ci_widths.append(width)
            test_type_labels.append(test_type)
            
            # Set color based on test type
            if test_type == "controlled":
                bar_colors.append("lightgreen")
            elif test_type == "benchmark":
                bar_colors.append("skyblue")
            else:
                bar_colors.append("salmon")
    
    # Sort by CI width
    sorted_indices = np.argsort(ci_widths)[::-1]  # Descending order
    sorted_metric_names = [metric_names[i] for i in sorted_indices]
    sorted_ci_widths = [ci_widths[i] for i in sorted_indices]
    sorted_bar_colors = [bar_colors[i] for i in sorted_indices]
    
    # Plot
    plt.bar(sorted_metric_names, sorted_ci_widths, color=sorted_bar_colors)
    plt.title("Confidence Interval Width Comparison")
    plt.xlabel("Metric (Test Type)")
    plt.ylabel("CI Width")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    
    ci_width_path = output_dir / "ci_width_comparison.png"
    plt.savefig(ci_width_path)
    plt.close()
    plots["ci_width_comparison"] = ci_width_path
    
    return plots


def calculate_intervals(input_dir: Optional[str] = None, confidence: float = 0.95) -> Dict[str, Any]:
    """
    Calculate confidence intervals for metrics in test results.
    
    Args:
        input_dir: Directory containing test results. If None, uses default location.
        confidence: Confidence level (0-1).
        
    Returns:
        Dictionary with confidence interval analysis.
    """
    logger.info("Starting confidence interval calculations")
    
    # Set up input and output directories
    if input_dir:
        input_path = Path(input_dir)
    else:
        # Use a default location - this may need to be adjusted for your environment
        input_path = Path(tempfile.gettempdir()) / "ossv-testing-results"
    
    output_dir = Path(tempfile.mkdtemp(prefix="ossv-confidence-"))
    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Extract metrics from test results
    logger.info(f"Extracting metrics from test results in {input_path}")
    metrics = extract_metrics_from_results(input_path)
    
    # Check if we have any metrics
    total_metrics = sum(len(values) for metric_dict in metrics.values() for values in metric_dict.values())
    
    if total_metrics == 0:
        logger.warning("No metrics found for confidence interval calculation")
        return {
            "input_dir": str(input_path),
            "output_dir": str(output_dir),
            "error": "No metrics found for confidence interval calculation",
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "confidence_level": confidence
            }
        }
    
    # Calculate confidence intervals
    logger.info(f"Calculating {confidence*100}% confidence intervals")
    intervals = calculate_confidence_intervals(metrics, confidence)
    
    # Generate plots
    logger.info("Generating confidence interval plots")
    plots = generate_ci_plots(intervals, plots_dir)
    
    # Prepare final results
    ci_results = {
        "input_dir": str(input_path),
        "output_dir": str(output_dir),
        "confidence_intervals": intervals,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "confidence_level": confidence,
            "metrics_analyzed": sum(1 for test_type in intervals.values() 
                                  for metric in test_type.values() 
                                  if metric["count"] > 0)
        }
    }
    
    # Display summary
    display_summary(intervals, confidence)
    
    logger.info("Confidence interval calculations completed")
    return ci_results


def display_summary(intervals: Dict[str, Dict[str, Dict[str, Any]]], confidence: float) -> None:
    """
    Display a summary of confidence interval results.
    
    Args:
        intervals: Confidence interval results.
        confidence: Confidence level.
    """
    console.print(f"\n[bold cyan]Confidence Interval Analysis ({confidence*100:.0f}% Confidence)[/]")
    
    # Display summary for each test type
    for test_type, metrics in intervals.items():
        metrics_with_data = {name: data for name, data in metrics.items() if data["count"] > 0}
        
        if not metrics_with_data:
            continue
        
        console.print(f"\n[bold cyan]{test_type.title()} Test Metrics:[/]")
        
        # Create table
        table = Table()
        table.add_column("Metric", style="green")
        table.add_column("Mean", style="cyan")
        table.add_column("Confidence Interval", style="yellow")
        table.add_column("Sample Size", style="cyan")
        
        for metric, data in metrics_with_data.items():
            ci = data["bootstrap_ci"]
            table.add_row(
                metric.replace("_", " ").title(),
                f"{data['mean']:.4f}",
                f"({ci[0]:.4f}, {ci[1]:.4f})",
                str(data["count"])
            )
        
        console.print(table)
    
    # Display interpretation
    console.print("\n[bold cyan]Interpretation:[/]")
    
    # Find metrics with most data
    all_metrics = []
    for test_type, metrics in intervals.items():
        for metric, data in metrics.items():
            if data["count"] > 0:
                all_metrics.append((test_type, metric, data))
    
    # Sort by sample size
    all_metrics.sort(key=lambda x: x[2]["count"], reverse=True)
    
    # Report on most reliable metrics
    if all_metrics:
        most_reliable = all_metrics[0]
        console.print(f"[green]• Most reliable metric:[/] {most_reliable[1].replace('_', ' ').title()} from {most_reliable[0].title()} tests with {most_reliable[2]['count']} samples")
        
        # Find narrowest CI
        narrowest_ci = min(all_metrics, key=lambda x: x[2]["ci_width"])
        console.print(f"[green]• Narrowest confidence interval:[/] {narrowest_ci[1].replace('_', ' ').title()} from {narrowest_ci[0].title()} tests ({narrowest_ci[2]['ci_width']:.4f} width)")
        
        # Find widest CI
        widest_ci = max(all_metrics, key=lambda x: x[2]["ci_width"])
        console.print(f"[yellow]• Widest confidence interval:[/] {widest_ci[1].replace('_', ' ').title()} from {widest_ci[0].title()} tests ({widest_ci[2]['ci_width']:.4f} width)")
        
        # Check for concerning metrics (wide CIs)
        concerning_metrics = [m for m in all_metrics if m[2]["ci_width"] > 0.3 and m[2]["count"] > 3]
        if concerning_metrics:
            console.print("\n[bold yellow]Metrics with wide confidence intervals that may need more testing:[/]")
            for test_type, metric, data in concerning_metrics:
                console.print(f"• {metric.replace('_', ' ').title()} from {test_type.title()} tests (CI width: {data['ci_width']:.4f})")
    
    console.print("\n[yellow]Note:[/] Wider confidence intervals indicate greater uncertainty in the estimate.")
    console.print("[yellow]To narrow confidence intervals:[/] Run more tests to increase sample size.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = calculate_intervals()
    print("Confidence interval calculations completed")
