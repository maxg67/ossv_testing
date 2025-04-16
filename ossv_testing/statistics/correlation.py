"""
Correlation analysis for vulnerability scanning results.

This module analyzes correlations between various metrics and factors
in vulnerability scanning to identify patterns and dependencies.
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
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Metrics to include in correlation analysis
CORRELATION_METRICS = [
    # Detection effectiveness
    "true_positive_rate",
    "false_positive_rate",
    "detection_latency",
    
    # Project characteristics
    "project_size",
    "dependency_count",
    "language_diversity",
    
    # Vulnerability characteristics
    "vulnerability_count",
    "severity_distribution",
    "vulnerability_age",
    
    # Scanner performance
    "scan_time",
    "memory_usage",
    "cpu_usage"
]


def load_test_results(results_dir: Path) -> Dict[str, Any]:
    """
    Load test results from directory.
    
    Args:
        results_dir: Directory containing test results.
        
    Returns:
        Dictionary of loaded test results.
    """
    consolidated_results = {
        "benchmark": {},
        "controlled": {},
        "performance": {},
        "projects": []
    }
    
    try:
        # Check if directory exists
        if not results_dir.exists():
            logger.warning(f"Results directory {results_dir} does not exist")
            return consolidated_results
        
        # Look for benchmark results
        benchmark_dir = results_dir / "benchmark"
        if benchmark_dir.exists():
            for result_file in benchmark_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        benchmark_data = json.load(f)
                        benchmark_type = result_file.stem.replace("benchmark_", "").replace("_results", "")
                        consolidated_results["benchmark"][benchmark_type] = benchmark_data
                except Exception as e:
                    logger.warning(f"Error loading benchmark file {result_file}: {str(e)}")
        
        # Look for controlled test results
        controlled_dir = results_dir / "controlled"
        if controlled_dir.exists():
            for result_file in controlled_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        controlled_data = json.load(f)
                        test_type = result_file.stem.replace("_results", "")
                        consolidated_results["controlled"][test_type] = controlled_data
                except Exception as e:
                    logger.warning(f"Error loading controlled test file {result_file}: {str(e)}")
        
        # Look for performance test results
        performance_dir = results_dir / "performance"
        if performance_dir.exists():
            for result_file in performance_dir.glob("*.json"):
                try:
                    with open(result_file, "r") as f:
                        performance_data = json.load(f)
                        test_type = result_file.stem.replace("performance_", "").replace("_results", "")
                        consolidated_results["performance"][test_type] = performance_data
                except Exception as e:
                    logger.warning(f"Error loading performance test file {result_file}: {str(e)}")
        
        # Extract project-level data for correlation analysis
        consolidated_results["projects"] = extract_project_data(consolidated_results)
        
        return consolidated_results
    
    except Exception as e:
        logger.error(f"Error loading test results: {str(e)}")
        return consolidated_results


def extract_project_data(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract project-level data from test results for correlation analysis.
    
    Args:
        results: Consolidated test results.
        
    Returns:
        List of project data dictionaries.
    """
    projects = []
    
    # Extract from controlled tests
    if "controlled" in results and "test_suite" in results["controlled"]:
        test_suite = results["controlled"]["test_suite"]
        if "test_cases" in test_suite:
            for test_id, test_case in test_suite.get("test_cases", {}).items():
                if "analysis" not in test_case:
                    continue
                    
                analysis = test_case["analysis"]
                
                # Extract project characteristics
                project = {
                    "project_id": test_id,
                    "project_name": test_case.get("name", "Unknown"),
                    "ecosystem": test_case.get("ecosystem", "Unknown"),
                    
                    # Metrics
                    "dependency_count": len(analysis.get("detected_vulns", [])) + len(analysis.get("missed_vulns", [])),
                    "vulnerability_count": len(analysis.get("detected_vulns", [])) + len(analysis.get("missed_vulns", [])),
                    "true_positive_rate": analysis.get("metrics", {}).get("true_positives", 0) / 
                                        (analysis.get("metrics", {}).get("true_positives", 0) + 
                                         analysis.get("metrics", {}).get("false_negatives", 0))
                                        if (analysis.get("metrics", {}).get("true_positives", 0) + 
                                            analysis.get("metrics", {}).get("false_negatives", 0)) > 0 else 0,
                    "false_positive_rate": analysis.get("metrics", {}).get("false_positives", 0) / 
                                         (analysis.get("metrics", {}).get("true_positives", 0) + 
                                          analysis.get("metrics", {}).get("false_positives", 0))
                                         if (analysis.get("metrics", {}).get("true_positives", 0) + 
                                             analysis.get("metrics", {}).get("false_positives", 0)) > 0 else 0,
                    "severity_high_pct": sum(1 for v in analysis.get("detected_vulns", []) 
                                         if v.get("expected", {}).get("severity", "") == "HIGH") / 
                                       len(analysis.get("detected_vulns", [])) if len(analysis.get("detected_vulns", [])) > 0 else 0
                }
                
                projects.append(project)
    
    # Extract from performance tests
    if "performance" in results and "load" in results["performance"]:
        load_tests = results["performance"]["load"]
        if "test_results" in load_tests:
            for config_id, result in load_tests.get("test_results", {}).items():
                if "analysis" not in result:
                    continue
                    
                analysis = result["analysis"]
                
                # Extract project and performance characteristics
                project = {
                    "project_id": config_id,
                    "project_name": result.get("config", {}).get("name", "Unknown"),
                    "project_size": (result.get("config", {}).get("npm_deps", 0) + 
                                   result.get("config", {}).get("python_deps", 0) + 
                                   result.get("config", {}).get("java_deps", 0)),
                    
                    # Performance metrics
                    "scan_time": result.get("metrics", {}).get("duration", 0),
                    "memory_usage": result.get("metrics", {}).get("memory_usage", 0),
                    "cpu_usage": result.get("metrics", {}).get("cpu_usage", 0),
                    "dependency_count": (result.get("config", {}).get("npm_deps", 0) + 
                                       result.get("config", {}).get("python_deps", 0) + 
                                       result.get("config", {}).get("java_deps", 0))
                }
                
                projects.append(project)
    
    return projects


def calculate_correlations(project_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate correlations between metrics.
    
    Args:
        project_data: List of project data dictionaries.
        
    Returns:
        Correlation analysis results.
    """
    # Convert to DataFrame
    df = pd.DataFrame(project_data)
    
    # Select numeric columns only
    numeric_df = df.select_dtypes(include=[np.number])
    
    # Replace NaN with 0
    numeric_df = numeric_df.fillna(0)
    
    # Initialize correlation results
    correlation_results = {
        "pearson": {},
        "spearman": {},
        "significant_correlations": [],
        "metrics_analyzed": list(numeric_df.columns),
        "correlation_matrix": None,
        "sample_size": len(numeric_df)
    }
    
    # Calculate Pearson correlation
    try:
        pearson_corr = numeric_df.corr(method='pearson')
        correlation_results["pearson"] = pearson_corr.to_dict()
        correlation_results["correlation_matrix"] = pearson_corr.to_dict()
    except Exception as e:
        logger.warning(f"Error calculating Pearson correlation: {str(e)}")
        correlation_results["pearson"] = {}
    
    # Calculate Spearman correlation
    try:
        spearman_corr = numeric_df.corr(method='spearman')
        correlation_results["spearman"] = spearman_corr.to_dict()
    except Exception as e:
        logger.warning(f"Error calculating Spearman correlation: {str(e)}")
        correlation_results["spearman"] = {}
    
    # Find significant correlations
    p_threshold = 0.05
    for col1 in numeric_df.columns:
        for col2 in numeric_df.columns:
            if col1 != col2:
                try:
                    # Calculate Pearson correlation and p-value
                    r, p = stats.pearsonr(numeric_df[col1], numeric_df[col2])
                    
                    # Check if correlation is significant
                    if p < p_threshold and abs(r) > 0.5:
                        correlation_results["significant_correlations"].append({
                            "metric1": col1,
                            "metric2": col2,
                            "correlation": r,
                            "p_value": p,
                            "strength": "strong" if abs(r) > 0.7 else "moderate",
                            "direction": "positive" if r > 0 else "negative"
                        })
                except Exception as e:
                    logger.debug(f"Error calculating correlation for {col1} and {col2}: {str(e)}")
    
    return correlation_results


def generate_correlation_plots(correlation_results: Dict[str, Any], output_dir: Path) -> Dict[str, Path]:
    """
    Generate correlation analysis plots.
    
    Args:
        correlation_results: Correlation analysis results.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # 1. Correlation Heatmap
    plt.figure(figsize=(14, 12))
    
    # Convert correlation matrix to DataFrame
    if correlation_results["correlation_matrix"]:
        corr_matrix = pd.DataFrame(correlation_results["correlation_matrix"])
        
        # Create heatmap
        mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
        sns.heatmap(corr_matrix, mask=mask, cmap="coolwarm", vmin=-1, vmax=1, annot=True, fmt=".2f",
                    linewidths=0.5, cbar_kws={"shrink": 0.8})
        
        plt.title("Correlation Matrix Heatmap")
        plt.tight_layout()
        
        heatmap_path = output_dir / "correlation_heatmap.png"
        plt.savefig(heatmap_path)
        plt.close()
        plots["correlation_heatmap"] = heatmap_path
    
    # 2. Significant Correlations Bar Chart
    if correlation_results["significant_correlations"]:
        plt.figure(figsize=(14, 10))
        
        # Prepare data
        sig_corrs = correlation_results["significant_correlations"]
        metric_pairs = [f"{c['metric1']}\nvs.\n{c['metric2']}" for c in sig_corrs]
        correlation_values = [c["correlation"] for c in sig_corrs]
        
        # Create bar chart
        bars = plt.bar(metric_pairs, correlation_values, color=[
            'green' if c >= 0 else 'red' for c in correlation_values
        ])
        
        # Add labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, height,
                    f"{height:.2f}", ha='center', va='bottom' if height >= 0 else 'top')
        
        plt.title("Significant Correlations")
        plt.xlabel("Metric Pairs")
        plt.ylabel("Correlation Coefficient")
        plt.axhline(y=0, color='black', linestyle='-', alpha=0.3)
        plt.axhline(y=0.7, color='green', linestyle='--', alpha=0.5, label="Strong Positive")
        plt.axhline(y=-0.7, color='red', linestyle='--', alpha=0.5, label="Strong Negative")
        plt.legend()
        
        # Handle long metric names
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        sig_corr_path = output_dir / "significant_correlations.png"
        plt.savefig(sig_corr_path)
        plt.close()
        plots["significant_correlations"] = sig_corr_path
    
    # 3. Scatter Matrix for Key Metrics
    try:
        # Choose key metrics for scatter matrix
        key_metrics = [
            "scan_time", "dependency_count", "true_positive_rate", 
            "memory_usage", "project_size"
        ]
        
        # Get available metrics
        available_metrics = correlation_results["metrics_analyzed"]
        metrics_to_use = [m for m in key_metrics if m in available_metrics]
        
        if len(metrics_to_use) >= 3:
            plt.figure(figsize=(14, 14))
            
            # Create sample DataFrame with the metrics
            df = pd.DataFrame({metric: correlation_results["pearson"].get(metric, {}) 
                            for metric in metrics_to_use})
            
            # Create scatter matrix
            axes = pd.plotting.scatter_matrix(df, alpha=0.5, diagonal='kde', figsize=(14, 14))
            
            # Set labels
            for i, metric_i in enumerate(metrics_to_use):
                for j, metric_j in enumerate(metrics_to_use):
                    if i != j:
                        axes[i, j].set_xlabel(metric_j)
                        axes[i, j].set_ylabel(metric_i)
            
            plt.suptitle("Scatter Matrix for Key Metrics")
            plt.tight_layout()
            plt.subplots_adjust(top=0.95)
            
            scatter_matrix_path = output_dir / "scatter_matrix.png"
            plt.savefig(scatter_matrix_path)
            plt.close()
            plots["scatter_matrix"] = scatter_matrix_path
    except Exception as e:
        logger.warning(f"Error creating scatter matrix: {str(e)}")
    
    return plots


def analyze_correlation(input_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze correlations between metrics in test results.
    
    Args:
        input_dir: Directory containing test results. If None, uses default location.
        
    Returns:
        Dictionary with correlation analysis.
    """
    logger.info("Starting correlation analysis")
    
    # Set up input and output directories
    if input_dir:
        input_path = Path(input_dir)
    else:
        # Use a default location - this may need to be adjusted for your environment
        input_path = Path(tempfile.gettempdir()) / "ossv-testing-results"
    
    output_dir = Path(tempfile.mkdtemp(prefix="ossv-correlation-"))
    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Load test results
    logger.info(f"Loading test results from {input_path}")
    test_results = load_test_results(input_path)
    
    # Check if we have project data
    if not test_results["projects"]:
        logger.warning("No project data found for correlation analysis")
        return {
            "input_dir": str(input_path),
            "output_dir": str(output_dir),
            "error": "No project data found for correlation analysis",
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        }
    
    # Calculate correlations
    logger.info(f"Calculating correlations for {len(test_results['projects'])} projects")
    correlation_results = calculate_correlations(test_results["projects"])
    
    # Generate plots
    logger.info("Generating correlation plots")
    plots = generate_correlation_plots(correlation_results, plots_dir)
    
    # Prepare final results
    analysis_results = {
        "input_dir": str(input_path),
        "output_dir": str(output_dir),
        "correlation_results": correlation_results,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "projects_analyzed": len(test_results["projects"]),
            "metrics_analyzed": correlation_results["metrics_analyzed"],
            "significant_correlations": len(correlation_results["significant_correlations"])
        }
    }
    
    # Display summary
    display_summary(correlation_results)
    
    logger.info("Correlation analysis completed")
    return analysis_results


def display_summary(correlation_results: Dict[str, Any]) -> None:
    """
    Display a summary of correlation analysis results.
    
    Args:
        correlation_results: Correlation analysis results.
    """
    console.print("\n[bold cyan]Correlation Analysis Summary[/]")
    
    # Create summary table
    table = Table(title=f"Analyzed {correlation_results['sample_size']} Projects")
    table.add_column("Metrics Analyzed", style="cyan")
    table.add_column("Value", justify="center")
    
    table.add_row("Metrics Included", str(len(correlation_results["metrics_analyzed"])))
    table.add_row("Significant Correlations Found", str(len(correlation_results["significant_correlations"])))
    
    console.print(table)
    
    # Display significant correlations
    if correlation_results["significant_correlations"]:
        console.print("\n[bold cyan]Significant Correlations:[/]")
        
        sig_table = Table()
        sig_table.add_column("Metric 1", style="green")
        sig_table.add_column("Metric 2", style="green")
        sig_table.add_column("Correlation", style="cyan")
        sig_table.add_column("P-Value", style="yellow")
        sig_table.add_column("Strength", style="cyan")
        sig_table.add_column("Direction", style="cyan")
        
        # Sort by absolute correlation strength
        sorted_corrs = sorted(
            correlation_results["significant_correlations"],
            key=lambda x: abs(x["correlation"]),
            reverse=True
        )
        
        for corr in sorted_corrs:
            sig_table.add_row(
                corr["metric1"],
                corr["metric2"],
                f"{corr['correlation']:.4f}",
                f"{corr['p_value']:.4f}",
                corr["strength"],
                corr["direction"]
            )
        
        console.print(sig_table)
        
        # Display key insights
        console.print("\n[bold cyan]Key Insights:[/]")
        
        # Find strongest positive correlation
        strongest_pos = max(correlation_results["significant_correlations"], 
                           key=lambda x: x["correlation"] if x["correlation"] > 0 else -float('inf'))
        
        if strongest_pos["correlation"] > 0:
            console.print(f"[green]• Strongest positive correlation:[/] {strongest_pos['metric1']} and {strongest_pos['metric2']} ({strongest_pos['correlation']:.4f})")
        
        # Find strongest negative correlation
        strongest_neg = min(correlation_results["significant_correlations"], 
                           key=lambda x: x["correlation"])
        
        if strongest_neg["correlation"] < 0:
            console.print(f"[red]• Strongest negative correlation:[/] {strongest_neg['metric1']} and {strongest_neg['metric2']} ({strongest_neg['correlation']:.4f})")
        
        # Find correlations with scan performance
        perf_corrs = [c for c in correlation_results["significant_correlations"] 
                    if "scan_time" in [c["metric1"], c["metric2"]]]
        
        if perf_corrs:
            console.print("[yellow]• Factors correlated with scan time:[/]")
            for corr in perf_corrs:
                other_metric = corr["metric2"] if corr["metric1"] == "scan_time" else corr["metric1"]
                direction = "increases" if corr["correlation"] > 0 else "decreases"
                console.print(f"  - As {other_metric} increases, scan time {direction} (r={corr['correlation']:.4f})")
    else:
        console.print("[yellow]No significant correlations found.[/]")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = analyze_correlation()
    print("Correlation analysis completed")
