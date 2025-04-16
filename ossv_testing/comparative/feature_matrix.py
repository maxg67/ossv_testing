"""
Feature comparison matrix for ossv-scanner.

This module creates a comprehensive feature comparison matrix between
ossv-scanner and other vulnerability scanning tools.
"""

import os
import time
import logging
import tempfile
import json
import yaml
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from matplotlib.patches import Patch
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Define features for comparison
FEATURE_CATEGORIES = {
    "Vulnerability Detection": [
        "npm dependencies",
        "PyPI dependencies",
        "Maven dependencies",
        "Gem dependencies",
        "Go dependencies",
        "Transitive dependencies",
        "CVE database integration",
        "GitHub advisories integration",
        "Custom vulnerability rules"
    ],
    "SBOM Generation": [
        "CycloneDX format",
        "SPDX format",
        "JSON output",
        "XML output",
        "PDF report",
        "License information",
        "Package URL (PURL) support",
        "Component evidence"
    ],
    "Scanning Capabilities": [
        "Command-line interface",
        "Programmatic API",
        "Local scanning",
        "CI/CD integration",
        "IDE plugins",
        "Docker container scanning",
        "Offline scanning"
    ],
    "Remediation": [
        "Vulnerability details",
        "Fix recommendations",
        "Automatic PR generation",
        "Severity classification",
        "Exploit likelihood",
        "Affected component paths",
        "Prioritization guidance"
    ],
    "Usability & Integration": [
        "Custom policies",
        "Ignore patterns",
        "Configuration file",
        "Output customization",
        "GitHub integration",
        "GitLab integration",
        "Jenkins integration",
        "REST API",
        "Multi-language support"
    ],
    "Reporting & Management": [
        "Historical vulnerability tracking",
        "Centralized dashboard",
        "Custom reports",
        "Team collaboration",
        "Role-based access control",
        "Compliance reporting",
        "Metrics and KPIs",
        "Notification system"
    ]
}

# Feature data for ossv-scanner and comparison tools
DEFAULT_FEATURE_DATA = {
    "ossv-scanner": {
        "description": "Open Source Software Vulnerability Scanner",
        "license": "Open Source",
        "primary_language": "Python",
        "website": "",
        "features": {
            # Vulnerability Detection
            "npm dependencies": True,
            "PyPI dependencies": True,
            "Maven dependencies": True,
            "Gem dependencies": False,
            "Go dependencies": False,
            "Transitive dependencies": True,
            "CVE database integration": True,
            "GitHub advisories integration": False,
            "Custom vulnerability rules": False,
            
            # SBOM Generation
            "CycloneDX format": True,
            "SPDX format": False,
            "JSON output": True,
            "XML output": True,
            "PDF report": False,
            "License information": True,
            "Package URL (PURL) support": True,
            "Component evidence": True,
            
            # Scanning Capabilities
            "Command-line interface": True,
            "Programmatic API": True,
            "Local scanning": True,
            "CI/CD integration": True,
            "IDE plugins": False,
            "Docker container scanning": False,
            "Offline scanning": True,
            
            # Remediation
            "Vulnerability details": True,
            "Fix recommendations": True,
            "Automatic PR generation": False,
            "Severity classification": True,
            "Exploit likelihood": False,
            "Affected component paths": True,
            "Prioritization guidance": False,
            
            # Usability & Integration
            "Custom policies": False,
            "Ignore patterns": True,
            "Configuration file": True,
            "Output customization": True,
            "GitHub integration": False,
            "GitLab integration": False,
            "Jenkins integration": False,
            "REST API": False,
            "Multi-language support": True,
            
            # Reporting & Management
            "Historical vulnerability tracking": False,
            "Centralized dashboard": False,
            "Custom reports": True,
            "Team collaboration": False,
            "Role-based access control": False,
            "Compliance reporting": False,
            "Metrics and KPIs": True,
            "Notification system": False
        }
    },
    "snyk": {
        "description": "Developer security platform",
        "license": "Commercial",
        "primary_language": "JavaScript",
        "website": "https://snyk.io/",
        "features": {
            # Vulnerability Detection
            "npm dependencies": True,
            "PyPI dependencies": True,
            "Maven dependencies": True,
            "Gem dependencies": True,
            "Go dependencies": True,
            "Transitive dependencies": True,
            "CVE database integration": True,
            "GitHub advisories integration": True,
            "Custom vulnerability rules": True,
            
            # SBOM Generation
            "CycloneDX format": True,
            "SPDX format": True,
            "JSON output": True,
            "XML output": True,
            "PDF report": True,
            "License information": True,
            "Package URL (PURL) support": True,
            "Component evidence": True,
            
            # Scanning Capabilities
            "Command-line interface": True,
            "Programmatic API": True,
            "Local scanning": True,
            "CI/CD integration": True,
            "IDE plugins": True,
            "Docker container scanning": True,
            "Offline scanning": True,
            
            # Remediation
            "Vulnerability details": True,
            "Fix recommendations": True,
            "Automatic PR generation": True,
            "Severity classification": True,
            "Exploit likelihood": True,
            "Affected component paths": True,
            "Prioritization guidance": True,
            
            # Usability & Integration
            "Custom policies": True,
            "Ignore patterns": True,
            "Configuration file": True,
            "Output customization": True,
            "GitHub integration": True,
            "GitLab integration": True,
            "Jenkins integration": True,
            "REST API": True,
            "Multi-language support": True,
            
            # Reporting & Management
            "Historical vulnerability tracking": True,
            "Centralized dashboard": True,
            "Custom reports": True,
            "Team collaboration": True,
            "Role-based access control": True,
            "Compliance reporting": True,
            "Metrics and KPIs": True,
            "Notification system": True
        }
    },
    "dependabot": {
        "description": "GitHub's dependency scanning tool",
        "license": "Free with GitHub",
        "primary_language": "Ruby",
        "website": "https://github.com/dependabot",
        "features": {
            # Vulnerability Detection
            "npm dependencies": True,
            "PyPI dependencies": True,
            "Maven dependencies": True,
            "Gem dependencies": True,
            "Go dependencies": True,
            "Transitive dependencies": True,
            "CVE database integration": True,
            "GitHub advisories integration": True,
            "Custom vulnerability rules": False,
            
            # SBOM Generation
            "CycloneDX format": False,
            "SPDX format": False,
            "JSON output": False,
            "XML output": False,
            "PDF report": False,
            "License information": True,
            "Package URL (PURL) support": False,
            "Component evidence": False,
            
            # Scanning Capabilities
            "Command-line interface": False,
            "Programmatic API": False,
            "Local scanning": False,
            "CI/CD integration": True,
            "IDE plugins": False,
            "Docker container scanning": False,
            "Offline scanning": False,
            
            # Remediation
            "Vulnerability details": True,
            "Fix recommendations": True,
            "Automatic PR generation": True,
            "Severity classification": True,
            "Exploit likelihood": False,
            "Affected component paths": True,
            "Prioritization guidance": False,
            
            # Usability & Integration
            "Custom policies": False,
            "Ignore patterns": True,
            "Configuration file": True,
            "Output customization": False,
            "GitHub integration": True,
            "GitLab integration": False,
            "Jenkins integration": False,
            "REST API": False,
            "Multi-language support": True,
            
            # Reporting & Management
            "Historical vulnerability tracking": True,
            "Centralized dashboard": False,
            "Custom reports": False,
            "Team collaboration": True,
            "Role-based access control": True,
            "Compliance reporting": False,
            "Metrics and KPIs": False,
            "Notification system": True
        }
    },
    "owasp-dependency-check": {
        "description": "Software composition analysis tool",
        "license": "Open Source",
        "primary_language": "Java",
        "website": "https://owasp.org/www-project-dependency-check/",
        "features": {
            # Vulnerability Detection
            "npm dependencies": True,
            "PyPI dependencies": True,
            "Maven dependencies": True,
            "Gem dependencies": False,
            "Go dependencies": False,
            "Transitive dependencies": True,
            "CVE database integration": True,
            "GitHub advisories integration": False,
            "Custom vulnerability rules": True,
            
            # SBOM Generation
            "CycloneDX format": True,
            "SPDX format": False,
            "JSON output": True,
            "XML output": True,
            "PDF report": False,
            "License information": True,
            "Package URL (PURL) support": True,
            "Component evidence": True,
            
            # Scanning Capabilities
            "Command-line interface": True,
            "Programmatic API": True,
            "Local scanning": True,
            "CI/CD integration": True,
            "IDE plugins": False,
            "Docker container scanning": True,
            "Offline scanning": True,
            
            # Remediation
            "Vulnerability details": True,
            "Fix recommendations": False,
            "Automatic PR generation": False,
            "Severity classification": True,
            "Exploit likelihood": False,
            "Affected component paths": True,
            "Prioritization guidance": False,
            
            # Usability & Integration
            "Custom policies": True,
            "Ignore patterns": True,
            "Configuration file": True,
            "Output customization": True,
            "GitHub integration": False,
            "GitLab integration": False,
            "Jenkins integration": True,
            "REST API": False,
            "Multi-language support": True,
            
            # Reporting & Management
            "Historical vulnerability tracking": False,
            "Centralized dashboard": False,
            "Custom reports": False,
            "Team collaboration": False,
            "Role-based access control": False,
            "Compliance reporting": True,
            "Metrics and KPIs": False,
            "Notification system": False
        }
    },
    "npm-audit": {
        "description": "Built-in npm security scanner",
        "license": "Free",
        "primary_language": "JavaScript",
        "website": "https://docs.npmjs.com/cli/v8/commands/npm-audit",
        "features": {
            # Vulnerability Detection
            "npm dependencies": True,
            "PyPI dependencies": False,
            "Maven dependencies": False,
            "Gem dependencies": False,
            "Go dependencies": False,
            "Transitive dependencies": True,
            "CVE database integration": True,
            "GitHub advisories integration": True,
            "Custom vulnerability rules": False,
            
            # SBOM Generation
            "CycloneDX format": False,
            "SPDX format": False,
            "JSON output": True,
            "XML output": False,
            "PDF report": False,
            "License information": False,
            "Package URL (PURL) support": False,
            "Component evidence": False,
            
            # Scanning Capabilities
            "Command-line interface": True,
            "Programmatic API": True,
            "Local scanning": True,
            "CI/CD integration": True,
            "IDE plugins": False,
            "Docker container scanning": False,
            "Offline scanning": False,
            
            # Remediation
            "Vulnerability details": True,
            "Fix recommendations": True,
            "Automatic PR generation": False,
            "Severity classification": True,
            "Exploit likelihood": False,
            "Affected component paths": True,
            "Prioritization guidance": False,
            
            # Usability & Integration
            "Custom policies": False,
            "Ignore patterns": True,
            "Configuration file": False,
            "Output customization": True,
            "GitHub integration": False,
            "GitLab integration": False,
            "Jenkins integration": False,
            "REST API": False,
            "Multi-language support": False,
            
            # Reporting & Management
            "Historical vulnerability tracking": False,
            "Centralized dashboard": False,
            "Custom reports": False,
            "Team collaboration": False,
            "Role-based access control": False,
            "Compliance reporting": False,
            "Metrics and KPIs": False,
            "Notification system": False
        }
    },
    "safety": {
        "description": "Python vulnerability scanner",
        "license": "Open Source / Commercial",
        "primary_language": "Python",
        "website": "https://pyup.io/safety/",
        "features": {
            # Vulnerability Detection
            "npm dependencies": False,
            "PyPI dependencies": True,
            "Maven dependencies": False,
            "Gem dependencies": False,
            "Go dependencies": False,
            "Transitive dependencies": True,
            "CVE database integration": True,
            "GitHub advisories integration": False,
            "Custom vulnerability rules": False,
            
            # SBOM Generation
            "CycloneDX format": False,
            "SPDX format": False,
            "JSON output": True,
            "XML output": False,
            "PDF report": False,
            "License information": False,
            "Package URL (PURL) support": False,
            "Component evidence": False,
            
            # Scanning Capabilities
            "Command-line interface": True,
            "Programmatic API": True,
            "Local scanning": True,
            "CI/CD integration": True,
            "IDE plugins": False,
            "Docker container scanning": False,
            "Offline scanning": True,
            
            # Remediation
            "Vulnerability details": True,
            "Fix recommendations": True,
            "Automatic PR generation": False,
            "Severity classification": True,
            "Exploit likelihood": False,
            "Affected component paths": False,
            "Prioritization guidance": False,
            
            # Usability & Integration
            "Custom policies": False,
            "Ignore patterns": True,
            "Configuration file": False,
            "Output customization": True,
            "GitHub integration": False,
            "GitLab integration": False,
            "Jenkins integration": False,
            "REST API": False,
            "Multi-language support": False,
            
            # Reporting & Management
            "Historical vulnerability tracking": False,
            "Centralized dashboard": True,
            "Custom reports": False,
            "Team collaboration": False,
            "Role-based access control": False,
            "Compliance reporting": False,
            "Metrics and KPIs": False,
            "Notification system": False
        }
    }
}


def create_feature_matrix(tools: List[str], feature_data: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    """
    Create a feature comparison matrix.
    
    Args:
        tools: List of tool IDs to include in the matrix.
        feature_data: Feature data for each tool.
        
    Returns:
        DataFrame with feature comparison matrix.
    """
    # Create a list of all features from FEATURE_CATEGORIES
    all_features = []
    for category, features in FEATURE_CATEGORIES.items():
        for feature in features:
            all_features.append((category, feature))
    
    # Create an empty DataFrame with tools as columns and features as rows
    matrix_data = []
    for category, feature in all_features:
        row_data = {"Category": category, "Feature": feature}
        
        for tool_id in tools:
            if tool_id in feature_data:
                # Get feature value (default to False if not found)
                has_feature = feature_data[tool_id]["features"].get(feature, False)
                row_data[tool_id] = has_feature
            else:
                row_data[tool_id] = False
        
        matrix_data.append(row_data)
    
    # Create DataFrame
    matrix_df = pd.DataFrame(matrix_data)
    
    return matrix_df


def calculate_feature_coverage(matrix_df: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
    """
    Calculate feature coverage metrics for each tool.
    
    Args:
        matrix_df: Feature matrix DataFrame.
        
    Returns:
        Dictionary with coverage metrics.
    """
    # Get tool columns (excluding Category and Feature)
    tool_columns = [col for col in matrix_df.columns if col not in ["Category", "Feature"]]
    
    # Get total feature count
    total_features = len(matrix_df)
    
    # Calculate coverage for each tool
    coverage = {}
    for tool in tool_columns:
        # Count features supported by this tool
        supported_features = matrix_df[tool].sum()
        coverage_pct = (supported_features / total_features) * 100
        
        # Calculate coverage by category
        category_coverage = {}
        for category in matrix_df["Category"].unique():
            category_df = matrix_df[matrix_df["Category"] == category]
            category_total = len(category_df)
            category_supported = category_df[tool].sum()
            category_coverage[category] = {
                "supported": int(category_supported),
                "total": category_total,
                "percentage": (category_supported / category_total) * 100 if category_total > 0 else 0
            }
        
        coverage[tool] = {
            "supported_features": int(supported_features),
            "total_features": total_features,
            "coverage_percentage": coverage_pct,
            "category_coverage": category_coverage
        }
    
    return coverage


def compare_with_ossv_scanner(matrix_df: pd.DataFrame) -> Dict[str, Dict[str, List[str]]]:
    """
    Compare each tool with ossv-scanner to identify unique features.
    
    Args:
        matrix_df: Feature matrix DataFrame.
        
    Returns:
        Dictionary with comparison results.
    """
    # Get tool columns (excluding Category and Feature)
    tool_columns = [col for col in matrix_df.columns if col not in ["Category", "Feature"]]
    
    # Compare each tool with ossv-scanner
    comparison = {}
    
    # Ensure ossv-scanner is in the matrix
    if "ossv-scanner" not in tool_columns:
        return comparison
    
    for tool in tool_columns:
        if tool == "ossv-scanner":
            continue
        
        # Features unique to ossv-scanner (ossv-scanner has, tool doesn't)
        ossv_unique = matrix_df[(matrix_df["ossv-scanner"] == True) & (matrix_df[tool] == False)]
        ossv_unique_features = []
        for _, row in ossv_unique.iterrows():
            ossv_unique_features.append(f"{row['Feature']} ({row['Category']})")
        
        # Features unique to the other tool (tool has, ossv-scanner doesn't)
        tool_unique = matrix_df[(matrix_df["ossv-scanner"] == False) & (matrix_df[tool] == True)]
        tool_unique_features = []
        for _, row in tool_unique.iterrows():
            tool_unique_features.append(f"{row['Feature']} ({row['Category']})")
        
        # Features both tools have
        common = matrix_df[(matrix_df["ossv-scanner"] == True) & (matrix_df[tool] == True)]
        common_features = []
        for _, row in common.iterrows():
            common_features.append(f"{row['Feature']} ({row['Category']})")
        
        comparison[tool] = {
            "ossv_scanner_unique": ossv_unique_features,
            "tool_unique": tool_unique_features,
            "common": common_features
        }
    
    return comparison


def generate_feature_matrix_plots(
    matrix_df: pd.DataFrame, 
    coverage: Dict[str, Dict[str, Any]], 
    output_dir: Path
) -> Dict[str, Path]:
    """
    Generate visualization plots for feature matrix.
    
    Args:
        matrix_df: Feature matrix DataFrame.
        coverage: Feature coverage metrics.
        output_dir: Directory to save plots.
        
    Returns:
        Dictionary mapping plot names to file paths.
    """
    output_dir.mkdir(exist_ok=True)
    plots = {}
    
    # Set plot style
    sns.set(style="whitegrid")
    
    # Get tool columns
    tool_columns = [col for col in matrix_df.columns if col not in ["Category", "Feature"]]
    
    # 1. Overall Feature Coverage
    plt.figure(figsize=(12, 6))
    
    # Prepare data
    tools = list(coverage.keys())
    coverage_pct = [coverage[tool]["coverage_percentage"] for tool in tools]
    
    # Sort by coverage percentage
    sorted_indices = np.argsort(coverage_pct)[::-1]  # Descending order
    sorted_tools = [tools[i] for i in sorted_indices]
    sorted_coverage = [coverage_pct[i] for i in sorted_indices]
    
    # Create bar chart
    plt.bar(sorted_tools, sorted_coverage, color='skyblue')
    plt.axhline(y=50, color='r', linestyle='--', alpha=0.3)
    
    # Add value labels
    for i, v in enumerate(sorted_coverage):
        plt.text(i, v + 1, f"{v:.1f}%", ha='center')
    
    # Add labels
    plt.title("Overall Feature Coverage")
    plt.xlabel("Tool")
    plt.ylabel("Coverage Percentage")
    plt.ylim(0, 105)  # Leave room for labels
    
    # Rotate x-axis labels
    plt.xticks(rotation=45, ha='right')
    
    plt.tight_layout()
    
    coverage_plot_path = output_dir / "overall_coverage.png"
    plt.savefig(coverage_plot_path)
    plt.close()
    plots["overall_coverage"] = coverage_plot_path
    
    # 2. Feature Coverage by Category
    plt.figure(figsize=(14, 10))
    
    # Prepare data
    categories = list(FEATURE_CATEGORIES.keys())
    tools = list(coverage.keys())
    
    # Create data for stacked bar chart
    category_coverage_data = {}
    for tool in tools:
        category_coverage_data[tool] = [coverage[tool]["category_coverage"][cat]["percentage"] for cat in categories]
    
    # Create stacked bar chart
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Use a different color for each category
    colors = plt.cm.viridis(np.linspace(0, 1, len(categories)))
    
    # Create bars for each tool
    x = np.arange(len(tools))
    width = 0.7
    
    for i, category in enumerate(categories):
        bottom = np.zeros(len(tools))
        for j, tool in enumerate(tools):
            if i > 0:
                bottom[j] = sum(category_coverage_data[tool][k] for k in range(i))
        
        plt.bar(x, [category_coverage_data[tool][i] for tool in tools], width, bottom=bottom, 
                label=category, color=colors[i])
    
    # Add labels
    plt.title("Feature Coverage by Category")
    plt.xlabel("Tool")
    plt.ylabel("Coverage Percentage")
    plt.xticks(x, tools, rotation=45, ha='right')
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), ncol=3)
    
    plt.tight_layout()
    
    category_plot_path = output_dir / "category_coverage.png"
    plt.savefig(category_plot_path)
    plt.close()
    plots["category_coverage"] = category_plot_path
    
    # 3. Heatmap of Feature Support
    plt.figure(figsize=(14, 20))
    
    # Prepare data
    # Create a pivot table for easier heatmap creation
    pivot_df = matrix_df.pivot_table(
        index=["Category", "Feature"], 
        columns=matrix_df.columns[2:],  # Skip Category and Feature columns
        values=matrix_df.columns[2:],   # Use the same columns for values
        aggfunc='first'                 # Just take the first value
    )
    
    # Sort by category and feature
    pivot_df = pivot_df.sort_index()
    
    # Create heatmap
    plt.figure(figsize=(len(tool_columns) * 1.5 + 2, len(pivot_df) * 0.4 + 2))
    
    # Create the heatmap
    ax = sns.heatmap(pivot_df, cmap=["white", "forestgreen"], linewidths=0.5, linecolor='gray',
                    cbar=False, annot=False)
    
    # Reformat axis labels
    plt.yticks(rotation=0)
    plt.xticks(rotation=45, ha='right')
    
    # Add title
    plt.title("Feature Support Comparison")
    
    # Add category separators and labels
    current_category = None
    y_pos = 0
    
    for (category, feature) in pivot_df.index:
        if category != current_category:
            if current_category is not None:
                plt.axhline(y=y_pos, color='black', linewidth=2)
            current_category = category
            plt.text(-0.5, y_pos + 0.5, category, fontsize=12, fontweight='bold',
                    ha='right', va='center')
        y_pos += 1
    
    # Create custom legend
    legend_elements = [
        Patch(facecolor='forestgreen', label='Supported'),
        Patch(facecolor='white', edgecolor='gray', label='Not Supported')
    ]
    plt.legend(handles=legend_elements, loc='upper right')
    
    plt.tight_layout()
    
    heatmap_path = output_dir / "feature_heatmap.png"
    plt.savefig(heatmap_path)
    plt.close()
    plots["feature_heatmap"] = heatmap_path
    
    # 4. Radar chart comparing ossv-scanner with other tools
    if "ossv-scanner" in tool_columns:
        # Create a radar chart for each category
        for category in FEATURE_CATEGORIES:
            # Filter features for this category
            category_df = matrix_df[matrix_df["Category"] == category]
            features = category_df["Feature"].tolist()
            
            # Count how many tools we're comparing
            other_tools = [t for t in tool_columns if t != "ossv-scanner"]
            
            # Skip if there are no features in this category
            if len(features) == 0 or len(other_tools) == 0:
                continue
            
            # Create radar chart
            fig = plt.figure(figsize=(10, 8))
            ax = fig.add_subplot(111, polar=True)
            
            # Number of features
            N = len(features)
            
            # Compute angle for each feature
            angles = [n / float(N) * 2 * np.pi for n in range(N)]
            angles += angles[:1]  # Close the loop
            
            # Add ossv-scanner
            ossv_values = [1 if category_df.loc[category_df["Feature"] == feature, "ossv-scanner"].values[0] else 0 for feature in features]
            ossv_values += ossv_values[:1]  # Close the loop
            ax.plot(angles, ossv_values, linewidth=2, linestyle='solid', label="ossv-scanner")
            ax.fill(angles, ossv_values, alpha=0.1)
            
            # Add other tools
            for tool in other_tools:
                values = [1 if category_df.loc[category_df["Feature"] == feature, tool].values[0] else 0 for feature in features]
                values += values[:1]  # Close the loop
                ax.plot(angles, values, linewidth=2, linestyle='solid', label=tool)
                ax.fill(angles, values, alpha=0.1)
            
            # Set feature labels
            ax.set_xticks(angles[:-1])
            ax.set_xticklabels(features, fontsize=8)
            
            # Configure y axis
            ax.set_yticks([0, 1])
            ax.set_yticklabels(["No", "Yes"])
            ax.set_ylim(0, 1)
            
            # Add legend and title
            plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
            plt.title(f"{category} Feature Comparison")
            
            plt.tight_layout()
            
            radar_path = output_dir / f"radar_{category.lower().replace(' ', '_')}.png"
            plt.savefig(radar_path)
            plt.close()
            plots[f"radar_{category.lower().replace(' ', '_')}"] = radar_path
    
    # 5. Bar chart showing unique features
    if "ossv-scanner" in tool_columns:
        # Get tools to compare with ossv-scanner
        other_tools = [t for t in tool_columns if t != "ossv-scanner"]
        
        # Count ossv-scanner unique features by category
        ossv_unique_by_category = {}
        for category in FEATURE_CATEGORIES:
            ossv_unique_count = 0
            
            # Filter for this category
            category_df = matrix_df[matrix_df["Category"] == category]
            
            # Count features where ossv-scanner has but others don't
            for _, row in category_df.iterrows():
                if row["ossv-scanner"] and not any(row[tool] for tool in other_tools):
                    ossv_unique_count += 1
            
            ossv_unique_by_category[category] = ossv_unique_count
        
        # Create bar chart
        plt.figure(figsize=(12, 6))
        
        # Plot bars
        categories = list(ossv_unique_by_category.keys())
        counts = [ossv_unique_by_category[cat] for cat in categories]
        
        plt.bar(categories, counts, color='lightblue')
        
        # Add value labels
        for i, v in enumerate(counts):
            if v > 0:
                plt.text(i, v + 0.1, str(v), ha='center')
        
        # Add labels
        plt.title("Unique Features in ossv-scanner")
        plt.xlabel("Feature Category")
        plt.ylabel("Count of Unique Features")
        
        # Rotate x-axis labels
        plt.xticks(rotation=45, ha='right')
        
        plt.tight_layout()
        
        unique_features_path = output_dir / "ossv_unique_features.png"
        plt.savefig(unique_features_path)
        plt.close()
        plots["ossv_unique_features"] = unique_features_path
    
    return plots


def generate_matrix(tools: List[str] = None, custom_feature_data: Dict[str, Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Generate a feature comparison matrix.
    
    Args:
        tools: List of tool IDs to include in the matrix. If None, all tools will be included.
        custom_feature_data: Custom feature data to override defaults.
        
    Returns:
        Dictionary with feature matrix and analysis.
    """
    logger.info("Starting feature matrix generation")
    
    # Prepare output directory
    output_dir = Path(tempfile.mkdtemp(prefix="ossv-feature-matrix-"))
    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Merge custom feature data with defaults
    feature_data = DEFAULT_FEATURE_DATA.copy()
    if custom_feature_data:
        feature_data.update(custom_feature_data)
    
    # Select tools to include
    if not tools:
        tools = list(feature_data.keys())
    else:
        # Filter to only include tools with known feature data
        tools = [t for t in tools if t in feature_data]
    
    # Ensure ossv-scanner is first in the list if present
    if "ossv-scanner" in tools:
        tools.remove("ossv-scanner")
        tools.insert(0, "ossv-scanner")
    
    # Create feature matrix
    matrix_df = create_feature_matrix(tools, feature_data)
    
    # Calculate feature coverage metrics
    coverage = calculate_feature_coverage(matrix_df)
    
    # Compare tools with ossv-scanner
    comparison = compare_with_ossv_scanner(matrix_df)
    
    # Generate visualization plots
    plots = generate_feature_matrix_plots(matrix_df, coverage, plots_dir)
    
    # Create feature matrix output
    matrix_output = {
        "tools": {tool: feature_data[tool] for tool in tools},
        "feature_matrix": matrix_df.to_dict(orient="records"),
        "feature_coverage": coverage,
        "comparison_with_ossv": comparison,
        "plots": {name: str(path) for name, path in plots.items()},
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tools_compared": tools
        }
    }
    
    # Display summary
    display_feature_matrix_summary(matrix_df, coverage, comparison)
    
    logger.info("Feature matrix generation completed")
    return matrix_output


def display_feature_matrix_summary(
    matrix_df: pd.DataFrame, 
    coverage: Dict[str, Dict[str, Any]], 
    comparison: Dict[str, Dict[str, List[str]]]
) -> None:
    """
    Display a summary of the feature matrix.
    
    Args:
        matrix_df: Feature matrix DataFrame.
        coverage: Feature coverage metrics.
        comparison: Comparison with ossv-scanner.
    """
    console.print("\n[bold cyan]Feature Matrix Summary[/]")
    
    # Get tool columns
    tool_columns = [col for col in matrix_df.columns if col not in ["Category", "Feature"]]
    
    # Create coverage table
    coverage_table = Table(title="Feature Coverage")
    coverage_table.add_column("Tool", style="cyan")
    coverage_table.add_column("Supported Features", style="green")
    coverage_table.add_column("Total Features", style="blue")
    coverage_table.add_column("Coverage", style="yellow")
    
    # Sort tools by coverage percentage
    sorted_tools = sorted(tool_columns, key=lambda t: coverage[t]["coverage_percentage"], reverse=True)
    
    for tool in sorted_tools:
        cov = coverage[tool]
        coverage_table.add_row(
            tool,
            str(cov["supported_features"]),
            str(cov["total_features"]),
            f"{cov['coverage_percentage']:.1f}%"
        )
    
    console.print(coverage_table)
    
    # Create category coverage table
    category_table = Table(title="Coverage by Category")
    category_table.add_column("Category", style="cyan")
    
    for tool in sorted_tools:
        category_table.add_column(tool, style="green")
    
    for category in FEATURE_CATEGORIES:
        row = [category]
        for tool in sorted_tools:
            cat_cov = coverage[tool]["category_coverage"][category]
            row.append(f"{cat_cov['percentage']:.1f}% ({cat_cov['supported']}/{cat_cov['total']})")
        
        category_table.add_row(*row)
    
    console.print(category_table)
    
    # Display ossv-scanner comparison if available
    if "ossv-scanner" in tool_columns and comparison:
        console.print("\n[bold cyan]Comparison with ossv-scanner[/]")
        
        for tool, comp in comparison.items():
            console.print(f"[bold]{tool} vs. ossv-scanner:[/]")
            
            console.print(f"[green]Features unique to ossv-scanner: {len(comp['ossv_scanner_unique'])}[/]")
            if comp['ossv_scanner_unique']:
                for feature in comp['ossv_scanner_unique'][:5]:  # Show top 5
                    console.print(f"  ✓ {feature}")
                if len(comp['ossv_scanner_unique']) > 5:
                    console.print(f"  ... and {len(comp['ossv_scanner_unique']) - 5} more")
            
            console.print(f"[yellow]Features unique to {tool}: {len(comp['tool_unique'])}[/]")
            if comp['tool_unique']:
                for feature in comp['tool_unique'][:5]:  # Show top 5
                    console.print(f"  ✓ {feature}")
                if len(comp['tool_unique']) > 5:
                    console.print(f"  ... and {len(comp['tool_unique']) - 5} more")
            
            console.print(f"[blue]Common features: {len(comp['common'])}[/]")
            console.print("")
    
    # Display overall assessment
    console.print("\n[bold cyan]Overall Assessment:[/]")
    
    if "ossv-scanner" in coverage:
        ossv_coverage = coverage["ossv-scanner"]["coverage_percentage"]
        
        # Find top commercial tool
        commercial_tools = [t for t in coverage if t != "ossv-scanner" and feature_data[t]["license"] == "Commercial"]
        if commercial_tools:
            top_commercial = max(commercial_tools, key=lambda t: coverage[t]["coverage_percentage"])
            commercial_coverage = coverage[top_commercial]["coverage_percentage"]
            
            coverage_diff = ossv_coverage - commercial_coverage
            
            if coverage_diff > 0:
                console.print(f"[green]ossv-scanner has {ossv_coverage:.1f}% feature coverage, which is {abs(coverage_diff):.1f}% more than {top_commercial}.[/]")
            else:
                console.print(f"[yellow]ossv-scanner has {ossv_coverage:.1f}% feature coverage, which is {abs(coverage_diff):.1f}% less than {top_commercial}.[/]")
        
        # Identify strengths and weaknesses
        strengths = []
        weaknesses = []
        
        for category in FEATURE_CATEGORIES:
            cat_cov = coverage["ossv-scanner"]["category_coverage"][category]
            if cat_cov["percentage"] >= 75:
                strengths.append(category)
            elif cat_cov["percentage"] <= 25:
                weaknesses.append(category)
        
        if strengths:
            console.print(f"[green]Strengths: {', '.join(strengths)}[/]")
        
        if weaknesses:
            console.print(f"[yellow]Areas for improvement: {', '.join(weaknesses)}[/]")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = generate_matrix()
    print("Feature matrix generation completed")
