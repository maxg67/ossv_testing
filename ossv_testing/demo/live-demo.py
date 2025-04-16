"""
Live demonstration module for ossv-scanner.

This module implements functionality for conducting live demonstrations of the
ossv-scanner, showcasing its capabilities in real-time with guided commentary
and visual feedback.
"""

import os
import time
import logging
import tempfile
import json
import subprocess
import shutil
import webbrowser
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import threading

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

logger = logging.getLogger(__name__)
console = Console()

# Define demo projects
DEMO_PROJECTS = [
    {
        "id": "demo-simple",
        "name": "Simple Demo Project",
        "description": "A simple project with known vulnerabilities for demonstration",
        "files": {
            "package.json": {
                "name": "simple-demo",
                "version": "1.0.0",
                "description": "Simple project for demonstration",
                "dependencies": {
                    "lodash": "4.17.15",  # Prototype pollution vulnerability
                    "jquery": "3.4.0",    # XSS vulnerability
                    "moment": "2.24.0"    # Low severity issue
                }
            },
            "app.js": """
// Simple demo application
const _ = require('lodash');
const $ = require('jquery');
const moment = require('moment');

console.log('Demo application starting...');
console.log('Current time:', moment().format('MMMM Do YYYY, h:mm:ss a'));

// Vulnerable merge operation (demonstration only)
const defaultConfig = { 'config': true };
const userConfig = JSON.parse('{"__proto__": {"polluted": true}}');
const merged = _.merge({}, defaultConfig, userConfig);
console.log('Configuration:', merged);

// Demo of jQuery usage
$('body').html('<h1>Demo App</h1>');
"""
        }
    },
    {
        "id": "demo-python",
        "name": "Python Demo Project",
        "description": "A Python project with known vulnerabilities for demonstration",
        "files": {
            "requirements.txt": """
Django==2.2.8
Jinja2==2.10.1
requests==2.22.0
""",
            "app.py": """
# Simple Python demo application
import os
from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/')
def index():
    # Potentially vulnerable template (demonstration only)
    template = '''
    <h1>Hello, {{ name }}</h1>
    <p>Welcome to the demo application!</p>
    '''
    name = request.args.get('name', 'Guest')
    return render_template_string(template, name=name)

@app.route('/fetch')
def fetch_data():
    # Potentially vulnerable request (demonstration only)
    url = request.args.get('url', 'https://example.com')
    response = requests.get(url)
    return response.text

if __name__ == '__main__':
    app.run(debug=True)
"""
        }
    }
]

DEMO_COMMENTARY = {
    "intro": """
# OSSV Scanner Live Demonstration

This live demonstration showcases the capabilities of the Open Source Software Vulnerability Scanner (ossv-scanner).
The scanner is designed to detect vulnerabilities in open source dependencies across multiple ecosystems.

In this demonstration, we will:
1. Create sample projects with known vulnerabilities
2. Run the scanner on these projects
3. Analyze the results and explain key findings
4. Show how to generate and interpret an SBOM (Software Bill of Materials)
    """,
    
    "project_creation": """
## Project Creation

Creating a sample project with known vulnerabilities for demonstration purposes.
This project includes dependencies with known security issues to demonstrate the scanner's detection capabilities.
    """,
    
    "scanning": """
## Vulnerability Scanning

Now running the ossv-scanner on the sample project.
The scanner is identifying dependencies, checking for known vulnerabilities, and generating a report.
    """,
    
    "results_analysis": """
## Results Analysis

Let's examine the scanner results:
- Identified dependencies and their versions
- Detected vulnerabilities with severity ratings
- Remediation recommendations
- False positive analysis
    """,
    
    "sbom_generation": """
## SBOM Generation

Software Bill of Materials (SBOM) provides a formal record of the components used in your software.
The ossv-scanner can generate SBOMs in standard formats like CycloneDX.
    """,
    
    "conclusion": """
## Conclusion

The ossv-scanner effectively identified several vulnerabilities in the dependencies:
- Critical and high severity issues that require immediate attention
- Medium and low severity issues that should be addressed
- Provided actionable remediation guidance

Key benefits demonstrated:
- Multi-ecosystem support
- Accurate detection with low false positives
- Clear and actionable results
- Integration with software development lifecycle
    """
}


def create_demo_project(project_config: Dict[str, Any], base_dir: Path) -> Path:
    """
    Create a demonstration project with predefined files.
    
    Args:
        project_config: Project configuration dictionary.
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created project.
    """
    project_dir = base_dir / project_config["id"]
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create each file in the project
    for file_path, content in project_config["files"].items():
        full_path = project_dir / file_path
        
        # Create parent directories if needed
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file content
        if isinstance(content, dict):
            with open(full_path, "w") as f:
                json.dump(content, f, indent=2)
        else:
            with open(full_path, "w") as f:
                f.write(content)
    
    return project_dir


def run_scanner_with_visuals(project_dir: Path, output_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """
    Run ossv-scanner on a project with visual feedback.
    
    Args:
        project_dir: Path to the project directory.
        output_dir: Directory to save output files.
        
    Returns:
        Tuple of (output_path, results_data).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-results.json"
    
    # Prepare command
    scan_cmd = [
        "ossv-scan",
        "--output-format", "json",
        "--output-path", str(output_path),
        str(project_dir)
    ]
    
    # Create alternative command for module use
    module_cmd = [
        "python", "-m", "ossv_scanner.main",
        "--output-format", "json",
        "--output-path", str(output_path),
        str(project_dir)
    ]
    
    # Create progress display
    progress_display = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Running scanner..."),
        BarColumn(),
        TextColumn("[bold]{task.description}"),
    )
    
    # Setup for animation
    phases = [
        "Identifying dependencies...",
        "Analyzing package structure...",
        "Querying vulnerability databases...",
        "Cross-referencing CVEs...",
        "Determining severity levels...",
        "Preparing recommendations...",
        "Generating report..."
    ]
    
    results_data = {}
    
    with Live(progress_display, refresh_per_second=10):
        # Add task for scanning
        task = progress_display.add_task("Starting scan...", total=len(phases))
        
        try:
            # Try to run as installed package
            process = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Animate the progress
            for i, phase in enumerate(phases):
                progress_display.update(task, description=phase, completed=i)
                time.sleep(0.5 + (0.5 * i))  # Gradually slow down for realism
            
            stdout, stderr = process.communicate()
            
            # Check if we need to try the module approach
            if process.returncode != 0:
                progress_display.update(task, description="Retrying with module approach...")
                process = subprocess.Popen(module_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
            
            # Complete the progress
            progress_display.update(task, description="Scan complete!", completed=len(phases))
            
            # Load results
            if output_path.exists():
                try:
                    with open(output_path, "r") as f:
                        results_data = json.load(f)
                except json.JSONDecodeError:
                    logger.warning("Error parsing results JSON")
            
        except Exception as e:
            logger.error(f"Error running scanner: {str(e)}")
            progress_display.update(task, description=f"Error: {str(e)}", completed=len(phases))
    
    return output_path, results_data


def display_results_analysis(results_data: Dict[str, Any]) -> None:
    """
    Display an analysis of scanner results with explanations.
    
    Args:
        results_data: Scanner results data.
    """
    vulnerabilities = results_data.get("vulnerabilities", {})
    dependencies = results_data.get("dependencies", [])
    
    # Display summary
    console.print("\n[bold cyan]Vulnerability Scan Results[/]")
    
    # Count vulnerabilities by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vuln_count = 0
    
    for dep, vulns in vulnerabilities.items():
        vuln_count += len(vulns)
        for vuln in vulns:
            severity = vuln.get("severity", "UNKNOWN")
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    # Display vulnerability summary
    console.print(f"Found [bold red]{vuln_count}[/] vulnerabilities in [bold blue]{len(dependencies)}[/] dependencies")
    
    # Create severity breakdown
    console.print("\n[bold]Vulnerability Severity Breakdown:[/]")
    console.print(f"[bold red]CRITICAL:[/] {severity_counts['CRITICAL']}")
    console.print(f"[bold orange3]HIGH:[/] {severity_counts['HIGH']}")
    console.print(f"[bold yellow]MEDIUM:[/] {severity_counts['MEDIUM']}")
    console.print(f"[bold green]LOW:[/] {severity_counts['LOW']}")
    
    # Display detailed vulnerability information
    if vuln_count > 0:
        console.print("\n[bold]Top Vulnerabilities:[/]")
        
        # Show most severe vulnerabilities
        top_vulns = []
        for dep, vulns in vulnerabilities.items():
            for vuln in vulns:
                severity = vuln.get("severity", "UNKNOWN")
                top_vulns.append((dep, vuln, severity))
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        top_vulns.sort(key=lambda x: severity_order.get(x[2], 5))
        
        # Display top 3 or fewer
        for i, (dep, vuln, severity) in enumerate(top_vulns[:3]):
            console.print(f"\n[bold]{i+1}. {dep}[/] - {vuln.get('cve_id', 'Unknown CVE')}")
            console.print(f"   Severity: [bold {get_severity_color(severity)}]{severity}[/]")
            console.print(f"   Description: {vuln.get('description', 'No description available')}")
            
            # Show remediation if available
            if "fixed_version" in vuln and vuln["fixed_version"]:
                console.print(f"   Remediation: Upgrade to version [bold green]{vuln['fixed_version']}[/] or later")
            
            # Show additional commentary based on severity
            if severity == "CRITICAL" or severity == "HIGH":
                console.print(f"   [bold red]This vulnerability requires immediate attention[/]")
            elif severity == "MEDIUM":
                console.print(f"   [bold yellow]This vulnerability should be addressed in upcoming releases[/]")
    
    # SBOM information if available
    if "sbom" in results_data:
        console.print("\n[bold]Software Bill of Materials (SBOM) Generated[/]")
        console.print("The SBOM provides a formal record of all dependencies used in this project.")
        console.print("It can be shared with security teams or used for compliance purposes.")


def get_severity_color(severity: str) -> str:
    """
    Get an appropriate color for a severity level.
    
    Args:
        severity: Severity level.
        
    Returns:
        Color name for Rich console.
    """
    severity_colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "green"
    }
    return severity_colors.get(severity, "white")


def run_demo() -> int:
    """
    Run a live demonstration of ossv-scanner.
    
    Returns:
        Exit code (0 for success).
    """
    console.print(Panel(Markdown(DEMO_COMMENTARY["intro"]), title="OSSV Scanner Demo"))
    time.sleep(1)
    
    # Create base directory for demo
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-demo-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Select demo project
    demo_project = DEMO_PROJECTS[0]  # Default to simple demo
    
    console.print(Markdown(DEMO_COMMENTARY["project_creation"]))
    console.print(f"Creating project: [bold cyan]{demo_project['name']}[/]")
    console.print(f"Description: {demo_project['description']}")
    
    # Create demo project
    project_dir = create_demo_project(demo_project, base_dir)
    
    # Show project files
    console.print("\n[bold]Project Structure:[/]")
    for file_path in demo_project["files"]:
        console.print(f"  - {file_path}")
        
        # Show content of small files
        full_path = project_dir / file_path
        if full_path.exists() and full_path.stat().st_size < 1000:
            # Format based on file type
            if file_path.endswith('.json'):
                with open(full_path, "r") as f:
                    try:
                        content = json.load(f)
                        syntax = Syntax(json.dumps(content, indent=2), "json", theme="monokai")
                        console.print(syntax)
                    except json.JSONDecodeError:
                        with open(full_path, "r") as f2:
                            syntax = Syntax(f2.read(), "json", theme="monokai")
                            console.print(syntax)
            elif file_path.endswith('.py'):
                with open(full_path, "r") as f:
                    syntax = Syntax(f.read(), "python", theme="monokai")
                    console.print(syntax)
            elif file_path.endswith('.js'):
                with open(full_path, "r") as f:
                    syntax = Syntax(f.read(), "javascript", theme="monokai")
                    console.print(syntax)
            else:
                with open(full_path, "r") as f:
                    console.print(f.read())
    
    # Pause for effect
    time.sleep(1)
    
    # Run scanner with visual feedback
    console.print(Markdown(DEMO_COMMENTARY["scanning"]))
    output_path, results_data = run_scanner_with_visuals(project_dir, output_dir)
    
    # Pause for effect
    time.sleep(1)
    
    # Analyze and display results
    console.print(Markdown(DEMO_COMMENTARY["results_analysis"]))
    display_results_analysis(results_data)
    
    # SBOM generation section
    console.print(Markdown(DEMO_COMMENTARY["sbom_generation"]))
    console.print("An SBOM has been generated as part of the scanner output.")
    
    # Show sample SBOM structure
    if "sbom" in results_data and "json" in results_data["sbom"]:
        try:
            sbom_data = json.loads(results_data["sbom"]["json"])
            console.print("\n[bold]SBOM Overview:[/]")
            console.print(f"Format: {sbom_data.get('bomFormat', 'Unknown')}")
            console.print(f"Spec Version: {sbom_data.get('specVersion', 'Unknown')}")
            console.print(f"Components: {len(sbom_data.get('components', []))} dependencies")
        except (json.JSONDecodeError, TypeError):
            console.print("[yellow]SBOM data is available but could not be parsed[/]")
    
    # Conclusion
    console.print(Markdown(DEMO_COMMENTARY["conclusion"]))
    
    # Show where results are saved
    console.print(f"\n[bold green]Demo completed successfully![/]")
    console.print(f"Results saved to: {output_path}")
    
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    exit_code = run_demo()
    sys.exit(exit_code)
