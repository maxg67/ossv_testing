"""
Interactive demo participation for ossv-scanner.

This module provides tools for interactive demonstrations of ossv-scanner,
allowing participants to actively engage with the scanner's capabilities.
"""

import os
import time
import logging
import tempfile
import json
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import questionary
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.progress import Progress

logger = logging.getLogger(__name__)
console = Console()

# Define interactive demo templates
DEMO_TEMPLATES = {
    "npm-basic": {
        "name": "Basic NPM Project",
        "description": "Simple NPM project with known vulnerabilities",
        "files": {
            "package.json": {
                "name": "interactive-demo",
                "version": "1.0.0",
                "description": "Interactive demo for ossv-scanner",
                "dependencies": {
                    "lodash": "4.17.15",  # CVE-2019-10744
                    "minimist": "1.2.0",  # CVE-2020-7598
                    "jquery": "3.4.0"     # CVE-2019-11358
                }
            }
        }
    },
    "python-basic": {
        "name": "Basic Python Project",
        "description": "Simple Python project with known vulnerabilities",
        "files": {
            "requirements.txt": "\n".join([
                "Django==2.2.8",  # CVE-2019-19844
                "Flask==0.12.2",  # CVE-2018-1000656
                "requests==2.20.0"  # CVE-2018-18074
            ])
        }
    },
    "mixed-basic": {
        "name": "Mixed Ecosystem Project",
        "description": "Project with multiple dependency ecosystems",
        "files": {
            "package.json": {
                "name": "interactive-mixed-demo",
                "version": "1.0.0",
                "description": "Interactive demo with multiple ecosystems",
                "dependencies": {
                    "lodash": "4.17.15",  # CVE-2019-10744
                    "jquery": "3.4.0"     # CVE-2019-11358
                }
            },
            "requirements.txt": "\n".join([
                "Django==2.2.8",  # CVE-2019-19844
                "Flask==0.12.2"   # CVE-2018-1000656
            ])
        }
    },
    "custom": {
        "name": "Custom Project",
        "description": "Create your own project to scan",
        "files": {}
    }
}

# Demo steps with explanations
DEMO_STEPS = [
    {
        "title": "Introduction",
        "description": """
This interactive demo will guide you through using ossv-scanner to detect 
vulnerabilities in open source dependencies. You'll see how the scanner works,
its capabilities, and how to interpret the results.
        """
    },
    {
        "title": "Project Selection",
        "description": """
Choose one of the provided project templates or create your own custom project.
Each template contains dependencies with known vulnerabilities to demonstrate
the scanner's detection capabilities.
        """
    },
    {
        "title": "Scanning",
        "description": """
We'll run ossv-scanner on the selected project to identify vulnerabilities
in its dependencies. The scanner analyzes dependency files like package.json
and requirements.txt to identify vulnerable packages.
        """
    },
    {
        "title": "Results Analysis",
        "description": """
Let's explore the scan results together. We'll look at:
- Detected vulnerabilities and their severity
- Affected dependencies and versions
- Recommended fixes
- SBOM (Software Bill of Materials) generation
        """
    },
    {
        "title": "Customization",
        "description": """
ossv-scanner offers various customization options:
- Output formats (JSON, XML, plain text)
- Filtering by severity
- Configurable reporting
- CI/CD integration
        """
    }
]


def create_demo_project(template_name: str, base_dir: Path) -> Path:
    """
    Create a demo project from a template.
    
    Args:
        template_name: Name of the template to use.
        base_dir: Base directory for the project.
        
    Returns:
        Path to the created project.
    """
    if template_name not in DEMO_TEMPLATES:
        raise ValueError(f"Unknown template: {template_name}")
    
    template = DEMO_TEMPLATES[template_name]
    
    # Create project directory
    project_dir = base_dir / template_name
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create files
    for file_path, content in template["files"].items():
        file_full_path = project_dir / file_path
        
        # Create parent directories if needed
        file_full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file content
        if isinstance(content, dict):
            with open(file_full_path, "w") as f:
                json.dump(content, f, indent=2)
        else:
            with open(file_full_path, "w") as f:
                f.write(content)
    
    return project_dir


def create_custom_project(base_dir: Path) -> Path:
    """
    Create a custom project based on user input.
    
    Args:
        base_dir: Base directory for the project.
        
    Returns:
        Path to the created project.
    """
    console.print(Panel.fit(
        "[bold]Custom Project Creation[/]\n\n"
        "Create your own project files for scanning. You can add dependencies "
        "with known vulnerabilities or use your own project files.",
        title="Custom Project"
    ))
    
    # Create project directory
    project_dir = base_dir / "custom-project"
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Ask which ecosystems to include
    ecosystems = questionary.checkbox(
        "Which dependency ecosystems would you like to include?",
        choices=[
            "NPM (JavaScript/Node.js)",
            "PyPI (Python)",
            "Maven (Java)",
            "Other/Custom Files"
        ]
    ).ask()
    
    # Process each selected ecosystem
    if "NPM (JavaScript/Node.js)" in ecosystems:
        create_npm_dependencies(project_dir)
    
    if "PyPI (Python)" in ecosystems:
        create_python_dependencies(project_dir)
    
    if "Maven (Java)" in ecosystems:
        create_maven_dependencies(project_dir)
    
    if "Other/Custom Files" in ecosystems:
        create_custom_files(project_dir)
    
    return project_dir


def create_npm_dependencies(project_dir: Path) -> None:
    """
    Create NPM dependencies based on user input.
    
    Args:
        project_dir: Project directory.
    """
    console.print("\n[bold cyan]NPM Dependencies[/]")
    
    # Sample vulnerable NPM packages
    vulnerable_packages = [
        {"name": "lodash", "version": "4.17.15", "vuln": "Prototype pollution (CVE-2019-10744)"},
        {"name": "jquery", "version": "3.4.0", "vuln": "Prototype pollution (CVE-2019-11358)"},
        {"name": "minimist", "version": "1.2.0", "vuln": "Prototype pollution (CVE-2020-7598)"},
        {"name": "express", "version": "4.17.1", "vuln": "Multiple vulnerabilities in dependencies"},
        {"name": "socket.io", "version": "2.3.0", "vuln": "ReDoS vulnerability (CVE-2020-28469)"}
    ]
    
    # Display available packages
    table = Table(title="Available Vulnerable NPM Packages")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Vulnerability", style="red")
    
    for pkg in vulnerable_packages:
        table.add_row(pkg["name"], pkg["version"], pkg["vuln"])
    
    console.print(table)
    
    # Ask which packages to include
    selected_packages = questionary.checkbox(
        "Select NPM packages to include:",
        choices=[f"{pkg['name']}@{pkg['version']}" for pkg in vulnerable_packages]
    ).ask()
    
    # Create package.json
    if selected_packages:
        pkg_json = {
            "name": "custom-npm-project",
            "version": "1.0.0",
            "description": "Custom NPM project for ossv-scanner demo",
            "dependencies": {}
        }
        
        for pkg_str in selected_packages:
            name, version = pkg_str.split("@")
            pkg_json["dependencies"][name] = version
        
        with open(project_dir / "package.json", "w") as f:
            json.dump(pkg_json, f, indent=2)
        
        console.print(f"[green]Created package.json with {len(selected_packages)} dependencies[/]")


def create_python_dependencies(project_dir: Path) -> None:
    """
    Create Python dependencies based on user input.
    
    Args:
        project_dir: Project directory.
    """
    console.print("\n[bold cyan]Python Dependencies[/]")
    
    # Sample vulnerable Python packages
    vulnerable_packages = [
        {"name": "Django", "version": "2.2.8", "vuln": "Account takeover (CVE-2019-19844)"},
        {"name": "Flask", "version": "0.12.2", "vuln": "Denial of service (CVE-2018-1000656)"},
        {"name": "Jinja2", "version": "2.10.1", "vuln": "Sandbox escape (CVE-2019-10906)"},
        {"name": "requests", "version": "2.20.0", "vuln": "CRLF injection (CVE-2018-18074)"},
        {"name": "urllib3", "version": "1.24.1", "vuln": "CRLF injection (CVE-2019-11236)"}
    ]
    
    # Display available packages
    table = Table(title="Available Vulnerable Python Packages")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Vulnerability", style="red")
    
    for pkg in vulnerable_packages:
        table.add_row(pkg["name"], pkg["version"], pkg["vuln"])
    
    console.print(table)
    
    # Ask which packages to include
    selected_packages = questionary.checkbox(
        "Select Python packages to include:",
        choices=[f"{pkg['name']}=={pkg['version']}" for pkg in vulnerable_packages]
    ).ask()
    
    # Create requirements.txt
    if selected_packages:
        with open(project_dir / "requirements.txt", "w") as f:
            f.write("\n".join(selected_packages))
        
        console.print(f"[green]Created requirements.txt with {len(selected_packages)} dependencies[/]")


def create_maven_dependencies(project_dir: Path) -> None:
    """
    Create Maven dependencies based on user input.
    
    Args:
        project_dir: Project directory.
    """
    console.print("\n[bold cyan]Maven Dependencies[/]")
    
    # Sample vulnerable Maven packages
    vulnerable_packages = [
        {"name": "org.springframework:spring-core", "version": "5.2.3.RELEASE", "vuln": "Remote code execution (CVE-2022-22965)"},
        {"name": "org.apache.struts:struts2-core", "version": "2.5.16", "vuln": "DoS vulnerability (CVE-2019-0233)"},
        {"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.8", "vuln": "Deserialization flaw (CVE-2019-12086)"},
        {"name": "org.apache.tomcat.embed:tomcat-embed-core", "version": "9.0.30", "vuln": "Session fixation (CVE-2020-9484)"},
        {"name": "org.apache.commons:commons-compress", "version": "1.19", "vuln": "Denial of service (CVE-2019-17195)"}
    ]
    
    # Display available packages
    table = Table(title="Available Vulnerable Maven Packages")
    table.add_column("Package", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Vulnerability", style="red")
    
    for pkg in vulnerable_packages:
        table.add_row(pkg["name"], pkg["version"], pkg["vuln"])
    
    console.print(table)
    
    # Ask which packages to include
    selected_packages = questionary.checkbox(
        "Select Maven packages to include:",
        choices=[f"{pkg['name']}:{pkg['version']}" for pkg in vulnerable_packages]
    ).ask()
    
    # Create pom.xml
    if selected_packages:
        pom_header = """<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>custom-maven-project</artifactId>
    <version>1.0.0</version>

    <dependencies>
"""
        
        pom_footer = """    </dependencies>
</project>"""
        
        dependencies = []
        for pkg_str in selected_packages:
            pkg_name, version = pkg_str.split(":")
            group_id, artifact_id = pkg_name.split(":")
            
            dependencies.append(f"""        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
            <version>{version}</version>
        </dependency>""")
        
        with open(project_dir / "pom.xml", "w") as f:
            f.write(pom_header + "\n".join(dependencies) + "\n" + pom_footer)
        
        console.print(f"[green]Created pom.xml with {len(selected_packages)} dependencies[/]")


def create_custom_files(project_dir: Path) -> None:
    """
    Create custom files based on user input.
    
    Args:
        project_dir: Project directory.
    """
    console.print("\n[bold cyan]Custom Files[/]")
    
    while True:
        # Ask for file name
        file_name = questionary.text("Enter file name (or leave empty to finish):").ask()
        
        if not file_name:
            break
        
        # Ask for file content
        content = questionary.text("Enter/paste file content:").ask()
        
        # Create the file
        file_path = project_dir / file_name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, "w") as f:
            f.write(content)
        
        console.print(f"[green]Created file: {file_name}[/]")
        
        # Ask if they want to add another file
        add_another = questionary.confirm("Add another file?").ask()
        if not add_another:
            break


def run_scanner(project_dir: Path, output_dir: Path) -> Path:
    """
    Run ossv-scanner on a project.
    
    Args:
        project_dir: Path to the project.
        output_dir: Directory to save scanner output.
        
    Returns:
        Path to the results file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_dir.name}-results.json"
    
    console.print(Panel.fit(
        "[bold]Scanning Project[/]\n\n"
        f"Project directory: {project_dir}\n"
        f"Output file: {output_path}",
        title="Scanner Execution"
    ))
    
    try:
        # Run the scanner
        with Progress() as progress:
            task = progress.add_task("[green]Running scanner...", total=100)
            
            scan_cmd = [
                "ossv-scan",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_dir)
            ]
            
            try:
                # Try to run as installed package
                progress.update(task, advance=30)
                process = subprocess.run(scan_cmd, check=True, capture_output=True)
                progress.update(task, advance=70)
            except (subprocess.SubprocessError, FileNotFoundError):
                # If that fails, try running as a module
                progress.update(task, advance=10)
                scan_cmd = [
                    "python", "-m", "ossv_scanner.main",
                    "--output-format", "json",
                    "--output-path", str(output_path),
                    str(project_dir)
                ]
                process = subprocess.run(scan_cmd, check=True, capture_output=True)
                progress.update(task, advance=90)
        
        console.print("[green]Scan completed successfully![/]")
        
    except Exception as e:
        console.print(f"[bold red]Error running scanner: {str(e)}[/]")
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
    
    return output_path


def explore_results(results_path: Path) -> None:
    """
    Interactive exploration of scan results.
    
    Args:
        results_path: Path to the results file.
    """
    try:
        # Load results
        with open(results_path, "r") as f:
            results = json.load(f)
        
        if "error" in results:
            console.print(f"[bold red]Error in scan results: {results['error']}[/]")
            return
        
        # Overview statistics
        vuln_count = sum(len(vulns) for vulns in results.get("vulnerabilities", {}).values())
        dep_count = len(results.get("dependencies", []))
        
        console.print(Panel.fit(
            f"[bold]Scan Results Overview[/]\n\n"
            f"Total dependencies: {dep_count}\n"
            f"Vulnerabilities found: {vuln_count}",
            title="Results Summary"
        ))
        
        # Display vulnerability details
        if vuln_count > 0:
            # Ask what to explore
            explore_option = questionary.select(
                "What would you like to explore?",
                choices=[
                    "Vulnerability details",
                    "Dependencies overview",
                    "SBOM information",
                    "View raw JSON results",
                    "Exit results exploration"
                ]
            ).ask()
            
            if explore_option == "Vulnerability details":
                show_vulnerability_details(results)
            elif explore_option == "Dependencies overview":
                show_dependencies_overview(results)
            elif explore_option == "SBOM information":
                show_sbom_info(results)
            elif explore_option == "View raw JSON results":
                show_raw_json(results)
        else:
            console.print("[green]No vulnerabilities found in the project![/]")
    
    except Exception as e:
        console.print(f"[bold red]Error exploring results: {str(e)}[/]")


def show_vulnerability_details(results: Dict[str, Any]) -> None:
    """
    Show detailed information about detected vulnerabilities.
    
    Args:
        results: Scan results.
    """
    vulnerabilities = results.get("vulnerabilities", {})
    if not vulnerabilities:
        console.print("[yellow]No vulnerability information available[/]")
        return
    
    # Create a list of all vulnerabilities
    all_vulns = []
    for dep_id, vulns in vulnerabilities.items():
        for vuln in vulns:
            all_vulns.append({
                "dependency": dep_id,
                "vuln_id": vuln.get("cve_id", "Unknown"),
                "severity": vuln.get("severity", "Unknown"),
                "description": vuln.get("description", "No description available"),
                "fixed_version": vuln.get("fixed_version", "Not specified"),
                "details": vuln
            })
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulns.sort(key=lambda v: severity_order.get(v["severity"], 5))
    
    # Display vulnerability table
    table = Table(title=f"Detected Vulnerabilities ({len(all_vulns)})")
    table.add_column("Dependency", style="cyan")
    table.add_column("Vulnerability ID", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Fixed Version", style="green")
    
    for vuln in all_vulns:
        # Set severity color
        severity_style = "red"
        if vuln["severity"] == "MEDIUM":
            severity_style = "yellow"
        elif vuln["severity"] == "LOW":
            severity_style = "green"
        
        table.add_row(
            vuln["dependency"],
            vuln["vuln_id"],
            f"[{severity_style}]{vuln['severity']}[/{severity_style}]",
            vuln["fixed_version"]
        )
    
    console.print(table)
    
    # Ask if user wants to see details for a specific vulnerability
    vuln_ids = [v["vuln_id"] for v in all_vulns]
    if len(vuln_ids) > 0:
        selected_vuln = questionary.select(
            "Select a vulnerability to see details:",
            choices=vuln_ids + ["Back to main menu"]
        ).ask()
        
        if selected_vuln != "Back to main menu":
            vuln = next((v for v in all_vulns if v["vuln_id"] == selected_vuln), None)
            if vuln:
                console.print(Panel.fit(
                    f"[bold]Vulnerability: {vuln['vuln_id']}[/]\n\n"
                    f"Affected package: {vuln['dependency']}\n"
                    f"Severity: {vuln['severity']}\n"
                    f"Description: {vuln['description']}\n"
                    f"Fixed in version: {vuln['fixed_version']}",
                    title="Vulnerability Details"
                ))


def show_dependencies_overview(results: Dict[str, Any]) -> None:
    """
    Show overview of detected dependencies.
    
    Args:
        results: Scan results.
    """
    dependencies = results.get("dependencies", [])
    if not dependencies:
        console.print("[yellow]No dependency information available[/]")
        return
    
    # Group dependencies by type
    dep_by_type = {}
    for dep in dependencies:
        dep_type = dep.get("type", "Unknown")
        if dep_type not in dep_by_type:
            dep_by_type[dep_type] = []
        dep_by_type[dep_type].append(dep)
    
    # Display summary by type
    console.print("[bold cyan]Dependencies by Type[/]")
    for dep_type, deps in dep_by_type.items():
        console.print(f"[green]{dep_type}:[/] {len(deps)} dependencies")
    
    # Display dependency list
    table = Table(title=f"Dependencies Overview ({len(dependencies)})")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="yellow")
    table.add_column("Type", style="green")
    table.add_column("Has Vulnerabilities", style="red")
    
    # Get vulnerable dependencies
    vuln_deps = set()
    for dep_id in results.get("vulnerabilities", {}).keys():
        vuln_deps.add(dep_id)
    
    for dep in dependencies:
        dep_name = dep.get("name", "Unknown")
        dep_version = dep.get("version", "Unknown")
        dep_id = f"{dep_name}@{dep_version}"
        
        has_vulns = "Yes" if dep_id in vuln_deps else "No"
        has_vulns_style = "red" if has_vulns == "Yes" else "green"
        
        table.add_row(
            dep_name,
            dep_version,
            dep.get("type", "Unknown"),
            f"[{has_vulns_style}]{has_vulns}[/{has_vulns_style}]"
        )
    
    console.print(table)


def show_sbom_info(results: Dict[str, Any]) -> None:
    """
    Show SBOM information from scan results.
    
    Args:
        results: Scan results.
    """
    sbom = results.get("sbom", {})
    if not sbom:
        console.print("[yellow]No SBOM information available[/]")
        return
    
    # Display SBOM info
    sbom_json = sbom.get("json", "{}")
    
    try:
        sbom_data = json.loads(sbom_json) if isinstance(sbom_json, str) else sbom_json
        
        console.print(Panel.fit(
            f"[bold]SBOM Information[/]\n\n"
            f"Format: {sbom_data.get('bomFormat', 'Unknown')}\n"
            f"Spec Version: {sbom_data.get('specVersion', 'Unknown')}\n"
            f"Components: {len(sbom_data.get('components', []))} items",
            title="Software Bill of Materials"
        ))
        
        # Ask if user wants to see the full SBOM
        show_full = questionary.confirm("Would you like to see the full SBOM?").ask()
        
        if show_full:
            sbom_str = json.dumps(sbom_data, indent=2)
            syntax = Syntax(sbom_str, "json", theme="monokai", line_numbers=True)
            console.print(syntax)
    
    except Exception as e:
        console.print(f"[bold red]Error parsing SBOM: {str(e)}[/]")


def show_raw_json(results: Dict[str, Any]) -> None:
    """
    Show raw JSON results.
    
    Args:
        results: Scan results.
    """
    json_str = json.dumps(results, indent=2)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(syntax)


def display_step(step: Dict[str, str]) -> None:
    """
    Display a demo step with explanation.
    
    Args:
        step: Step information.
    """
    console.print(Panel.fit(
        f"[bold]{step['title']}[/]\n\n{step['description']}",
        title=f"Step: {step['title']}",
        border_style="green"
    ))
    
    input("\nPress Enter to continue...")


def run_interactive_demo() -> int:
    """
    Run an interactive demonstration of the ossv-scanner.
    
    Returns:
        Exit code (0 for success).
    """
    console.print("[bold blue]Starting Interactive ossv-scanner Demo[/]")
    
    # Set up directories
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-interactive-demo-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Step 1: Introduction
        display_step(DEMO_STEPS[0])
        
        # Step 2: Project Selection
        display_step(DEMO_STEPS[1])
        
        # Display available templates
        table = Table(title="Available Project Templates")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description", style="yellow")
        
        for template_id, template in DEMO_TEMPLATES.items():
            table.add_row(template_id, template["name"], template["description"])
        
        console.print(table)
        
        # Ask user to select a template
        template_choices = list(DEMO_TEMPLATES.keys())
        selected_template = questionary.select(
            "Select a project template:",
            choices=template_choices
        ).ask()
        
        # Create project from template
        if selected_template == "custom":
            project_dir = create_custom_project(base_dir)
        else:
            project_dir = create_demo_project(selected_template, base_dir)
        
        console.print(f"[green]Project created at: {project_dir}[/]")
        
        # Step 3: Scanning
        display_step(DEMO_STEPS[2])
        
        # Run the scanner
        results_path = run_scanner(project_dir, output_dir)
        
        # Step 4: Results Analysis
        display_step(DEMO_STEPS[3])
        
        # Explore results
        explore_results(results_path)
        
        # Step 5: Customization
        display_step(DEMO_STEPS[4])
        
        # Demonstrate customization options
        console.print(Panel.fit(
            "[bold]Scanner Customization Options[/]\n\n"
            "ossv-scan --help\n"
            "ossv-scan --output-format json --output-path results.json --min-severity medium project_dir\n"
            "ossv-scan --sbom-only --output-format xml project_dir\n"
            "ossv-scan --ci --fail-on-severity high project_dir",
            title="Command-line Examples"
        ))
        
        # Conclusion
        console.print(Panel.fit(
            "[bold]Thank You![/]\n\n"
            "This concludes the interactive demo of ossv-scanner. "
            "You've seen how to scan a project for vulnerabilities, "
            "interpret the results, and use various options.\n\n"
            "For more information, check out the documentation or run:\n"
            "ossv-scan --help",
            title="Demo Completed",
            border_style="green"
        ))
        
        console.print(f"[bold green]Demo completed successfully![/]")
        console.print(f"Demo project directory: {base_dir}")
        
        return 0
        
    except Exception as e:
        console.print(f"[bold red]Error during interactive demo: {str(e)}[/]")
        return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(run_interactive_demo())