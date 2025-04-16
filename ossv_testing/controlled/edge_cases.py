"""
Edge case testing for ossv-scanner.

This module tests how the scanner handles unusual dependency configurations and edge cases,
such as non-standard versioning schemes, deeply nested dependencies, and conflicting versions.
"""

import os
import time
import logging
import tempfile
import json
import yaml
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# Edge case test definitions
EDGE_CASES = [
    {
        "id": "ec-01",
        "name": "Non-standard Versioning",
        "description": "Test handling of non-standard version formats",
        "ecosystem": "npm",
        "files": {
            "package.json": {
                "name": "non-standard-versions",
                "version": "1.0.0",
                "description": "Test for non-standard version formats",
                "dependencies": {
                    "lodash": "latest",                # 'latest' tag
                    "jquery": ">=2.0.0",               # Version range
                    "express": "github:expressjs/express#4.17.1",  # GitHub URL
                    "debug": "^2.x",                   # x-range with caret
                    "moment": "~2.29.0-beta.1",        # Pre-release with tilde
                    "chalk": "next",                   # 'next' tag
                    "socket.io": "*"                   # Wildcard
                }
            }
        },
        "expected_behavior": {
            "should_parse": True,
            "should_check_versions": True,
            "should_handle_ranges": True,
            "should_handle_nonstandard": True
        }
    },
    {
        "id": "ec-02",
        "name": "Deeply Nested Dependencies",
        "description": "Test handling of deeply nested dependency trees",
        "ecosystem": "npm",
        "files": {
            "package.json": {
                "name": "deep-nesting",
                "version": "1.0.0",
                "description": "Test for deeply nested dependencies",
                "dependencies": {
                    "webpack": "5.60.0",        # Has deeply nested dependencies
                    "babel-core": "6.26.3",     # Has many transitive dependencies
                    "react": "17.0.2",          # Complex dependency tree
                    "vue": "2.6.14"             # Complex dependency tree
                }
            },
            "nested-config/package.json": {
                "name": "nested-config",
                "version": "1.0.0",
                "dependencies": {
                    "axios": "0.21.1",           # CVE-2021-3749
                    "jquery": "1.12.4"           # Multiple vulnerabilities
                }
            }
        },
        "expected_behavior": {
            "should_parse": True,
            "should_find_nested": True,
            "should_check_transitive": True
        }
    },
    {
        "id": "ec-03",
        "name": "Conflicting Version Requirements",
        "description": "Test handling of conflicting version requirements",
        "ecosystem": "python",
        "files": {
            "requirements.txt": "\n".join([
                "Django==1.11.29",               # Older but explicit
                "django>=3.2.0",                 # Newer but range (conflicting)
                "requests==2.22.0",              # Explicit
                "requests>=2.25.0",              # Range (conflicting)
            ])
        },
        "expected_behavior": {
            "should_parse": True,
            "should_detect_conflicts": True,
            "should_prefer_explicit": True
        }
    },
    {
        "id": "ec-04",
        "name": "Mixed Ecosystems in One Directory",
        "description": "Test handling of mixed package ecosystems in one directory",
        "ecosystem": "mixed",
        "files": {
            "package.json": {
                "name": "mixed-ecosystem-project",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15",  # CVE-2019-10744
                    "jquery": "3.4.0"     # CVE-2019-11358
                }
            },
            "requirements.txt": "\n".join([
                "Django==2.2.8",  # CVE-2019-19844
                "Flask==0.12.2"   # CVE-2018-1000656
            ]),
            "pom.xml": """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>mixed-ecosystem</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
            <version>2.5.16</version>
        </dependency>
    </dependencies>
</project>""",
            "Gemfile": "source 'https://rubygems.org'\n\ngem 'rails', '5.2.4.3'\ngem 'nokogiri', '1.10.9'"
        },
        "expected_behavior": {
            "should_parse": True,
            "should_handle_mixed": True,
            "should_check_all": True
        }
    },
    {
        "id": "ec-05",
        "name": "Empty and Invalid Files",
        "description": "Test handling of empty and invalid dependency files",
        "ecosystem": "mixed",
        "files": {
            "empty-package.json": "{}",
            "malformed-package.json": "{\"name\": \"malformed\", \"dependencies\": {\"broken\":",
            "empty-requirements.txt": "",
            "malformed-pom.xml": "<project><modelVersion>4.0.0</modelVersion><artifactId>broken</artifactId></wrong-tag>",
            "package.json": {
                "name": "valid-alongside-invalid",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15"  # Should still detect this vulnerable package
                }
            }
        },
        "expected_behavior": {
            "should_handle_empty": True,
            "should_handle_malformed": True,
            "should_parse_valid": True
        }
    },
    {
        "id": "ec-06",
        "name": "Non-standard Locations",
        "description": "Test handling of dependency files in non-standard locations",
        "ecosystem": "mixed",
        "files": {
            "frontend/client/src/package.json": {
                "name": "deeply-nested-pkg",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15"  # CVE-2019-10744
                }
            },
            "backend/config/deps/requirements.txt": "\n".join([
                "Django==2.2.8"  # CVE-2019-19844
            ]),
            "docs/examples/sample-app/package.json": {
                "name": "example-app",
                "version": "1.0.0",
                "dependencies": {
                    "jquery": "3.4.0"  # CVE-2019-11358
                }
            }
        },
        "expected_behavior": {
            "should_find_nested": True,
            "should_parse_all": True,
            "should_check_all": True
        }
    },
    {
        "id": "ec-07",
        "name": "Unusual Character Encodings",
        "description": "Test handling of files with unusual character encodings",
        "ecosystem": "npm",
        "files": {
            # This will be created with UTF-16 encoding in the setup function
            "package.json.utf16": json.dumps({
                "name": "utf16-encoded",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15"  # CVE-2019-10744
                }
            }, indent=2),
            # This will be created with UTF-8 BOM in the setup function
            "package.json.bom": json.dumps({
                "name": "bom-encoded",
                "version": "1.0.0",
                "dependencies": {
                    "jquery": "3.4.0"  # CVE-2019-11358
                }
            }, indent=2)
        },
        "expected_behavior": {
            "should_handle_encodings": True
        }
    },
    {
        "id": "ec-08",
        "name": "Indirect Dependencies",
        "description": "Test handling of indirectly referenced dependencies",
        "ecosystem": "mixed",
        "files": {
            "package.json": {
                "name": "workspace-root",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {}
            },
            "packages/pkg-a/package.json": {
                "name": "pkg-a",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15"  # CVE-2019-10744
                }
            },
            "docker/Dockerfile": """FROM node:14
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
CMD ["npm", "start"]
""",
            "pyproject.toml": """[tool.poetry]
name = "poetry-project"
version = "0.1.0"
description = ""

[tool.poetry.dependencies]
python = "^3.8"
django = "2.2.8"  # CVE-2019-19844

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
"""
        },
        "expected_behavior": {
            "should_parse_workspaces": True,
            "should_parse_nonstandard": True
        }
    }
]


def create_edge_case_project(test_case: Dict[str, Any], base_dir: Path) -> Path:
    """
    Create a project with edge case dependencies.
    
    Args:
        test_case: Edge case test definition.
        base_dir: Base directory to create the project in.
        
    Returns:
        Path to the created project.
    """
    # Create project directory
    project_dir = base_dir / test_case["id"]
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create each file in the test case
    for file_path, content in test_case["files"].items():
        full_path = project_dir / file_path
        
        # Create parent directories if needed
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Special handling for different encodings
        if file_path.endswith(".utf16"):
            actual_path = full_path.with_suffix("")  # Remove the .utf16 suffix
            with open(actual_path, "w", encoding="utf-16") as f:
                if isinstance(content, dict):
                    json.dump(content, f, indent=2)
                else:
                    f.write(content)
                    
        elif file_path.endswith(".bom"):
            actual_path = full_path.with_suffix("")  # Remove the .bom suffix
            with open(actual_path, "wb") as f:
                # Write UTF-8 BOM
                f.write(b'\xef\xbb\xbf')
                # Write content
                if isinstance(content, dict):
                    f.write(json.dumps(content, indent=2).encode('utf-8'))
                else:
                    f.write(content.encode('utf-8'))
                    
        else:
            with open(full_path, "w") as f:
                if isinstance(content, dict):
                    json.dump(content, f, indent=2)
                else:
                    f.write(content)
    
    return project_dir


def run_scanner(project_path: Path, output_dir: Path) -> Path:
    """
    Run ossv-scanner on a project.
    
    Args:
        project_path: Path to the project.
        output_dir: Directory to save scanner output.
        
    Returns:
        Path to the scanner output file.
    """
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{project_path.name}-results.json"
    
    try:
        # Run the scanner
        logger.info(f"Running ossv-scanner on {project_path}")
        
        scan_cmd = [
            "ossv-scan",
            "--output-format", "json",
            "--output-path", str(output_path),
            str(project_path)
        ]
        
        try:
            # Try to run as installed package
            process = subprocess.run(scan_cmd, capture_output=True, text=True)
            logger.debug(f"Scanner output: {process.stdout}")
            if process.returncode != 0:
                logger.warning(f"Scanner returned non-zero exit code: {process.returncode}")
                logger.warning(f"Error output: {process.stderr}")
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            scan_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--output-format", "json",
                "--output-path", str(output_path),
                str(project_path)
            ]
            process = subprocess.run(scan_cmd, capture_output=True, text=True)
            logger.debug(f"Scanner output: {process.stdout}")
            if process.returncode != 0:
                logger.warning(f"Scanner returned non-zero exit code: {process.returncode}")
                logger.warning(f"Error output: {process.stderr}")
        
        logger.info(f"Scanner completed. Results at {output_path}")
        return output_path
        
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        # Create empty file to avoid file not found errors
        with open(output_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return output_path


def analyze_edge_case_result(result_path: Path, test_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze scanner results for edge cases.
    
    Args:
        result_path: Path to scanner result file.
        test_case: Edge case test definition.
        
    Returns:
        Analysis results.
    """
    analysis = {
        "success": False,
        "dependencies_found": 0,
        "vulnerabilities_found": 0,
        "parse_errors": [],
        "expected_behavior_results": {},
        "notes": []
    }
    
    # Check if results file exists
    if not result_path.exists():
        logger.warning(f"Results file not found: {result_path}")
        analysis["success"] = False
        analysis["notes"].append("Scanner did not produce an output file")
        return analysis
    
    try:
        # Load scanner results
        with open(result_path, "r") as f:
            scan_results = json.load(f)
        
        # Extract dependencies and vulnerabilities
        dependencies = scan_results.get("dependencies", [])
        vulnerabilities = scan_results.get("vulnerabilities", {})
        
        analysis["dependencies_found"] = len(dependencies)
        analysis["vulnerabilities_found"] = sum(len(vulns) for vulns in vulnerabilities.values())
        
        # Check for errors
        if "error" in scan_results:
            analysis["success"] = False
            analysis["parse_errors"].append(scan_results["error"])
        else:
            analysis["success"] = True
        
        # Analyze expected behavior
        expected_behavior = test_case["expected_behavior"]
        
        # Should parse files
        if "should_parse" in expected_behavior:
            result = analysis["dependencies_found"] > 0
            analysis["expected_behavior_results"]["should_parse"] = result
        
        # Should check versions
        if "should_check_versions" in expected_behavior:
            # If any vulnerability is found, versions are being checked
            result = analysis["vulnerabilities_found"] > 0
            analysis["expected_behavior_results"]["should_check_versions"] = result
        
        # Should handle ranges
        if "should_handle_ranges" in expected_behavior:
            # Look for dependencies with version ranges
            has_range_deps = False
            for dep in dependencies:
                if "version" in dep and any(c in dep["version"] for c in ["^", "~", ">=", "*", "x"]):
                    has_range_deps = True
                    break
            
            analysis["expected_behavior_results"]["should_handle_ranges"] = has_range_deps
        
        # Should handle non-standard versions
        if "should_handle_nonstandard" in expected_behavior:
            # Look for dependencies with non-standard versions
            has_nonstandard = False
            for dep in dependencies:
                if "version" in dep and any(v == dep["version"] for v in ["latest", "next", "*"]):
                    has_nonstandard = True
                    break
            
            analysis["expected_behavior_results"]["should_handle_nonstandard"] = has_nonstandard
        
        # Should find nested dependencies
        if "should_find_nested" in expected_behavior:
            # Check for dependencies from nested files
            if test_case["id"] == "ec-02":
                # For deeply nested test, check if dependencies from nested-config were found
                has_nested = any(dep["name"] == "axios" for dep in dependencies)
            elif test_case["id"] == "ec-06":
                # For non-standard locations test, check if dependencies from frontend/client/src were found
                has_nested = any(dep["name"] == "lodash" for dep in dependencies)
            else:
                has_nested = False
            
            analysis["expected_behavior_results"]["should_find_nested"] = has_nested
        
        # Should handle mixed ecosystems
        if "should_handle_mixed" in expected_behavior:
            # Check if dependencies from different ecosystems were found
            has_npm = any(dep.get("package_type") == "npm" for dep in dependencies)
            has_pypi = any(dep.get("package_type") == "pypi" for dep in dependencies)
            
            analysis["expected_behavior_results"]["should_handle_mixed"] = has_npm and has_pypi
        
        # Should handle empty/malformed files
        if "should_handle_empty" in expected_behavior:
            # If we got here without errors, empty files were handled
            analysis["expected_behavior_results"]["should_handle_empty"] = analysis["success"]
        
        if "should_handle_malformed" in expected_behavior:
            # Check if valid dependencies were still found despite malformed files
            has_valid = any(dep["name"] == "lodash" for dep in dependencies)
            analysis["expected_behavior_results"]["should_handle_malformed"] = has_valid
        
        # Add notes based on findings
        if not analysis["success"]:
            analysis["notes"].append("Scanner encountered errors during processing")
        
        if analysis["dependencies_found"] == 0:
            analysis["notes"].append("No dependencies were found")
        
        # Overall success based on meeting expected behaviors
        behavior_results = analysis["expected_behavior_results"]
        if behavior_results:
            success_rate = sum(1 for v in behavior_results.values() if v) / len(behavior_results)
            analysis["behavior_success_rate"] = success_rate
            
            if success_rate >= 0.8:
                analysis["notes"].append("Scanner successfully handled most edge cases")
            elif success_rate >= 0.5:
                analysis["notes"].append("Scanner had mixed results with edge cases")
            else:
                analysis["notes"].append("Scanner struggled with most edge cases")
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing results: {str(e)}")
        analysis["success"] = False
        analysis["parse_errors"].append(str(e))
        analysis["notes"].append("Error occurred during analysis")
        return analysis


def run_tests(basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run edge case tests.
    
    Args:
        basic: Whether to run a basic subset of tests.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Test results.
    """
    logger.info("Starting edge case tests")
    
    # Set up test environment
    base_dir = Path(tempfile.mkdtemp(prefix="ossv-edge-cases-"))
    output_dir = base_dir / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Select test cases
    if basic:
        # Use a minimal set of test cases for basic testing
        selected_cases = [EDGE_CASES[0], EDGE_CASES[3]]  # Non-standard versions and mixed ecosystems
    elif comprehensive:
        # Use all test cases and potentially add more complex ones
        selected_cases = EDGE_CASES
        # TODO: Add more complex edge cases for comprehensive testing
    else:
        # Default to all standard test cases
        selected_cases = EDGE_CASES
    
    test_results = {}
    
    # Summary metrics
    summary = {
        "total_tests": len(selected_cases),
        "successful_tests": 0,
        "failed_tests": 0,
        "total_behaviors_tested": 0,
        "successful_behaviors": 0,
        "overall_success_rate": 0.0,
        "by_category": {}
    }
    
    # Group test cases by ecosystem for summary
    ecosystems = set(tc["ecosystem"] for tc in selected_cases)
    for ecosystem in ecosystems:
        summary["by_category"][ecosystem] = {
            "tests": 0,
            "success": 0,
            "fail": 0,
            "rate": 0.0
        }
    
    with Progress() as progress:
        # Create and test each edge case
        task = progress.add_task("[green]Running edge case tests...", total=len(selected_cases))
        
        for test_case in selected_cases:
            logger.info(f"Testing {test_case['name']} ({test_case['id']})")
            
            # Create test project
            project_dir = create_edge_case_project(test_case, base_dir)
            
            # Run scanner
            result_path = run_scanner(project_dir, output_dir)
            
            # Analyze results
            analysis = analyze_edge_case_result(result_path, test_case)
            
            # Store results
            test_results[test_case["id"]] = {
                "name": test_case["name"],
                "description": test_case["description"],
                "ecosystem": test_case["ecosystem"],
                "project_path": str(project_dir),
                "result_path": str(result_path),
                "analysis": analysis
            }
            
            # Update summary
            ecosystem = test_case["ecosystem"]
            success = analysis["success"]
            
            if success:
                summary["successful_tests"] += 1
                summary["by_category"][ecosystem]["success"] += 1
            else:
                summary["failed_tests"] += 1
                summary["by_category"][ecosystem]["fail"] += 1
            
            summary["by_category"][ecosystem]["tests"] += 1
            
            # Count behavior successes
            behaviors = analysis.get("expected_behavior_results", {})
            summary["total_behaviors_tested"] += len(behaviors)
            summary["successful_behaviors"] += sum(1 for v in behaviors.values() if v)
            
            progress.update(task, advance=1)
    
    # Calculate success rates
    if summary["total_tests"] > 0:
        summary["overall_success_rate"] = summary["successful_tests"] / summary["total_tests"]
    
    if summary["total_behaviors_tested"] > 0:
        summary["behavior_success_rate"] = summary["successful_behaviors"] / summary["total_behaviors_tested"]
    
    for ecosystem in summary["by_category"]:
        if summary["by_category"][ecosystem]["tests"] > 0:
            summary["by_category"][ecosystem]["rate"] = (
                summary["by_category"][ecosystem]["success"] / 
                summary["by_category"][ecosystem]["tests"]
            )
    
    # Final results
    final_results = {
        "test_environment": {
            "base_dir": str(base_dir),
            "output_dir": str(output_dir)
        },
        "test_cases": test_results,
        "summary": summary,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "test_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
            "num_test_cases": len(selected_cases)
        }
    }
    
    # Display summary
    display_summary(summary)
    
    logger.info("Edge case tests completed")
    return final_results


def display_summary(summary: Dict[str, Any]) -> None:
    """
    Display a summary of edge case test results.
    
    Args:
        summary: Summary metrics dictionary.
    """
    console.print("\n[bold cyan]Edge Case Test Summary[/]")
    
    # Create overall summary table
    table = Table(title="Edge Case Testing Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Rate", style="yellow")
    
    table.add_row("Total Tests", str(summary["total_tests"]), "")
    table.add_row("Successful Tests", str(summary["successful_tests"]), f"{summary['overall_success_rate']:.1%}")
    table.add_row("Failed Tests", str(summary["failed_tests"]), f"{1 - summary['overall_success_rate']:.1%}")
    table.add_row("Total Behaviors Tested", str(summary["total_behaviors_tested"]), "")
    table.add_row("Successful Behaviors", str(summary["successful_behaviors"]), f"{summary.get('behavior_success_rate', 0):.1%}")
    
    console.print(table)
    
    # Create ecosystem breakdown table
    console.print("\n[bold cyan]Results by Category[/]")
    eco_table = Table()
    eco_table.add_column("Category", style="cyan")
    eco_table.add_column("Tests", style="green")
    eco_table.add_column("Success", style="green")
    eco_table.add_column("Fail", style="red")
    eco_table.add_column("Success Rate", style="yellow")
    
    for category, metrics in summary["by_category"].items():
        eco_table.add_row(
            category,
            str(metrics["tests"]),
            str(metrics["success"]),
            str(metrics["fail"]),
            f"{metrics['rate']:.1%}"
        )
    
    console.print(eco_table)
    
    # Overall assessment
    if summary["overall_success_rate"] >= 0.8:
        console.print("[bold green]Overall Assessment:[/] Scanner handles edge cases well")
    elif summary["overall_success_rate"] >= 0.5:
        console.print("[bold yellow]Overall Assessment:[/] Scanner has moderate edge case handling")
    else:
        console.print("[bold red]Overall Assessment:[/] Scanner struggles with edge cases")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_tests()
    print(json.dumps(results, indent=2))
