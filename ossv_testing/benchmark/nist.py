"""
NIST framework compliance testing for ossv-scanner.

Tests the scanner against NIST Special Publication 800-218: Secure Software Development Framework (SSDF),
specifically focusing on PW.4 (Identify and Confirm Vulnerabilities) and PO.1.1 (Create and maintain a 
software bill of materials).
"""

import os
import time
import logging
import tempfile
import json
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import requests
from rich.console import Console
from rich.progress import Progress

from ossv_scanner.parsers import get_parser_for_project

logger = logging.getLogger(__name__)
console = Console()

# NIST SSDF practices relevant to vulnerability scanning
NIST_PRACTICES = {
    "PW.4": "Identify and Confirm Vulnerabilities on an Ongoing Basis",
    "PW.4.1": "Gather information about potential vulnerabilities in the software and third-party components",
    "PW.4.2": "Review vulnerability reports and analyze their impact on the software",
    "PW.4.3": "Analyze software for vulnerabilities and verify security issues are fixed",
    "PW.4.4": "Track and analyze attacks and vulnerabilities reported externally",
    "PO.1.1": "Create and maintain a software bill of materials (SBOM) for each software release",
}

# Reference vulnerabilities based on NIST National Vulnerability Database 
REFERENCE_VULNS = [
    {"cve_id": "CVE-2021-44228", "package": "log4j", "version": "2.0"},      # Log4j (critical)
    {"cve_id": "CVE-2021-42574", "package": "ua-parser-js", "version": "0.7.29"}, # UA Parser (critical)
    {"cve_id": "CVE-2021-3749", "package": "axios", "version": "0.21.1"},    # Axios (high)
    {"cve_id": "CVE-2020-7598", "package": "minimist", "version": "0.2.1"},  # Minimist (medium)
    {"cve_id": "CVE-2019-11358", "package": "jquery", "version": "3.3.1"},   # jQuery (medium)
    {"cve_id": "CVE-2018-1000620", "package": "eslint", "version": "4.18.2"}, # ESLint (low)
]

def create_test_project() -> Tuple[Path, List[Dict[str, Any]]]:
    """
    Create a test project with known vulnerabilities.
    
    Returns:
        Tuple of (project_path, expected_vulnerabilities)
    """
    # Create temp directory for project
    project_dir = Path(tempfile.mkdtemp(prefix="ossv-nist-test-"))
    
    # Create package.json with vulnerable dependencies
    package_json = {
        "name": "ossv-nist-test",
        "version": "1.0.0",
        "description": "Test project for NIST compliance testing",
        "dependencies": {
            "axios": "0.21.1",
            "jquery": "3.3.1",
            "log4j": "2.0.0",
            "minimist": "0.2.1",
            "ua-parser-js": "0.7.29",
            "eslint": "4.18.2"
        }
    }
    
    with open(project_dir / "package.json", "w") as f:
        json.dump(package_json, f, indent=2)
    
    # Create a requirements.txt with Python dependencies
    with open(project_dir / "requirements.txt", "w") as f:
        f.write("requests==2.25.1\nflask==2.0.1\npandas>=1.3.0\n")
    
    # Create a simple Python script
    with open(project_dir / "app.py", "w") as f:
        f.write("""
import requests
import json

def main():
    response = requests.get("https://api.example.com/data")
    data = response.json()
    print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()
""")
    
    # Return the project path and the list of expected vulnerabilities
    expected_vulns = REFERENCE_VULNS.copy()
    
    return project_dir, expected_vulns


def validate_sbom(sbom_path: Path) -> Dict[str, Any]:
    """
    Validate the SBOM against NIST guidelines.
    
    Args:
        sbom_path: Path to the SBOM file.
        
    Returns:
        Dictionary with validation results.
    """
    validation_results = {
        "format_valid": False,
        "schema_valid": False,
        "component_count": 0,
        "required_fields_present": False,
        "missing_fields": [],
        "cyclonedx_version": None,
    }
    
    # Check if file exists
    if not sbom_path.exists():
        return validation_results
    
    try:
        # Load the SBOM file
        with open(sbom_path, "r") as f:
            if sbom_path.suffix.lower() == ".json":
                sbom_data = json.load(f)
                validation_results["format_valid"] = True
            else:
                logger.warning(f"Unsupported SBOM format: {sbom_path.suffix}")
                return validation_results
        
        # Check CycloneDX format
        if "bomFormat" in sbom_data and sbom_data["bomFormat"] == "CycloneDX":
            validation_results["schema_valid"] = True
            validation_results["cyclonedx_version"] = sbom_data.get("specVersion", "unknown")
        
        # Count components
        if "components" in sbom_data:
            validation_results["component_count"] = len(sbom_data["components"])
        
        # Check required fields according to NIST guidance
        required_fields = ["bomFormat", "specVersion", "components"]
        missing_fields = []
        
        for field in required_fields:
            if field not in sbom_data:
                missing_fields.append(field)
        
        validation_results["missing_fields"] = missing_fields
        validation_results["required_fields_present"] = len(missing_fields) == 0
        
        return validation_results
    
    except Exception as e:
        logger.error(f"Error validating SBOM: {str(e)}")
        return validation_results


def check_scanner_output(output_path: Path, expected_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Check the scanner output for expected vulnerabilities.
    
    Args:
        output_path: Path to the scanner output file.
        expected_vulns: List of expected vulnerabilities.
        
    Returns:
        Dictionary with validation results.
    """
    results = {
        "found_vulnerabilities": [],
        "missed_vulnerabilities": [],
        "detection_rate": 0.0,
        "false_positives": [],
        "false_negatives": [],
    }
    
    # Check if file exists
    if not output_path.exists():
        results["missed_vulnerabilities"] = expected_vulns
        return results
    
    try:
        # Load the scanner output
        with open(output_path, "r") as f:
            if output_path.suffix.lower() == ".json":
                output_data = json.load(f)
            else:
                logger.warning(f"Unsupported output format: {output_path.suffix}")
                results["missed_vulnerabilities"] = expected_vulns
                return results
        
        # Extract detected vulnerabilities
        detected_vulns = []
        if "vulnerabilities" in output_data:
            for dep_id, vulns in output_data["vulnerabilities"].items():
                for vuln in vulns:
                    detected_vulns.append({
                        "cve_id": vuln.get("cve_id", "unknown"),
                        "dependency": dep_id.split("@")[0] if "@" in dep_id else dep_id,
                        "version": dep_id.split("@")[1] if "@" in dep_id else "unknown",
                        "severity": vuln.get("severity", "unknown"),
                    })
        
        # Check which expected vulnerabilities were found
        found = []
        missed = []
        
        for exp_vuln in expected_vulns:
            # See if this vulnerability was detected
            found_match = False
            for detected in detected_vulns:
                if detected["cve_id"] == exp_vuln["cve_id"]:
                    found_match = True
                    found.append(exp_vuln)
                    break
            
            if not found_match:
                missed.append(exp_vuln)
        
        # Check for false positives (not in expected list)
        false_positives = []
        for detected in detected_vulns:
            if not any(detected["cve_id"] == exp["cve_id"] for exp in expected_vulns):
                # This could be a legitimate vulnerability not in our test list,
                # but for simplicity we'll count it as a false positive
                false_positives.append(detected)
        
        # Calculate detection rate
        detection_rate = len(found) / len(expected_vulns) if expected_vulns else 0
        
        # Populate results
        results["found_vulnerabilities"] = found
        results["missed_vulnerabilities"] = missed
        results["detection_rate"] = detection_rate
        results["false_positives"] = false_positives
        results["false_negatives"] = missed
        
        return results
    
    except Exception as e:
        logger.error(f"Error analyzing scanner output: {str(e)}")
        results["missed_vulnerabilities"] = expected_vulns
        return results


def run_ossv_scanner(project_path: Path, output_dir: Path) -> Tuple[Path, Path]:
    """
    Run the ossv-scanner on the test project.
    
    Args:
        project_path: Path to the test project.
        output_dir: Directory to save scanner output.
        
    Returns:
        Tuple of (output_report_path, sbom_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Report path
    report_path = output_dir / "scan-report.json"
    sbom_path = output_dir / "sbom.json"
    
    try:
        # Run the scanner
        logger.info(f"Running ossv-scanner on {project_path}")
        
        # First, run with --sbom-only to get the SBOM
        sbom_cmd = [
            "ossv-scan",
            "--sbom-only",
            "--output-format", "json",
            "--output-path", str(sbom_path),
            str(project_path)
        ]
        
        try:
            # Try to run as installed package
            subprocess.run(sbom_cmd, check=True, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            sbom_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--sbom-only",
                "--output-format", "json",
                "--output-path", str(sbom_path),
                str(project_path)
            ]
            subprocess.run(sbom_cmd, check=True, capture_output=True)
        
        # Then run the full vulnerability scan
        scan_cmd = [
            "ossv-scan",
            "--output-format", "json",
            "--output-path", str(report_path),
            str(project_path)
        ]
        
        try:
            # Try to run as installed package
            subprocess.run(scan_cmd, check=True, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            # If that fails, try running as a module
            scan_cmd = [
                "python", "-m", "ossv_scanner.main",
                "--output-format", "json",
                "--output-path", str(report_path),
                str(project_path)
            ]
            subprocess.run(scan_cmd, check=True, capture_output=True)
        
        logger.info(f"Scanner completed successfully. Reports at {report_path} and {sbom_path}")
        return report_path, sbom_path
    
    except Exception as e:
        logger.error(f"Error running ossv-scanner: {str(e)}")
        # Create empty files to avoid file not found errors
        with open(report_path, "w") as f:
            json.dump({"error": str(e)}, f)
        with open(sbom_path, "w") as f:
            json.dump({"error": str(e)}, f)
        
        return report_path, sbom_path


def evaluate_nist_compliance(scanner_results: Dict[str, Any], sbom_validation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate compliance with NIST SSDF practices.
    
    Args:
        scanner_results: Results from checking the scanner output.
        sbom_validation: Results from validating the SBOM.
        
    Returns:
        Dictionary with compliance results for each practice.
    """
    compliance_results = {}
    
    # PW.4: Identify and Confirm Vulnerabilities
    pw4_score = scanner_results["detection_rate"] * 100
    pw4_status = "Compliant" if pw4_score >= 80 else "Partially Compliant" if pw4_score >= 50 else "Non-Compliant"
    
    compliance_results["PW.4"] = {
        "practice": NIST_PRACTICES["PW.4"],
        "score": pw4_score,
        "status": pw4_status,
        "details": f"Detected {len(scanner_results['found_vulnerabilities'])} of {len(scanner_results['found_vulnerabilities'] + scanner_results['missed_vulnerabilities'])} vulnerabilities",
        "recommendations": []
    }
    
    # Add recommendations based on findings
    if scanner_results["missed_vulnerabilities"]:
        compliance_results["PW.4"]["recommendations"].append(
            f"Improve detection for: {', '.join(v['cve_id'] for v in scanner_results['missed_vulnerabilities'])}"
        )
    
    if scanner_results["false_positives"]:
        compliance_results["PW.4"]["recommendations"].append(
            f"Reduce false positives: {len(scanner_results['false_positives'])} false positives detected"
        )
    
    # PW.4.1: Gather information about potential vulnerabilities
    pw41_score = scanner_results["detection_rate"] * 100
    pw41_status = "Compliant" if pw41_score >= 80 else "Partially Compliant" if pw41_score >= 50 else "Non-Compliant"
    
    compliance_results["PW.4.1"] = {
        "practice": NIST_PRACTICES["PW.4.1"],
        "score": pw41_score,
        "status": pw41_status,
        "details": f"Effectiveness in identifying vulnerabilities in third-party components",
        "recommendations": []
    }
    
    # PO.1.1: Create and maintain a software bill of materials (SBOM)
    po11_score = 0
    if sbom_validation["format_valid"] and sbom_validation["schema_valid"]:
        # Basic requirements met
        po11_score += 50
        
        # Check for component completeness
        if sbom_validation["component_count"] > 0:
            po11_score += 25
        
        # Check for required fields
        if sbom_validation["required_fields_present"]:
            po11_score += 25
    
    po11_status = "Compliant" if po11_score >= 80 else "Partially Compliant" if po11_score >= 50 else "Non-Compliant"
    
    compliance_results["PO.1.1"] = {
        "practice": NIST_PRACTICES["PO.1.1"],
        "score": po11_score,
        "status": po11_status,
        "details": f"SBOM generation capability: {sbom_validation['component_count']} components, format valid: {sbom_validation['format_valid']}, schema valid: {sbom_validation['schema_valid']}",
        "recommendations": []
    }
    
    if not sbom_validation["format_valid"]:
        compliance_results["PO.1.1"]["recommendations"].append("Ensure SBOM is generated in a valid format (JSON/XML)")
    
    if not sbom_validation["schema_valid"]:
        compliance_results["PO.1.1"]["recommendations"].append("Ensure SBOM follows CycloneDX schema specification")
    
    if sbom_validation["missing_fields"]:
        compliance_results["PO.1.1"]["recommendations"].append(
            f"Add missing required fields to SBOM: {', '.join(sbom_validation['missing_fields'])}"
        )
    
    # Calculate overall compliance
    scores = [
        compliance_results["PW.4"]["score"],
        compliance_results["PW.4.1"]["score"],
        compliance_results["PO.1.1"]["score"]
    ]
    
    overall_score = sum(scores) / len(scores)
    overall_status = "Compliant" if overall_score >= 80 else "Partially Compliant" if overall_score >= 50 else "Non-Compliant"
    
    compliance_results["overall"] = {
        "score": overall_score,
        "status": overall_status,
        "compliant_practices": sum(1 for p in ["PW.4", "PW.4.1", "PO.1.1"] if compliance_results[p]["status"] == "Compliant"),
        "partially_compliant_practices": sum(1 for p in ["PW.4", "PW.4.1", "PO.1.1"] if compliance_results[p]["status"] == "Partially Compliant"),
        "non_compliant_practices": sum(1 for p in ["PW.4", "PW.4.1", "PO.1.1"] if compliance_results[p]["status"] == "Non-Compliant"),
    }
    
    return compliance_results


def run_benchmark(basic: bool = False, comprehensive: bool = False) -> Dict[str, Any]:
    """
    Run the NIST benchmark tests.
    
    Args:
        basic: Whether to run a basic test.
        comprehensive: Whether to run comprehensive tests.
        
    Returns:
        Dictionary with benchmark results.
    """
    logger.info("Starting NIST benchmark tests")
    
    # Create test project with known vulnerabilities
    project_path, expected_vulns = create_test_project()
    
    # Create output directory
    output_dir = project_path / "output"
    output_dir.mkdir(exist_ok=True)
    
    # Run the scanner on the test project
    report_path, sbom_path = run_ossv_scanner(project_path, output_dir)
    
    # Check scanner output and SBOM
    scanner_results = check_scanner_output(report_path, expected_vulns)
    sbom_validation = validate_sbom(sbom_path)
    
    # Evaluate NIST compliance
    compliance_results = evaluate_nist_compliance(scanner_results, sbom_validation)
    
    # If comprehensive, run additional tests
    if comprehensive:
        logger.info("Running comprehensive NIST benchmark tests")
        # TODO: Implement comprehensive tests
    
    # Combine results
    benchmark_results = {
        "project_path": str(project_path),
        "expected_vulnerabilities": expected_vulns,
        "scanner_results": scanner_results,
        "sbom_validation": sbom_validation,
        "compliance": compliance_results,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "benchmark_type": "basic" if basic else "comprehensive" if comprehensive else "standard",
        }
    }
    
    logger.info("NIST benchmark tests completed")
    return benchmark_results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = run_benchmark()
    print(json.dumps(results, indent=2))
