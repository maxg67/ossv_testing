"""
Benchmark testing module for OSSV Testing Framework.

This module provides tools for evaluating ossv-scanner against established standards
and measuring its effectiveness in detecting vulnerabilities.
"""

from ossv_testing.benchmark.nist import run_benchmark as run_nist_benchmark
from ossv_testing.benchmark.owasp import run_benchmark as run_owasp_benchmark
from ossv_testing.benchmark.cve_coverage import analyze_coverage
