"""
Statistical analysis module for OSSV Testing Framework.

This module provides tools for statistical analysis of test results to ensure
scientific rigor in evaluating the ossv-scanner performance.
"""

from ossv_testing.statistics.monte_carlo import run_simulation
from ossv_testing.statistics.correlation import analyze_correlation
from ossv_testing.statistics.confidence import calculate_intervals
