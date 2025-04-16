"""
Comparative testing module for OSSV Testing Framework.

This module provides tools for comparing ossv-scanner with other vulnerability scanning tools
to evaluate relative performance, feature coverage, and return on investment.
"""

from ossv_testing.comparative.tool_matrix import compare_tools
from ossv_testing.comparative.roi import analyze_roi
from ossv_testing.comparative.feature_matrix import generate_matrix
