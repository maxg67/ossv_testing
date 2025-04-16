"""
Controlled testing module for OSSV Testing Framework.

This module provides tools for testing the scanner against known vulnerabilities
in controlled environments.
"""

from ossv_testing.controlled.test_suite import run_tests as run_test_suite
from ossv_testing.controlled.blind_tests import run_tests as run_blind_tests
from ossv_testing.controlled.edge_cases import run_tests as run_edge_tests
