# ossv_testing/integration/__init__.py
"""
Integration testing module for OSSV Testing Framework.

This module provides tools for testing the integration of ossv-scanner
with CI/CD pipelines, APIs, and various developer tooling.
"""

from ossv_testing.integration.ci_cd import run_tests as run_cicd_tests
from ossv_testing.integration.api_tests import run_tests as run_api_tests
from ossv_testing.integration.plugin_tests import run_tests as run_plugin_tests