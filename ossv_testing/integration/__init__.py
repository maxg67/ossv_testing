# ossv_testing/integration/__init__.py
"""
Integration testing module for OSSV Testing Framework.

This module provides tools for testing the integration of ossv-scanner
with CI/CD pipelines, APIs, and various developer tooling.
"""

from ossv_testing.integration.ci_cd import run_tests as run_cicd_tests
from ossv_testing.integration.api_tests import run_tests as run_api_tests
from ossv_testing.integration.plugin_tests import run_plugin_tests


# Create placeholder functions if the actual ones don't exist
def run_cicd_tests():
    return {"status": "not_implemented"}

def run_api_tests():
    return {"status": "not_implemented"}

def run_plugin_tests():
    return {"status": "not_implemented"}

# Try to import the real functions, but use placeholders if they don't exist
try:
    from ossv_testing.integration.ci_cd import run_tests as run_cicd_tests
except (ImportError, AttributeError):
    pass

try:
    from ossv_testing.integration.api_tests import run_tests as run_api_tests
except (ImportError, AttributeError):
    pass

try:
    from ossv_testing.integration.plugin_tests import run_tests as run_plugin_tests
except (ImportError, AttributeError):
    pass