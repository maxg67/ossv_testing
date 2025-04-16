"""
Command-line interface for the OSSV Testing Framework.
"""

import sys
import argparse
import logging
from typing import List, Optional

from rich.console import Console
from rich.logging import RichHandler

from ossv_testing.core import TestFramework

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("ossv-testing")
console = Console()


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Scientific testing framework for OSS Vulnerability Scanner"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run tests")
    run_parser.add_argument("--basic", action="store_true", help="Run basic test suite")
    run_parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive test suite")
    run_parser.add_argument("--output", help="Output directory for test results")
    run_parser.add_argument("--config", help="Path to test configuration file")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    # Benchmark command
    benchmark_parser = subparsers.add_parser("benchmark", help="Run benchmark tests")
    benchmark_parser.add_argument("--framework", choices=["nist", "owasp", "cve_coverage", "all"], 
                                 default="all", help="Benchmark framework to use")
    benchmark_parser.add_argument("--output", help="Output directory for benchmark results")
    
    # Performance command
    perf_parser = subparsers.add_parser("performance", help="Run performance tests")
    perf_parser.add_argument("--mode", choices=["load", "chaos", "resource", "all"], 
                            default="all", help="Performance test mode")
    perf_parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    perf_parser.add_argument("--output", help="Output directory for performance results")
    
    # Compare command
    compare_parser = subparsers.add_parser("compare", help="Run comparative tests")
    compare_parser.add_argument("--tools", help="Comma-separated list of tools to compare")
    compare_parser.add_argument("--mode", choices=["feature", "roi", "both"], 
                               default="both", help="Comparison mode")
    compare_parser.add_argument("--output", help="Output directory for comparison results")
    
    # Visualize command
    viz_parser = subparsers.add_parser("visualize", help="Generate visualizations")
    viz_parser.add_argument("--type", choices=["dashboard", "report", "leaderboard"], 
                           required=True, help="Visualization type")
    viz_parser.add_argument("--input", help="Input directory with test results")
    viz_parser.add_argument("--output", help="Output directory for visualizations")
    
    # Integration command
    integration_parser = subparsers.add_parser("integration", help="Run integration tests")
    integration_parser.add_argument("--type", choices=["ci_cd", "api", "plugin", "all"], 
                                   default="all", help="Integration test type")
    integration_parser.add_argument("--output", help="Output directory for integration test results")
    
    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run demonstration")
    demo_parser.add_argument("--scenario", help="Demonstration scenario to run")
    demo_parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    
    return parser


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    if args is None:
        args = sys.argv[1:]
    
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    if not parsed_args.command:
        parser.print_help()
        return 1
    
    # Set up verbose logging if requested
    if getattr(parsed_args, "verbose", False):
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize the test framework
        framework = TestFramework()
        
        # Execute the requested command
        if parsed_args.command == "run":
            if parsed_args.basic:
                return framework.run_basic_tests(output_dir=parsed_args.output, config_path=parsed_args.config)
            elif parsed_args.comprehensive:
                return framework.run_comprehensive_tests(output_dir=parsed_args.output, config_path=parsed_args.config)
            else:
                console.print("[bold red]Error:[/] Please specify --basic or --comprehensive")
                return 1
                
        elif parsed_args.command == "benchmark":
            return framework.run_benchmarks(
                framework=parsed_args.framework,
                output_dir=parsed_args.output
            )
            
        elif parsed_args.command == "performance":
            return framework.run_performance_tests(
                mode=parsed_args.mode,
                duration=parsed_args.duration,
                output_dir=parsed_args.output
            )
            
        elif parsed_args.command == "compare":
            tools = parsed_args.tools.split(",") if parsed_args.tools else []
            return framework.run_comparative_tests(
                tools=tools,
                mode=parsed_args.mode,
                output_dir=parsed_args.output
            )
            
        elif parsed_args.command == "visualize":
            return framework.generate_visualization(
                viz_type=parsed_args.type,
                input_dir=parsed_args.input,
                output_dir=parsed_args.output
            )
            
        elif parsed_args.command == "integration":
            return framework.run_integration_tests(
                test_type=parsed_args.type,
                output_dir=parsed_args.output
            )
            
        elif parsed_args.command == "demo":
            return framework.run_demo(
                scenario=parsed_args.scenario,
                interactive=parsed_args.interactive
            )
    
    except Exception as e:
        logger.exception(f"Error executing command: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
