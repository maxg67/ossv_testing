"""
Core functionality for the OSSV Testing Framework.
"""

import os
import time
import logging
import tempfile
import json
import yaml
from typing import List, Dict, Any, Optional, Union
from pathlib import Path

from rich.console import Console
from rich.progress import Progress

logger = logging.getLogger(__name__)
console = Console()


class TestFramework:
    """Main class for orchestrating the testing framework."""
    
    def __init__(self):
        """Initialize the test framework."""
        self.results_dir = Path("ossv_results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = time.time()
        self.config = {}
        self.base_dir = Path.cwd()
        
        # Import modules conditionally to avoid circular imports
        from ossv_testing.benchmark import nist, owasp, cve_coverage
        from ossv_testing.controlled import test_suite, blind_tests, edge_cases
        from ossv_testing.performance import load_testing, chaos, resource_usage
        from ossv_testing.comparative import tool_matrix, roi, feature_matrix
        from ossv_testing.statistics import monte_carlo, correlation, confidence
        from ossv_testing.visualization import dashboard, leaderboard, report_gen
        from ossv_testing.integration import ci_cd, api_tests, plugin_tests
        from ossv_testing.demo import live_demo, participation, scenarios
        
        # Store module references
        self.modules = {
            "benchmark": {
                "nist": nist,
                "owasp": owasp,
                "cve_coverage": cve_coverage,
            },
            "controlled": {
                "test_suite": test_suite,
                "blind_tests": blind_tests,
                "edge_cases": edge_cases,
            },
            "performance": {
                "load_testing": load_testing,
                "chaos": chaos,
                "resource_usage": resource_usage,
            },
            "comparative": {
                "tool_matrix": tool_matrix,
                "roi": roi,
                "feature_matrix": feature_matrix,
            },
            "statistics": {
                "monte_carlo": monte_carlo,
                "correlation": correlation,
                "confidence": confidence,
            },
            "visualization": {
                "dashboard": dashboard,
                "leaderboard": leaderboard,
                "report_gen": report_gen,
            },
            "integration": {
                "ci_cd": ci_cd,
                "api_tests": api_tests,
                "plugin_tests": plugin_tests,
            },
            "demo": {
                "live_demo": live_demo,
                "participation": participation,
                "scenarios": scenarios,
            },
        }
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to configuration file.
            
        Returns:
            Configuration dictionary.
        """
        if not config_path:
            return {}
        
        config_path = Path(config_path)
        if not config_path.exists():
            logger.warning(f"Config file {config_path} does not exist.")
            return {}
        
        try:
            if config_path.suffix.lower() in (".yaml", ".yml"):
                with open(config_path, "r") as f:
                    return yaml.safe_load(f)
            elif config_path.suffix.lower() == ".json":
                with open(config_path, "r") as f:
                    return json.load(f)
            else:
                logger.warning(f"Unsupported config format: {config_path.suffix}")
                return {}
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            return {}
    
    def _prepare_output_dir(self, output_dir: Optional[str]) -> Path:
        """
        Prepare the output directory.
        
        Args:
            output_dir: Path to output directory.
            
        Returns:
            Path object for the output directory.
        """
        if output_dir:
            path = Path(output_dir)
            path.mkdir(parents=True, exist_ok=True)
            return path
        else:
            return self.results_dir
    
    @staticmethod
    def convert_paths(results):
        """
        Recursively convert any Path objects to strings for JSON serialization.
        Also handles non-serializable types like functions.
        
        Args:
            results: Object to convert (can be dict, list, Path, or other type).
            
        Returns:
            Object with all Path objects converted to strings and non-serializable objects converted to their string representation.
        """
        import types
        from pathlib import Path
        
        if isinstance(results, dict):
                return {key: TestFramework.convert_paths(value) for key, value in results.items()}
        elif isinstance(results, list):
                return [TestFramework.convert_paths(item) for item in results]
        elif isinstance(results, Path):
                return str(results)  # Convert Path object to string
        elif isinstance(results, (types.FunctionType, types.BuiltinFunctionType, types.MethodType)):
                return f"<function {results.__name__}>"  # Convert function object to string
        else:
                return results


    def _save_results(self, results: Dict[str, Any], output_dir: Path, name: str) -> None:
        """
        Save test results to files.
        """
        # Convert any Path objects in the results to strings
        results = self.convert_paths(results)

        # Save as JSON
        json_path = output_dir / f"{name}.json"
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2)
        
        # Save as YAML
        yaml_path = output_dir / f"{name}.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(results, f, default_flow_style=False)
        
        logger.info(f"Results saved to {json_path} and {yaml_path}")
        
        console = Console()
        console.print(f"[green]Results saved to:[/] {json_path}")

    def run_basic_tests(
        self,
        output_dir: Optional[str] = None,
        config_path: Optional[str] = None
        ) -> int:
                """
        Run a basic test suite.

        Args:
            output_dir (Optional[str]): Directory to save results.
            config_path (Optional[str]): Path to configuration file.

        Returns:
            int: Exit code (0 for success).
              """
                self.start_time = time.time()
                console.print("[bold blue]Running basic test suite...[/]")

                # Prepare output directory and load config
                output_path = self._prepare_output_dir(output_dir)
                self.config = self._load_config(config_path)

        # Run tests using shared progress bar
                with Progress() as progress:
                    task = progress.add_task("[green]Running tests...", total=3)

                    # 1. Run NIST benchmark
                    nist_module = self.modules["benchmark"]["nist"]
                    nist_results = nist_module.run_benchmark(basic=True)
                    progress.update(task, advance=1)

                    # 2. Run controlled test suite
                    test_suite_module = self.modules["controlled"]["test_suite"]
                    test_suite_results = test_suite_module.run_tests(basic=True)
                    progress.update(task, advance=1)

                    # 3. Run performance test
                    perf_module = self.modules["performance"]["resource_usage"]
                    perf_results = perf_module.run_test(
                        config=self.config,
                        base_dir=self.base_dir,
                        progress=progress,
                        basic=True
                    )
                    progress.update(task, advance=1)

                # Combine all results
                all_results = {
                        "nist_benchmark": nist_results,
                        "controlled_tests": test_suite_results,
                        "performance_tests": perf_results,
                        "metadata": {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "duration": time.time() - self.start_time,
                            "test_type": "basic"
                        }
                    }

                    # Save results
                self._save_results(all_results, output_path, "basic_test_results")

                # Display summary
                console.print(f"[bold green]✅ Basic tests completed in {time.time() - self.start_time:.2f} seconds![/]")
                console.print(f"[blue]📁 Results saved to:[/] {output_path}")

                return 0
   
    
    def run_comprehensive_tests(self, output_dir: Optional[str] = None, config_path: Optional[str] = None) -> int:
        """
        Run a comprehensive test suite.
        
        Args:
            output_dir: Directory to save results.
            config_path: Path to configuration file.
            
        Returns:
            Exit code (0 for success).
        """
        console.print("[bold blue]Running comprehensive test suite...[/]")
        console.print("[yellow]This may take a while...[/]")
        
        output_path = self._prepare_output_dir(output_dir)
        self.config = self._load_config(config_path)
        
        test_modules = [
            # Benchmarks
            ("NIST benchmark", self.modules["benchmark"]["nist"].run_benchmark),
            ("OWASP benchmark", self.modules["benchmark"]["owasp"].run_benchmark),
            ("CVE coverage", self.modules["benchmark"]["cve_coverage"].analyze_coverage),
            
            # Controlled tests
            ("Known vulnerability test suite", self.modules["controlled"]["test_suite"].run_tests),
            ("Blind tests", self.modules["controlled"]["blind_tests"].run_tests),
            ("Edge cases", self.modules["controlled"]["edge_cases"].run_tests),
            
            # Performance tests
            ("Load testing", self.modules["performance"]["load_testing"].run_test),
            ("Chaos engineering", self.modules["performance"]["chaos"].run_test),
            ("Resource usage", self.modules["performance"]["resource_usage"].run_test),
            
            # Comparative tests
            ("Tool comparison", self.modules["comparative"]["tool_matrix"].compare_tools),
            ("ROI analysis", self.modules["comparative"]["roi"].analyze_roi),
            ("Feature matrix", self.modules["comparative"]["feature_matrix"].generate_matrix),
            
            # Statistical analysis
            ("Monte Carlo simulation", self.modules["statistics"]["monte_carlo"].run_simulation),
            ("Correlation analysis", self.modules["statistics"]["correlation"].analyze_correlation),
            ("Confidence intervals", self.modules["statistics"]["confidence"].calculate_intervals),
        ]
        
        results = {}
        
        with Progress() as progress:
            task = progress.add_task("[green]Running tests...", total=len(test_modules))
            
            for name, func in test_modules:
                try:
                    results[name.lower().replace(" ", "_")] = func(comprehensive=True)
                except Exception as e:
                    logger.error(f"Error in {name}: {str(e)}")
                    results[name.lower().replace(" ", "_")] = {"error": str(e)}
                
                progress.update(task, advance=1)
        
        # Add metadata
        results["metadata"] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": time.time() - self.start_time,
            "test_type": "comprehensive",
        }
        
        # Save results
        self._save_results(results, output_path, "comprehensive_test_results")
        
        console.print(f"[bold green]Comprehensive tests completed in {time.time() - self.start_time:.2f} seconds![/]")
        console.print(f"Results saved to {output_path}")
        
        return 0
    
    def run_benchmarks(self, framework: str = "all", output_dir: Optional[str] = None) -> int:
        """
        Run benchmark tests.
        
        Args:
            framework: Benchmark framework to use.
            output_dir: Directory to save results.
            
        Returns:
            Exit code (0 for success).
        """
        console.print(f"[bold blue]Running benchmark tests: {framework}[/]")
        output_path = self._prepare_output_dir(output_dir)
        
        results = {}
        
        if framework == "all" or framework == "nist":
            console.print("Running NIST benchmark...")
            results["nist"] = self.modules["benchmark"]["nist"].run_benchmark()
        
        if framework == "all" or framework == "owasp":
            console.print("Running OWASP benchmark...")
            results["owasp"] = self.modules["benchmark"]["owasp"].run_benchmark()
        
        if framework == "all" or framework == "cve_coverage":
            console.print("Analyzing CVE coverage...")
            results["cve_coverage"] = self.modules["benchmark"]["cve_coverage"].analyze_coverage()
        
        # Add metadata
        results["metadata"] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": time.time() - self.start_time,
            "benchmark_type": framework,
        }
        
        # Save results
        self._save_results(results, output_path, f"benchmark_{framework}")
        
        console.print(f"[bold green]Benchmark tests completed in {time.time() - self.start_time:.2f} seconds![/]")
        console.print(f"Results saved to {output_path}")
        
        return 0
    
    def run_performance_tests(self, mode: str = "all", duration: int = 60, output_dir: Optional[str] = None) -> int:
        """
        Run performance tests.
        
        Args:
            mode: Performance test mode.
            duration: Test duration in seconds.
            output_dir: Directory to save results.
            
        Returns:
            Exit code (0 for success).
        """
        console.print(f"[bold blue]Running performance tests: {mode}[/]")
        output_path = self._prepare_output_dir(output_dir)
        
        results = {}
        
        if mode == "all" or mode == "load":
            console.print("Running load tests...")
            results["load"] = self.modules["performance"]["load_testing"].run_test(duration=duration)
        
        if mode == "all" or mode == "chaos":
            console.print("Running chaos tests...")
            results["chaos"] = self.modules["performance"]["chaos"].run_test(duration=duration)
        
        if mode == "all" or mode == "resource":
            console.print("Running resource usage tests...")
            results["resource"] = self.modules["performance"]["resource_usage"].run_test(duration=duration)
        
        # Add metadata
        results["metadata"] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": time.time() - self.start_time,
            "test_duration": duration,
            "performance_mode": mode,
        }
        
        # Save results
        self._save_results(results, output_path, f"performance_{mode}")
        
        console.print(f"[bold green]Performance tests completed in {time.time() - self.start_time:.2f} seconds![/]")
        console.print(f"Results saved to {output_path}")
        
        return 0
    
    def run_comparative_tests(self, tools: List[str], mode: str = "both", output_dir: Optional[str] = None) -> int:
        """
        Run comparative tests.
        
        Args:
            tools: List of tools to compare.
            mode: Comparison mode.
            output_dir: Directory to save results.
            
        Returns:
            Exit code (0 for success).
        """
        console.print(f"[bold blue]Running comparative tests: {mode}[/]")
        output_path = self._prepare_output_dir(output_dir)
        
        if not tools:
            tools = ["snyk", "dependabot", "owasp-dependency-check"]
            console.print(f"[yellow]No tools specified, using defaults: {', '.join(tools)}[/]")
        
        results = {}
        
        if mode == "both" or mode == "feature":
            console.print("Generating feature matrix...")
            results["feature_matrix"] = self.modules["comparative"]["feature_matrix"].generate_matrix(tools=tools)
        
        if mode == "both" or mode == "roi":
            console.print("Analyzing ROI...")
            results["roi"] = self.modules["comparative"]["roi"].analyze_roi(tools=tools)
        
        # Add tool comparison in both modes
        console.print("Comparing tools...")
        results["tool_matrix"] = self.modules["comparative"]["tool_matrix"].compare_tools(tools=tools)
        
        # Add metadata
        results["metadata"] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": time.time() - self.start_time,
            "comparison_mode": mode,
            "tools_compared": tools,
        }
        
        # Save results
        self._save_results(results, output_path, f"comparative_{mode}")
        
        console.print(f"[bold green]Comparative tests completed in {time.time() - self.start_time:.2f} seconds![/]")
        console.print(f"Results saved to {output_path}")
        
        return 0
    
    def generate_visualization(self, viz_type: str, input_dir: Optional[str] = None, output_dir: Optional[str] = None) -> int:
        """
        Generate visualizations.
        
        Args:
            viz_type: Visualization type.
            input_dir: Directory with input data.
            output_dir: Directory to save visualizations.
            
        Returns:
            Exit code (0 for success).
        """
        console.print(f"[bold blue]Generating visualization: {viz_type}[/]")
        output_path = self._prepare_output_dir(output_dir)
        
        # Use the results_dir if no input_dir is specified
        input_path = Path(input_dir) if input_dir else self.results_dir
        
        if not input_path.exists():
            console.print(f"[bold red]Error: Input directory {input_path} does not exist.[/]")
            return 1
        
        try:
            if viz_type == "dashboard":
                self.modules["visualization"]["dashboard"].generate_dashboard(input_path, output_path)
            elif viz_type == "report":
                self.modules["visualization"]["report_gen"].generate_report(input_path, output_path)
            elif viz_type == "leaderboard":
                self.modules["visualization"]["leaderboard"].generate_leaderboard(input_path, output_path)
            
            console.print(f"[bold green]Visualization generated successfully![/]")
            console.print(f"Output saved to {output_path}")
            
            return 0
            
        except Exception as e:
            console.print(f"[bold red]Error generating visualization: {str(e)}[/]")
            return 1
    
    def run_integration_tests(self, test_type: str = "all", output_dir: Optional[str] = None) -> int:
        """
        Run integration tests.
        
        Args:
            test_type: Integration test type.
            output_dir: Directory to save results.
            
        Returns:
            Exit code (0 for success).
        """
        console.print(f"[bold blue]Running integration tests: {test_type}[/]")
        output_path = self._prepare_output_dir(output_dir)
        
        results = {}
        
        if test_type == "all" or test_type == "ci_cd":
            console.print("Running CI/CD integration tests...")
            results["ci_cd"] = self.modules["integration"]["ci_cd"].run_tests()
        
        if test_type == "all" or test_type == "api":
            console.print("Running API integration tests...")
            results["api"] = self.modules["integration"]["api_tests"].run_tests()
        
        if test_type == "all" or test_type == "plugin":
            console.print("Running plugin integration tests...")
            results["plugin"] = self.modules["integration"]["plugin_tests"].run_tests()
        
        # Add metadata
        results["metadata"] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": time.time() - self.start_time,
            "integration_type": test_type,
        }
        
        # Save results
        self._save_results(results, output_path, f"integration_{test_type}")
        
        console.print(f"[bold green]Integration tests completed in {time.time() - self.start_time:.2f} seconds![/]")
        console.print(f"Results saved to {output_path}")
        
        return 0
    
    def run_demo(self, scenario: Optional[str] = None, interactive: bool = False) -> int:
        """
        Run demonstration.
        
        Args:
            scenario: Demonstration scenario to run.
            interactive: Whether to run in interactive mode.
            
        Returns:
            Exit code (0 for success).
        """
        console.print(f"[bold blue]Running demonstration{f': {scenario}' if scenario else ''}[/]")
        
        try:
            if scenario:
                # Run specific scenario
                self.modules["demo"]["scenarios"].run_scenario(scenario, interactive=interactive)
            elif interactive:
                # Run interactive demo
                self.modules["demo"]["participation"].run_interactive_demo()
            else:
                # Run live demo
                self.modules["demo"]["live_demo"].run_demo()
            
            console.print(f"[bold green]Demonstration completed successfully![/]")
            return 0
            
        except Exception as e:
            console.print(f"[bold red]Error running demonstration: {str(e)}[/]")
            return 1
