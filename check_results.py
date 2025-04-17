import os
import json
from pathlib import Path

def check_directory(dir_path):
    path = Path(dir_path)
    print(f"Checking directory: {path} (exists: {path.exists()})")
    
    if not path.exists():
        print("Directory doesn't exist!")
        return
    
    # List all files and directories
    print("\nContents:")
    for item in path.iterdir():
        if item.is_dir():
            print(f"  📁 {item.name}/")
            # List files in subdirectory
            for subitem in item.iterdir():
                print(f"     - {subitem.name}")
        else:
            print(f"  📄 {item.name}")
    
    # Check for JSON files
    json_files = list(path.glob("**/*.json"))
    print(f"\nFound {len(json_files)} JSON files")
    
    # Try to load one JSON file as example
    if json_files:
        example_file = json_files[0]
        print(f"\nExample file: {example_file}")
        try:
            with open(example_file, "r") as f:
                data = json.load(f)
            print(f"Successfully loaded JSON with keys: {list(data.keys())}")
        except Exception as e:
            print(f"Error loading file: {e}")

# Replace with your actual results path
results_path = r"C:/Users/maxgr/Testing/ossv_testing/ossv_results"
check_directory(results_path)