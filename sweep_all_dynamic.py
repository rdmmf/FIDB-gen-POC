import os
import subprocess
from multiprocessing import Pool
from pathlib import Path

def get_all_recipes():
    recipe_dir = Path("recipes/libs")
    return [p.stem for p in recipe_dir.glob("*.toml")]

def process_sample(sample_path):
    sample = os.path.basename(sample_path)
    report_file = f"artifacts/sweep_reports_dynamic/{sample}.json"
    if os.path.exists(report_file):
        return sample
        
    recipes = get_all_recipes()
    guess_args = []
    for r in recipes:
        guess_args.extend(["--guess", r])
        
    env = os.environ.copy()
    env["GHIDRA_HEADLESS"] = "/opt/ghidra/ghidra_12.0.4_PUBLIC/support/analyzeHeadless"
    
    cmd = [
        "uv", "run", "fidb-poc", "hunt", sample_path, 
        "--fidb-dir", "artifacts/fidbs", 
        "--max-candidates", "20", 
        "--report", report_file
    ] + guess_args
    
    subprocess.run(cmd, capture_output=True, env=env)
    return sample

if __name__ == '__main__':
    os.makedirs("artifacts/sweep_reports_dynamic", exist_ok=True)
    # Just an example script - they can feed their dataset into a list here
    print(f"Dynamic sweep configured for recipes: {get_all_recipes()}")
