import os
import subprocess
from multiprocessing import Pool
from pathlib import Path

def get_all_recipes():
    recipe_dir = Path("recipes/libs")
    return [p.stem for p in recipe_dir.glob("*.toml")]

def get_elf_files():
    cmd = "find ~/data/malware/mirai3 ~/data/malware/random_payloads_0gias -type f -exec file {} + | grep -i 'ELF' | cut -d: -f1"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return [line.strip() for line in output.split('\n') if line.strip()]

def process_sample(sample_path):
    sample = os.path.basename(sample_path)
    # create a hash or safe name to avoid collisions if multiple dirs have same filename
    # actually, usually they are md5/sha256 hashes anyway, but let's be safe
    safe_name = sample_path.replace("/", "_").strip("_")[-100:] 
    
    report_file = f"artifacts/sweep_reports_massive/{safe_name}.json"
    if os.path.exists(report_file):
        return sample_path
        
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
    
    # We don't want stdout to spam, so capture it
    try:
        subprocess.run(cmd, capture_output=True, env=env, timeout=1200) # 20 mins max per binary
    except subprocess.TimeoutExpired:
        pass
        
    return sample_path

if __name__ == '__main__':
    os.makedirs("artifacts/sweep_reports_massive", exist_ok=True)
    targets = get_elf_files()
    print(f"Loaded {len(targets)} ELF binaries for massive sweep.")
    
    # Use 4 processes for parallel hunting
    with Pool(4) as p:
        for i, res in enumerate(p.imap_unordered(process_sample, targets)):
            if i % 10 == 0:
                print(f"Processed {i}/{len(targets)}: {os.path.basename(res)}")
