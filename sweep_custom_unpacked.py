import os
import subprocess
import json
import csv
from multiprocessing import Pool

output_csv = 'artifacts/hunt_sweep_results.csv'
rows = list(csv.DictReader(open(output_csv)))
unmatched = [r['sample'] for r in rows if r['status'] == 'success' and r['match'] == 'false']

dir1 = os.path.expanduser('~/data/malware/mirai3/unpacked')
dir2 = os.path.expanduser('~/data/malware/mirai3/samples/qemu-unpacked')

found = []
for sample in unmatched:
    if os.path.exists(os.path.join(dir1, sample)):
        found.append((sample, os.path.join(dir1, sample)))
    elif os.path.exists(os.path.join(dir2, sample)):
        found.append((sample, os.path.join(dir2, sample)))

def process_sample(item):
    sample, target_path = item
    report_file = f"artifacts/sweep_reports/{sample}.json"
    env = os.environ.copy()
    env["GHIDRA_HEADLESS"] = "/opt/ghidra/ghidra_12.0.4_PUBLIC/support/analyzeHeadless"
    subprocess.run([
        "uv", "run", "fidb-poc", "hunt", target_path, 
        "--fidb-dir", "artifacts/fidbs", 
        "--max-candidates", "20", 
        "--report", report_file
    ], capture_output=True, env=env)
    return sample

if __name__ == '__main__':
    with Pool(4) as p:
        for res in p.imap_unordered(process_sample, found):
            print(f"Processed {res}")
