import os
import subprocess
from multiprocessing import Pool

targets = [
    "0e0328dc8084e6203c09a3e5ea1539f8",
    "1ed17cd8d521a329e62321797547a03c",
    "1f47ecc10bc008ad26e504897b940f22",
    "59ed6584c46d0acf17196546091f4f17",
    "692772873985269ccfa0c3df17fa15b4",
    "8e7e88377aae5459d5acaceae91a80ee",
    "af764b5e68436e284cf8f62ba5c77063",
    "f9374562d78ad41f64da5e83b2be7fc7"
]

dir1 = os.path.expanduser('~/data/malware/mirai3/unpacked')

def process_sample(sample):
    target_path = os.path.join(dir1, sample)
    report_file = f"artifacts/sweep_reports_large/{sample}.json"
    
    env = os.environ.copy()
    env["GHIDRA_HEADLESS"] = "/opt/ghidra/ghidra_12.0.4_PUBLIC/support/analyzeHeadless"
    subprocess.run([
        "uv", "run", "fidb-poc", "hunt", target_path, 
        "--fidb-dir", "artifacts/fidbs", 
        "--max-candidates", "20", 
        "--guess", "uclibc",
        "--guess", "openssl",
        "--guess", "curl",
        "--guess", "zlib",
        "--guess", "libpcap",
        "--guess", "mbedtls",
        "--report", report_file
    ], capture_output=True, env=env)
    return sample

if __name__ == '__main__':
    os.makedirs("artifacts/sweep_reports_large", exist_ok=True)
    with Pool(1) as p:
        for res in p.imap_unordered(process_sample, targets):
            print(f"Processed {res}")
