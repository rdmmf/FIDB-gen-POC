import os
import subprocess
from multiprocessing import Pool

# Next 25 binaries after the top 8
targets = [
    "baf3d3dfbc28ff11ce1063eb83a0a686",
    "e2d9d09de0da60b37bf485dafd26a1bf",
    "673c690dbad12aa01e0d0623b280f611",
    "412addf4c974ec7cb0eeff939e7e60a7",
    "8b8f149222295214def7f412169f08c5",
    "105ba8c91db717917a93564044333b16",
    "315a79aafaab2547380c1d3cac678be7",
    "16c2addf057b3e3b2703500462e38c1c",
    "a4ac8d1efb14add8b245976f2100c6c5",
    "3a803f13f69a9d848607c4ff087bf51c",
    "bff593e83c967c63a757e60be854bc75",
    "762ef22840a768874c52007a44cfb639",
    "20532b27d976e865aceb0ec11d9f2ff8",
    "76967ae237e049914ddf302f6937ae06",
    "aa815409644f5fe353c8442b754d018e",
    "4c5dba456d5f631d9c32e1d7c93acfc5",
    "b266a7f254f58ba8976d54b10b946306",
    "91e42ffd877e35670b9a66d860e32444",
    "60a848d364d7094870023ec831a2dfe2",
    "0cf8ec8d5af0972b66ad9abdd276e22a"
]

dir1 = os.path.expanduser('~/data/malware/mirai3/unpacked')

def process_sample(sample):
    target_path = os.path.join(dir1, sample)
    report_file = f"artifacts/sweep_reports_unexpected/{sample}.json"
    if os.path.exists(report_file):
        return sample
        
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
        "--guess", "mbedtls",
        "--guess", "libssh2",
        "--guess", "libpcap",
        "--report", report_file
    ], capture_output=True, env=env)
    return sample

if __name__ == '__main__':
    os.makedirs("artifacts/sweep_reports_unexpected", exist_ok=True)
    with Pool(1) as p:
        for res in p.imap_unordered(process_sample, targets):
            print(f"Processed {res}")
