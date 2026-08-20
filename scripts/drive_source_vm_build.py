#!/usr/bin/env python3
"""Cross-compile a source recipe inside an isolated, offline QEMU VM.

Generic across (libc, arch) combos -- everything recipe-specific comes in as
an argument. The VM's guest arch is always the host's (x86_64, KVM): this
does NOT emulate the target CPU, it only isolates execution of the
downloaded, untrusted cross-compiler from the host. Network is brought up
only long enough to install Alpine's own signed make/gcc/musl-dev/gcompat
packages, then severed via the QEMU monitor before the toolchain ever runs.

Usage:
  drive_source_vm_build.py \
    --work WORK_DIR --iso alpine-virt.iso \
    --src-dir uClibc-0.9.30.1 --toolchain-dir powerpc-e500mc--uclibc--stable \
    --arch powerpc --cross-bin-prefix bin/powerpc-buildroot-linux-uclibc- \
    --library-path lib/libc.a

WORK_DIR must already contain src-dir/ (with a host-generated .config) and
toolchain-dir/, plus scratch.qcow2 (pre-created) and an out/ subdirectory.
Copies WORK_DIR/<library-path relative to src build root> to WORK_DIR/out/.
"""
import argparse
import pexpect
import socket
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--work", required=True)
parser.add_argument("--iso", required=True)
parser.add_argument("--src-dir", required=True, help="source tree dir name under --work")
parser.add_argument("--toolchain-dir", required=True, help="toolchain dir name under --work")
parser.add_argument("--arch", required=True, help="value for make ARCH=")
parser.add_argument(
    "--cross-bin-prefix", required=True,
    help="cross compiler prefix relative to the toolchain dir, e.g. bin/powerpc-buildroot-linux-uclibc-",
)
parser.add_argument("--library-path", required=True, help="built library path relative to the source build root, e.g. lib/libc.a")
parser.add_argument("--jobs", default="4")  # matches the VM's hardcoded -smp 4
args = parser.parse_args()

WORK = args.work
PROMPT = r"localhost:.*# $"
MONSOCK = f"{WORK}/qmon.sock"

cmd = (
    f"qemu-system-x86_64 -m 2048 -smp 4 -enable-kvm -cpu host -nographic "
    f"-drive file={WORK}/scratch.qcow2,if=virtio,format=qcow2 "
    f"-cdrom {args.iso} -boot d "
    f"-virtfs local,path={WORK},mount_tag=ro9p,security_model=none,readonly=on "
    f"-virtfs local,path={WORK}/out,mount_tag=rwout,security_model=none "
    f"-netdev user,id=net0 -device virtio-net-pci,netdev=net0,id=netdev0 "
    f"-monitor unix:{MONSOCK},server,nowait"
)
print("LAUNCH:", cmd, flush=True)

child = pexpect.spawn(cmd, timeout=60, encoding="utf-8", logfile=sys.stdout)

child.expect("boot:", timeout=60)
# alpine-virt's syslinux.cfg LABEL is "virt", not "linux" -- sending the
# wrong label leaves isolinux stuck retrying the boot: prompt forever.
child.sendline("virt console=ttyS0,115200n8")

child.expect("login:", timeout=120)
child.sendline("root")


def wait_prompt(timeout):
    # Alpine's ash emits a one-time ANSI cursor-position query (\x1b[6n) at
    # the very first prompt; answer it once, don't wait for a second prompt
    # draw (the real prompt text is already on screen by then).
    idx = child.expect([PROMPT, r"\x1b\[6n"], timeout=timeout)
    if idx == 1:
        child.send("\x1b[24;80R")


wait_prompt(120)
print(">>> got initial prompt", flush=True)


def run(c, timeout=60, expect_prompt=True):
    child.sendline(c)
    if expect_prompt:
        wait_prompt(timeout)


# --- phase 1: network ON, Alpine's own signed CDN only, to install build tools ---
run("ip link set eth0 up", timeout=15)
run("udhcpc -i eth0", timeout=30)
run("echo 'https://dl-cdn.alpinelinux.org/alpine/v3.19/main' > /etc/apk/repositories")
run("apk update", timeout=60)
# gcompat: many prebuilt cross-toolchains ship glibc-linked x86_64 binaries;
# Alpine is musl-based and has no glibc loader without it.
run("apk add --no-cache make gcc musl-dev gcompat", timeout=90)
run("which make gcc && make --version | head -1 && gcc --version | head -1")

# --- cut the network before touching anything from the downloaded toolchain ---
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(20):
    try:
        s.connect(MONSOCK)
        break
    except OSError:
        time.sleep(0.5)
else:
    raise RuntimeError("could not connect to qemu monitor")
s.recv(4096)
s.sendall(b"device_del netdev0\n")
time.sleep(1)
print("MONITOR:", s.recv(4096), flush=True)
s.sendall(b"netdev_del net0\n")
time.sleep(1)
print("MONITOR:", s.recv(4096), flush=True)
s.close()

run("ip link", timeout=15)
print(">>> network removed, proceeding offline", flush=True)

run("mkdir -p /mnt/ro /mnt/out")
run("mount -t 9p -o trans=virtio,version=9p2000.L,ro ro9p /mnt/ro")
run("mount -t 9p -o trans=virtio,version=9p2000.L rwout /mnt/out")
run(f"cp -r /mnt/ro/{args.src_dir} /root/build", timeout=60)
run(f"cp -r /mnt/ro/{args.toolchain_dir} /root/toolchain", timeout=180)
run("ls -la /root/build/.config")
print(">>> starting build (host generated .config, no cross-compiler involved there)", flush=True)
run(
    f"cd /root/build && make ARCH={args.arch} "
    f"CROSS=/root/toolchain/{args.cross_bin_prefix} -j{args.jobs} "
    "> /root/build.log 2>&1 ; echo BUILD_EXIT=$?",
    timeout=2400,
)
run("tail -c 300000 /root/build.log")
print(">>> build step done", flush=True)
run(f"cp /root/build/{args.library_path} /mnt/out/ && ls -la /mnt/out")
run("poweroff", expect_prompt=False)
try:
    child.expect(pexpect.EOF, timeout=60)
except Exception as e:
    print("EOF wait exception:", e, flush=True)
