#!/usr/bin/env python3
"""Cross-compile a source recipe inside an isolated, offline QEMU VM.

Generic across (libc, arch) combos -- everything recipe-specific comes in as
an argument. The VM's guest arch is always the host's (x86_64, KVM): this
does NOT emulate the target CPU, it only isolates execution of the
downloaded, untrusted cross-compiler (and, for --build-adapter plain_make,
untrusted source) from the host. Network is brought up only long enough to
install Alpine's own signed make/gcc/musl-dev/gcompat packages (plus unzip,
if --payload-kind zip), then severed via the QEMU monitor before the
toolchain or source is ever touched.

--payload-archive/--payload-kind extract an untrusted source archive
*inside the VM* instead of on the host -- same isolation argument that
already covers running an untrusted compiler: a parser exploit in the
disposable, network-severed guest is not a host compromise. Alpine ships
`unzip` in its main repo, so zip-packaged sources are supported this way;
it does not ship `unrar`/`p7zip`, so rar-packaged sources have no clean
signed-package extractor here and are out of scope (see
recipes/malware/README.md). --src-dir (host pre-extracted) stays the path
for tar-based sources, unchanged.

--build-adapter selects the fixed, reviewed command sequence run inside the
VM -- this script never accepts a caller-supplied shell command, matching
the "recipe cannot supply a command" invariant adapters.py enforces on the
native build path. Adding a new source shape (a different malware fork's
actual build system) means adding a new named adapter function here, not
widening this to accept arbitrary text.

  uclibc_defconfig  existing uClibc-family flow: make ARCH=... CROSS=...
                     against a host-generated .config (kconfig-based libc
                     source trees only).
  plain_make         make CC=<cross_bin_prefix>gcc in the source root, no
                     ARCH=/CROSS=/.config. Verify against the ACTUAL
                     Makefile of any given malware fork before trusting
                     output -- this is a sensible default shape, not a
                     verified match for a specific fork's build system.
  mirai_bot_gcc      matches a specific real fork's actual build system
                     (a direct gcc invocation, no Makefile) -- see the
                     recipe that uses this adapter for the exact source
                     and command this was verified against.

Usage:
  drive_source_vm_build.py \
    --work WORK_DIR --iso alpine-virt.iso \
    --src-dir uClibc-0.9.30.1 --toolchain-dir powerpc-e500mc--uclibc--stable \
    --build-adapter uclibc_defconfig \
    --arch powerpc --cross-bin-prefix bin/powerpc-buildroot-linux-uclibc- \
    --output-relpath lib/libc.a

WORK_DIR must already contain src-dir/ (with a host-generated .config for
uclibc_defconfig; untouched for plain_make) and toolchain-dir/, plus
scratch.qcow2 (pre-created) and an out/ subdirectory. Copies
WORK_DIR/<output-relpath relative to src build root> to WORK_DIR/out/.
"""
import argparse
import pexpect
import socket
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--work", required=True)
parser.add_argument("--iso", required=True)
parser.add_argument("--src-dir", help="source tree dir name under --work, pre-extracted on host")
parser.add_argument(
    "--payload-archive",
    help="raw, unverified-format source archive filename under --work; extracted "
    "inside the VM instead of on the host. Mutually exclusive with --src-dir.",
)
parser.add_argument("--payload-kind", choices=("zip",), help="required with --payload-archive")
parser.add_argument("--toolchain-dir", required=True, help="toolchain dir name under --work")
parser.add_argument(
    "--build-adapter",
    choices=("uclibc_defconfig", "plain_make", "mirai_bot_gcc", "openssl", "configure", "configure_zlib", "configure_libpcap", "make_mbedtls", "configure_libssh2"),
    default="uclibc_defconfig",
)
parser.add_argument(
    "--arch", help="value for make ARCH= (uclibc_defconfig) or -DMIRAI_BOT_ARCH= (mirai_bot_gcc)"
)
parser.add_argument(
    "--cross-bin-prefix", required=True,
    help="cross compiler prefix relative to the toolchain dir, e.g. bin/powerpc-buildroot-linux-uclibc-",
)
parser.add_argument(
    "--output-relpath", required=True,
    help="built artifact path relative to the source build root to copy out, e.g. lib/libc.a",
)
parser.add_argument("--jobs", default="4")  # matches the VM's hardcoded -smp 4
args = parser.parse_args()
if args.build_adapter in ("uclibc_defconfig", "mirai_bot_gcc") and not args.arch:
    parser.error(f"--arch is required for --build-adapter {args.build_adapter}")
if bool(args.src_dir) == bool(args.payload_archive):
    parser.error("exactly one of --src-dir or --payload-archive is required")
if args.payload_archive and not args.payload_kind:
    parser.error("--payload-kind is required with --payload-archive")

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
packages = "make gcc musl-dev gcompat perl linux-headers"
if args.payload_kind == "zip":
    packages += " unzip"
run(f"apk add --no-cache {packages}", timeout=90)
run("which make gcc && make --version | head -1 && gcc --version | head -1")

print(">>> injecting obstack shim for older gcc", flush=True)
run("echo 'int obstack_vprintf(void *o, const char *f, void * ap) { return 0; }' > /root/obstack.c")
run("echo 'int obstack_printf(void *o, const char *f, ...) { return 0; }' >> /root/obstack.c")
run("gcc -shared -fPIC /root/obstack.c -o /root/libobstack.so")
run("export LD_PRELOAD=/root/libobstack.so")

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
if args.src_dir:
    run(f"cp -r /mnt/ro/{args.src_dir} /root/build", timeout=60)
else:
    # Untrusted archive, never parsed on the host: copy the raw bytes in and
    # extract with Alpine's own signed unzip, inside the disposable,
    # already-offline guest.
    run("mkdir -p /root/payload", timeout=15)
    run(f"unzip -q /mnt/ro/{args.payload_archive} -d /root/payload", timeout=120)
    run("ls -la /root/payload")
    # exit 1 must stay inside `sh -c`, not the interactive login shell, or a
    # layout mismatch would kill the whole console session instead of just
    # failing this step.
    run(
        "sh -c 'set -- /root/payload/*/; "
        '[ "$#" -eq 1 ] && [ -d "$1" ] || { echo PAYLOAD_LAYOUT_ERROR; exit 1; }; '
        "mv \"$1\" /root/build'",
        timeout=30,
    )
run(f"cp -r /mnt/ro/{args.toolchain_dir} /root/toolchain", timeout=180)

if args.build_adapter == "uclibc_defconfig":
    run("ls -la /root/build/.config")
    print(">>> starting build (host generated .config, no cross-compiler involved there)", flush=True)
    build_command = (
        f"cd /root/build && make ARCH={args.arch} "
        f"CROSS=/root/toolchain/{args.cross_bin_prefix} -j{args.jobs} "
        "> /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "plain_make":
    print(">>> starting build (plain make, no ARCH=/.config)", flush=True)
    build_command = (
        f"cd /root/build && make CC=/root/toolchain/{args.cross_bin_prefix}gcc "
        f"-j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "openssl":
    print(">>> starting build (openssl ./Configure)", flush=True)
    target = "linux-generic64" if "64" in args.arch else "linux-generic32"
    build_command = (
        f"cd /root/build && "
        f"./Configure {target} no-async --cross-compile-prefix=/root/toolchain/{args.cross_bin_prefix} "
        f"> /root/config.log 2>&1 ; cat /root/config.log ; "
        f"make -j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "configure":
    print(">>> starting build (standard ./configure)", flush=True)
    build_command = (
        f"cd /root/build && "
        f"CC=/root/toolchain/{args.cross_bin_prefix}gcc "
        f"./configure --host={args.arch}-linux --disable-shared --without-ssl --without-zlib "
        f"> /root/config.log 2>&1 ; cat /root/config.log ; "
        f"make -j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "configure_zlib":
    print(">>> starting build (zlib ./configure)", flush=True)
    build_command = (
        f"cd /root/build && "
        f"CC=/root/toolchain/{args.cross_bin_prefix}gcc "
        f"./configure --static "
        f"> /root/config.log 2>&1 ; cat /root/config.log ; "
        f"make -j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "configure_libssh2":
    print(">>> starting build (libssh2 ./configure)", flush=True)
    build_command = (
        f"cd /root/build && "
        f"CC=/root/toolchain/{args.cross_bin_prefix}gcc "
        f"./configure --host={args.arch}-linux --disable-shared --without-openssl --without-libgcrypt "
        f"> /root/config.log 2>&1 ; cat /root/config.log ; "
        f"make -j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "configure_libpcap":
    print(">>> starting build (libpcap ./configure)", flush=True)
    build_command = (
        f"cd /root/build && "
        f"CC=/root/toolchain/{args.cross_bin_prefix}gcc "
        f"./configure --host={args.arch}-linux --disable-shared "
        f"> /root/config.log 2>&1 ; cat /root/config.log ; "
        f"make -j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )
elif args.build_adapter == "make_mbedtls":
    print(">>> starting build (mbedtls make)", flush=True)
    build_command = (
        f"cd /root/build && "
        f"CC=/root/toolchain/{args.cross_bin_prefix}gcc "
        f"make no_test lib -j{args.jobs} > /root/build.log 2>&1 ; echo BUILD_EXIT=$?"
    )

run(build_command, timeout=2400)
run("tail -c 300000 /root/build.log")
print(">>> build step done", flush=True)
run(f"cp /root/build/{args.output_relpath} /mnt/out/ && ls -la /mnt/out")
run("poweroff", expect_prompt=False)
try:
    child.expect(pexpect.EOF, timeout=60)
except Exception as e:
    print("EOF wait exception:", e, flush=True)
