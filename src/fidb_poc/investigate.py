"""Evidence-driven target investigation and package-family hypotheses."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re

from .elf import ElfFacts, inspect_elf


PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}
SIGNAL_WORDS = (
    "/proc/", "/dev/", "/bin/", "busybox", "watchdog", "password", "login",
    "username", "system", "shell", "infected", "botnet", "telnet", "http", "libc",
)
PACKAGE_MARKERS = {
    "zlib": ("zlib", "inflate", "deflate", "gzopen", "adler32"),
    "openssl": ("openssl", "libcrypto", "libssl", "ssl_connect", "x509_"),
    "mbedtls": ("mbedtls", "polarssl"),
    "libcurl": ("libcurl", "curl_easy_"),
    "libpcap": ("libpcap", "pcap_open_"),
}


@dataclass(frozen=True)
class Decoding:
    encoding: str
    key: int
    score: int
    strings: tuple[str, ...]


@dataclass(frozen=True)
class Hypothesis:
    family: str
    confidence: str
    disposition: str
    reason: str
    candidate_packages: tuple[str, ...]


@dataclass(frozen=True)
class Investigation:
    target: ElfFacts
    decoded_strings: tuple[Decoding, ...]
    insights: tuple[str, ...]
    hypotheses: tuple[Hypothesis, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _decode_with_key(data: bytes, key: int, minimum: int = 5) -> tuple[str, ...]:
    strings: list[str] = []
    current = bytearray()
    for original in data:
        value = original ^ key
        if original == key:
            if len(current) >= minimum:
                strings.append(current.decode("ascii"))
            current.clear()
        elif value in PRINTABLE:
            current.append(value)
        else:
            current.clear()
    return tuple(strings)


def _score(strings: tuple[str, ...]) -> int:
    joined = "\n".join(strings).lower()
    signal = sum(8 for word in SIGNAL_WORDS if word in joined)
    natural_words = {
        "your", "device", "just", "infected", "authentication", "attempt", "failed",
        "password", "login", "username", "account", "enable", "system", "shell",
    }
    language = sum(1 for word in re.findall(r"[a-z]{4,}", joined) if word in natural_words)
    return signal + language + min(len(strings), 20)


def find_decodings(data: bytes, limit: int = 3) -> tuple[Decoding, ...]:
    data = data[:500000]  # LIMIT SIZE for speed
    candidates: list[Decoding] = []
    for key in range(1, 256):
        strings = _decode_with_key(data, key)
        score = _score(strings)
        if score < 24:
            continue
        useful = tuple(
            value for value in strings
            if any(word in value.lower() for word in SIGNAL_WORDS)
            or len(re.findall(r"[A-Za-z]{4,}", value)) >= 2
        )
        candidates.append(Decoding("single-byte-xor", key, score, useful[:80]))
    candidates.sort(key=lambda item: (-item.score, item.key))
    return tuple(candidates[:limit])


def investigate(path: str | Path) -> Investigation:
    target_path = Path(path).expanduser()
    facts = inspect_elf(target_path)
    data = target_path.read_bytes()
    decodings = find_decodings(data)
    decoded_text = "\n".join(
        value.lower() for decoding in decodings for value in decoding.strings
    )

    insights: list[str] = []
    if decodings:
        best = decodings[0]
        insights.append(
            f"Detected {best.encoding} strings with key 0x{best.key:02x} "
            f"(evidence score {best.score})."
        )
    if "busybox" in decoded_text and "/proc/" in decoded_text:
        insights.append("Decoded process-management and BusyBox strings support a Mirai-family payload.")
    if "watchdog" in decoded_text:
        insights.append("Decoded watchdog device paths indicate embedded Linux persistence handling.")
    if facts.statically_linked:
        insights.append("Static linkage makes the C runtime the highest-value initial FID family.")

    hypotheses: list[Hypothesis] = []
    libc_evidence = "libc" in decoded_text or b"libc" in data.lower()
    if facts.statically_linked:
        hypotheses.extend((
            Hypothesis(
                "c-runtime", "high" if libc_evidence else "medium", "build",
                "The static target references libc but exposes no runtime identity; bounded "
                "uClibc, musl, and glibc variants can discriminate it.",
                ("uclibc", "musl", "glibc"),
            ),
            Hypothesis(
                "compiler-runtime", "low", "build-after-c-runtime",
                "A static C executable normally embeds compiler support routines, but .comment is absent.",
                ("libgcc",),
            ),
        ))

    combined = data.lower() + decoded_text.encode("utf-8", errors="ignore")
    for package, markers in PACKAGE_MARKERS.items():
        found = [marker for marker in markers if marker.encode("ascii") in combined]
        hypotheses.append(Hypothesis(
            package,
            "medium" if found else "none",
            "build" if found else "not-scheduled",
            (f"Observed package markers: {', '.join(found)}." if found else
             "No package-specific marker was observed; absence is not proof of exclusion."),
            (package,) if found else (),
        ))

    return Investigation(facts, decodings, tuple(insights), tuple(hypotheses))
