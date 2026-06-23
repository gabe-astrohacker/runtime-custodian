#!/usr/bin/env python3
"""Generate reproducible binwalk test samples.

The committed `bzip2.bin` / `yaffs2.bin` / `zip.bin` fixtures each contain a
single format and are opaque (no provenance). Binwalk's real job, and the
process-heavy workload this monitor is meant to observe, is *recursively
extracting many embedded formats* from a firmware-like image — under
`binwalk -e` each recognised format spawns its own extractor process (gzip,
unzip, bzip2, ...), which is exactly the exec/fork event stream the runtime
monitor attests.

This script builds larger, more diverse, fully deterministic samples so the
binwalk performance experiments exercise that recursive-extraction path and so
the fixtures have reproducible provenance (the manifest records each sample's
sha256). Determinism: all content is fixed and compression is invoked with
timestamp-free options, so regenerating yields byte-identical output (and the
same sha256) on a given Python/zlib.

Output goes to `samples/` (gitignored) by default; point the binwalk experiment
at one with `--input samples/firmware-composite.bin`.

    ./scripts/gen_binwalk_samples.py                 # 4 MiB composite + manifest
    ./scripts/gen_binwalk_samples.py --size-mib 16   # bigger, for throughput runs
    ./scripts/gen_binwalk_samples.py --all           # also emit single-format blobs
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import struct
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

# A fixed DOS timestamp (1980-01-01) and zeroed unix mtime keep archive headers
# free of wall-clock time, so output is byte-stable across runs.
ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
FIXED_MTIME = 0

# Compressible filler: deterministic pseudo-English so the compressors produce
# realistic (non-degenerate) streams that binwalk's extractors will accept.
_LOREM = (
    b"runtime custodian firmware image segment. embedded payload follows with "
    b"deterministic content so the archive compresses to a stable byte stream. "
)


def compressible_blob(n: int) -> bytes:
    """`n` bytes of deterministic, compressible content."""
    reps = (n // len(_LOREM)) + 1
    return (_LOREM * reps)[:n]


def entropy_blob(n: int, label: bytes) -> bytes:
    """`n` bytes of deterministic high-entropy filler (SHA-256 keystream).

    High entropy keeps binwalk from trying to descend into the padding while
    making the image look like real firmware (random-looking gaps between
    recognised sections). Deterministic across Python versions.
    """
    out = bytearray()
    counter = 0
    while len(out) < n:
        out.extend(hashlib.sha256(label + struct.pack("<Q", counter)).digest())
        counter += 1
    return bytes(out[:n])


def gzip_stream(payload: bytes) -> bytes:
    # mtime=0 removes the timestamp the gzip header would otherwise embed.
    return gzip.compress(payload, compresslevel=9, mtime=0)


def bzip2_stream(payload: bytes) -> bytes:
    return bz2.compress(payload, compresslevel=9)


def xz_stream(payload: bytes) -> bytes:
    return lzma.compress(payload, format=lzma.FORMAT_XZ, preset=6)


def zip_archive(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            info = zipfile.ZipInfo(filename=name, date_time=ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # unix, fixed so the host OS doesn't leak in
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def tar_archive(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = FIXED_MTIME
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def cpio_newc_archive(members: list[tuple[str, bytes]]) -> bytes:
    """Minimal deterministic `newc` cpio (initramfs magic 070701)."""

    def field(value: int) -> bytes:
        return b"%08x" % (value & 0xFFFFFFFF)

    def pad4(data: bytes) -> bytes:
        return data + b"\x00" * ((-len(data)) % 4)

    def entry(ino: int, name: str, data: bytes) -> bytes:
        name_bytes = name.encode() + b"\x00"
        header = (
            b"070701"
            + field(ino)
            + field(0o100644)  # mode: regular file
            + field(0)  # uid
            + field(0)  # gid
            + field(1)  # nlink
            + field(FIXED_MTIME)
            + field(len(data))
            + field(0) * 4  # dev/rdev major/minor
            + field(len(name_bytes))
            + field(0)  # check
        )
        return pad4(header + name_bytes) + pad4(data)

    out = bytearray()
    for i, (name, data) in enumerate(members, start=1):
        out += entry(i, name, data)
    # Trailer marks end of archive.
    out += entry(0, "TRAILER!!!", b"")
    return bytes(out)


# Small magic-only headers for formats binwalk *identifies* (added for signature
# diversity / detection counts; not meant to be extracted).
PNG_MAGIC = bytes.fromhex("89504e470d0a1a0a") + b"\x00\x00\x00\rIHDR"
JPEG_MAGIC = bytes.fromhex("ffd8ffe000104a46494600")
GIF_MAGIC = b"GIF89a"
ELF_MAGIC = bytes.fromhex("7f454c46") + bytes([2, 1, 1, 0]) + b"\x00" * 8
UIMAGE_MAGIC = struct.pack(">I", 0x27051956)  # U-Boot uImage header magic


@dataclass
class Section:
    label: str
    data: bytes
    gap: int = 4096  # entropy padding that follows this section


@dataclass
class Sample:
    name: str
    data: bytes
    contents: list[str] = field(default_factory=list)


def build_composite(size_bytes: int) -> Sample:
    """A firmware-like image concatenating many extractable + identifiable formats."""
    payload = compressible_blob(8192)

    # A zip that itself contains a gzip member, so `binwalk -e` recurses a level.
    nested_zip = zip_archive(
        [
            ("etc/config.txt", payload),
            ("etc/banner.gz", gzip_stream(payload)),
            ("bin/init", ELF_MAGIC + entropy_blob(256, b"init")),
        ]
    )

    sections = [
        Section("uimage-header", UIMAGE_MAGIC + b"\x00" * 60 + b"kernel\x00"),
        Section("gzip", gzip_stream(payload * 3)),
        Section("bzip2", bzip2_stream(payload * 3)),
        Section("xz", xz_stream(payload * 3)),
        Section("zip-nested", nested_zip),
        Section("tar", tar_archive([("rootfs/passwd", payload), ("rootfs/hosts", payload)])),
        Section("cpio-initramfs", cpio_newc_archive([("init", payload), ("README", payload)])),
        Section("png", PNG_MAGIC + entropy_blob(512, b"png")),
        Section("jpeg", JPEG_MAGIC + entropy_blob(512, b"jpg")),
        Section("gif", GIF_MAGIC + entropy_blob(256, b"gif")),
        Section("elf", ELF_MAGIC + entropy_blob(1024, b"elf")),
    ]

    out = bytearray()
    contents: list[str] = []
    for s in sections:
        out += s.data
        out += entropy_blob(s.gap, b"gap-" + s.label.encode())
        contents.append(s.label)

    # Pad with deterministic entropy to the requested size (firmware tail).
    if len(out) < size_bytes:
        out += entropy_blob(size_bytes - len(out), b"tail-pad")
    # If the structured content already exceeds the target, keep it intact
    # rather than truncating a format mid-stream.

    return Sample("firmware-composite.bin", bytes(out), contents)


def build_dense(count: int, payload_size: int = 64) -> Sample:
    """A high-event firmware image: a *branching tree of nested zips* so that
    recursive extraction (``binwalk -Me``) forks an external ``unzip`` per node
    and descends, yielding ~`count` external extraction execs — the exec/event
    stream that stresses the monitor's per-event path (e.g. TPM extension).

    Why this shape: binwalk extracts zip *externally* (``unzip``) and Matryoshka
    recurses into each extracted archive, so a tree of Z nested zips forks ~Z
    ``unzip`` processes (empirically verified: a depth-8 binary branching tree =
    255 zips => 255 ``unzip`` execs). A flat zip of gzip members does NOT work:
    one ``unzip`` extracts them all and gzip decompression does not fork per
    member (~8 execs total). The tree is binary-branching with depth chosen so
    ``2**depth - 1 >= count``.

    MUST be run with ``binwalk -Me`` (recursive); plain ``-e`` only unzips the
    outer archive and stops. Fully deterministic.
    """
    branch = 2
    depth = max(1, int(count).bit_length())  # 2**depth - 1 >= count nodes

    def make(level: int) -> bytes:
        if level == 0:
            return b"leaf " + compressible_blob(payload_size)
        members = [
            (f"c{i}." + ("txt" if level - 1 == 0 else "zip"), make(level - 1))
            for i in range(branch)
        ]
        return zip_archive(members)

    nested_zips = 2 ** depth - 1
    return Sample(
        f"firmware-dense-{count}.bin",
        make(depth),
        [f"branching nested-zip tree: {nested_zips} nested zips (depth {depth}); use binwalk -Me"],
    )


def build_single_format_samples() -> list[Sample]:
    """Documented single-format equivalents of the legacy opaque fixtures."""
    payload = compressible_blob(16384)
    return [
        Sample("gzip-stream.bin", gzip_stream(payload), ["gzip"]),
        Sample("bzip2-stream.bin", bzip2_stream(payload), ["bzip2"]),
        Sample("xz-stream.bin", xz_stream(payload), ["xz"]),
        Sample(
            "zip-archive.bin",
            zip_archive([("a.txt", payload), ("b.txt", payload), ("nested.gz", gzip_stream(payload))]),
            ["zip", "gzip(nested)"],
        ),
        Sample("tar-archive.bin", tar_archive([("a", payload), ("b", payload)]), ["tar"]),
    ]


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", default="samples", help="output directory (relative to repo root)")
    parser.add_argument("--size-mib", type=float, default=4.0, help="target size of the composite image in MiB")
    parser.add_argument("--all", action="store_true", help="also emit single-format blobs")
    parser.add_argument(
        "--dense",
        type=int,
        action="append",
        default=None,
        metavar="N",
        help="emit a high-event sample with N embedded extractable streams "
        "(~N binwalk extractions); repeatable, e.g. --dense 500 --dense 2000",
    )
    args = parser.parse_args()

    out_dir = (repo_root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.dense:
        samples = [build_dense(n) for n in args.dense]
    else:
        samples = [build_composite(int(args.size_mib * 1024 * 1024))]
    if args.all:
        samples.extend(build_single_format_samples())

    manifest = {"generator": "scripts/gen_binwalk_samples.py", "samples": []}
    for sample in samples:
        path = out_dir / sample.name
        path.write_bytes(sample.data)
        digest = hashlib.sha256(sample.data).hexdigest()
        manifest["samples"].append(
            {
                "name": sample.name,
                "size_bytes": len(sample.data),
                "sha256": digest,
                "contents": sample.contents,
            }
        )
        print(f"wrote {path.relative_to(repo_root)}  {len(sample.data):>9} bytes  sha256={digest[:16]}…  [{', '.join(sample.contents)}]")

    manifest_path = out_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {manifest_path.relative_to(repo_root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
