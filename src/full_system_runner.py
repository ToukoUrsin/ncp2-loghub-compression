#!/usr/bin/env python3
"""Acquire and measure the six full files missing from the admitted panel.

This is a bounded, single-trial screen.  The raw archives and temporary
frames live below /tmp on the compute host; only the small JSON receipt is
written under results/.  Every codec is checked against the same raw SHA-256
and a one-byte truncation control.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

SYSTEMS = {
    "Android": {
        "url": "https://zenodo.org/records/8196385/files/Android_v1.zip?download=1",
        "archive": "Android_v1.zip", "archive_bytes": 24858007,
        "archive_md5": "3b35b3cc00d577a510cf9f416d59b3b3", "kind": "zip",
        "source_record": "https://zenodo.org/records/8196385",
    },
    "BGL": {
        "url": "https://zenodo.org/records/8275861/files/BGL.zip?download=1",
        "archive": "BGL.zip", "archive_bytes": 86118141,
        "archive_md5": "521ee643375bb6e9d0dd88636ff7ece1", "kind": "zip",
        "source_record": "https://zenodo.org/records/8275861",
    },
    "HDFS": {
        "url": "https://zenodo.org/records/8275861/files/HDFS.zip?download=1",
        "archive": "HDFS.zip", "archive_bytes": 321944794,
        "archive_md5": "f23880dd4938379a535ab71a8d27a798", "kind": "zip",
        "source_record": "https://zenodo.org/records/8275861",
    },
    "Spark": {
        "url": "https://zenodo.org/records/8275861/files/Spark.zip?download=1",
        "archive": "Spark.zip", "archive_bytes": 230699188,
        "archive_md5": "ca0ef9c6e8ece0df602793bd302e03a6", "kind": "zip",
        "source_record": "https://zenodo.org/records/8275861",
    },
    "Thunderbird": {
        "url": "https://zenodo.org/records/8275861/files/Thunderbird.zip?download=1",
        "archive": "Thunderbird.zip", "archive_bytes": 293018641,
        "archive_md5": "a8d365d003845c3bef61661375513910", "kind": "zip",
        "source_record": "https://zenodo.org/records/8275861",
    },
    "Windows": {
        "url": "https://zenodo.org/records/8196385/files/Windows.tar.gz?download=1",
        "archive": "Windows.tar.gz", "archive_bytes": 1670098945,
        "archive_md5": "8b994d947d30617d51e2a565152ae90f", "kind": "tar.gz",
        "source_record": "https://zenodo.org/records/8196385",
    },
}

BLOCK = 1 << 20
MASK = (1 << 64) - 1
MAXV = 10**18 - 1


def digest(path: Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_archive(url: str, archive: Path, expected_bytes: int,
                  expected_md5: str) -> None:
    """Download a Zenodo member with retry/resume (gateway 504 is transient)."""
    part = archive.with_name(archive.name + ".part")
    for attempt in range(1, 13):
        try:
            cmd = ["curl", "-fL", "--retry", "3", "--retry-all-errors",
                   "--retry-delay", "3", "--connect-timeout", "30",
                   "--max-time", "7200", "-C", "-", "-o", part, url]
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rc = p.returncode
        except FileNotFoundError:
            # Daytona's minimal image has no curl.  Preserve the same
            # resumable contract with the standard library so the packet is
            # runnable there as well as on the AWS hosts.
            import urllib.request
            offset = part.stat().st_size if part.exists() else 0
            req = urllib.request.Request(url, headers={"User-Agent": "rf-log-compression/1"})
            if offset:
                req.add_header("Range", f"bytes={offset}-")
            try:
                with urllib.request.urlopen(req, timeout=7200) as src, part.open("ab" if offset else "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                rc = 0
            except Exception as exc:
                print(f"urllib retry {attempt}/12 error={exc}", flush=True)
                rc = 1
        if part.exists() and part.stat().st_size > expected_bytes:
            part.unlink()
        if (rc == 0 and part.exists()
                and part.stat().st_size == expected_bytes
                and digest(part, "md5") == expected_md5):
            part.replace(archive)
            return
        # A complete but bad response should restart from byte zero; an
        # incomplete response is retained for curl's next ranged attempt.
        if part.exists() and part.stat().st_size == expected_bytes:
            part.unlink()
        print(f"download retry {attempt}/12 rc={rc} bytes="
              f"{part.stat().st_size if part.exists() else 0}", flush=True)
        time.sleep(min(30, attempt * 2))
    raise RuntimeError(f"download failed after retries: {url}")


def run(cmd: list[object], env: dict[str, str], timeout: int = 86400,
        stdout: Path | None = None) -> dict:
    start = time.perf_counter()
    if stdout is None:
        p = subprocess.run([str(x) for x in cmd], env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
    else:
        with stdout.open("wb") as out:
            p = subprocess.run([str(x) for x in cmd], env=env, stdout=out,
                               stderr=subprocess.PIPE, timeout=timeout)
    return {"command": [str(x) for x in cmd], "seconds": time.perf_counter() - start,
            "returncode": p.returncode,
            "stderr_tail": p.stderr.decode(errors="replace")[-1200:]}


def acquire(root: Path, system: str) -> tuple[Path, dict]:
    meta = SYSTEMS[system]
    archive = root / meta["archive"]
    if not archive.exists() or archive.stat().st_size != meta["archive_bytes"] or digest(archive, "md5") != meta["archive_md5"]:
        archive.unlink(missing_ok=True)
        fetch_archive(meta["url"], archive, meta["archive_bytes"], meta["archive_md5"])
    if archive.stat().st_size != meta["archive_bytes"] or digest(archive, "md5") != meta["archive_md5"]:
        raise RuntimeError(f"{system}: archive pin mismatch")
    raw = root / "raw" / system / f"{system}_full.log"
    raw.parent.mkdir(parents=True, exist_ok=True)
    if not raw.exists():
        if meta["kind"] == "zip":
            with zipfile.ZipFile(archive) as z:
                entries = [x for x in z.infolist() if x.filename.endswith("_full.log")]
                if system == "Android":
                    entries = [x for x in z.infolist() if x.filename.endswith("Android.log")]
                if len(entries) != 1:
                    raise RuntimeError(f"{system}: unexpected zip entries {[x.filename for x in z.infolist()[:8]]}")
                with z.open(entries[0]) as src, raw.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                entry = entries[0].filename
        else:
            with tarfile.open(archive, "r:gz") as tar:
                entries = [x for x in tar.getmembers() if x.isfile() and Path(x.name).name == "Windows.log"]
                if len(entries) != 1:
                    raise RuntimeError(f"Windows: unexpected tar entries {len(entries)}")
                src = tar.extractfile(entries[0])
                assert src is not None
                with src, raw.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                entry = entries[0].name
    info = {"archive_url": meta["url"], "source_record": meta["source_record"],
            "archive": meta["archive"], "archive_bytes": archive.stat().st_size,
            "archive_md5": meta["archive_md5"], "archive_entry": entry,
            "raw_bytes": raw.stat().st_size, "raw_sha256": digest(raw)}
    return raw, info


def stream_hash_decode(cmd: list[object], expected_sha: str, expected_n: int,
                       env: dict[str, str]) -> dict:
    start = time.perf_counter()
    p = subprocess.Popen([str(x) for x in cmd], env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    h = hashlib.sha256(); n = 0
    assert p.stdout is not None
    while True:
        chunk = p.stdout.read(1 << 20)
        if not chunk:
            break
        h.update(chunk); n += len(chunk)
    err = p.stderr.read().decode(errors="replace") if p.stderr else ""
    rc = p.wait()
    got = h.hexdigest() if n else None
    return {"command": [str(x) for x in cmd], "seconds": time.perf_counter() - start,
            "returncode": rc, "bytes": n, "sha256": got,
            "exact": rc == 0 and n == expected_n and got == expected_sha,
            "stderr_tail": err[-1200:]}


def independent_ncp_check(frame: Path, expected_sha: str, expected_n: int,
                          zstd_lib: Path) -> dict:
    """Independent streaming parser; it never materializes a full raw file."""
    Z = C.CDLL(str(zstd_lib))
    Z.ZSTD_decompress.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
    Z.ZSTD_decompress.restype = C.c_size_t
    Z.ZSTD_isError.argtypes = [C.c_size_t]; Z.ZSTD_isError.restype = C.c_uint
    Z.ZSTD_findFrameCompressedSize.argtypes = [C.c_void_p, C.c_size_t]
    Z.ZSTD_findFrameCompressedSize.restype = C.c_size_t
    Z.ZSTD_getFrameContentSize.argtypes = [C.c_void_p, C.c_size_t]
    Z.ZSTD_getFrameContentSize.restype = C.c_uint64
    stream_hash = hashlib.sha256(); raw_hash = hashlib.sha256(); raw_n = 0
    with frame.open("rb") as f:
        def take(n: int, include: bool = True) -> bytes:
            nonlocal stream_hash
            b = f.read(n)
            if len(b) != n: raise ValueError("truncated frame")
            if include: stream_hash.update(b)
            return b
        if take(4) != b"NCP2": raise ValueError("bad magic")
        blocks = 0
        while True:
            r = int.from_bytes(take(4), "little")
            if not r:
                break
            l = int.from_bytes(take(4), "little")
            t = int.from_bytes(take(4), "little")
            c = int.from_bytes(take(4), "little")
            if not (0 < r <= BLOCK and 0 <= l <= t <= 11 * r and c > 0): raise ValueError("bad bounds")
            z = take(c)
            zbuf = C.create_string_buffer(z)
            if Z.ZSTD_findFrameCompressedSize(zbuf, c) != c or Z.ZSTD_getFrameContentSize(zbuf, c) != t:
                raise ValueError("bad zstd frame")
            out = C.create_string_buffer(t)
            n = Z.ZSTD_decompress(out, t, zbuf, c)
            if Z.ZSTD_isError(n) or n != t: raise ValueError("zstd decode")
            b = out.raw; i = 0; q = l; h = 0; prev = [0] * 65536; block_n = 0
            while i < l:
                ch = b[i]; i += 1
                if ch == 255:
                    if i >= l: raise ValueError("missing width")
                    w = b[i]; i += 1
                    if w:
                        if not (1 <= w <= 18): raise ValueError("bad width")
                        val = 0
                        for k in range(9):
                            if q >= len(b): raise ValueError("bad varint")
                            v = b[q]; q += 1; val |= (v & 127) << (7 * k)
                            if not v & 128:
                                if k and not (v & 127): raise ValueError("noncanonical varint")
                                break
                        else: raise ValueError("long varint")
                        slot = ((h * 0x9e3779b97f4a7c15) & MASK) >> 48
                        delta = val // 2 if val % 2 == 0 else -(val // 2) - 1
                        value = prev[slot] + delta
                        if not (0 <= value < 10**w): raise ValueError("bad value")
                        prev[slot] = value
                        text = f"{value:0{w}d}".encode("ascii")
                        raw_hash.update(text); raw_n += w; block_n += w
                        h = ((h << 8) | 255) & MASK
                        continue
                elif 48 <= ch <= 57:
                    raise ValueError("unencoded digit")
                if block_n >= r: raise ValueError("raw overflow")
                raw_hash.update(bytes((ch,))); raw_n += 1; block_n += 1
                h = 0 if ch == 10 else ((h << 8) | ch) & MASK
            if q != len(b) or block_n != r: raise ValueError("block mismatch")
            blocks += 1
        encoded_digest = take(32, include=False)
        if encoded_digest != stream_hash.digest(): raise ValueError("encoded digest mismatch")
        if f.read(1): raise ValueError("trailing bytes")
    got = raw_hash.hexdigest()
    return {"passed": got == expected_sha and raw_n == expected_n, "raw_bytes": raw_n,
            "raw_sha256": got, "blocks": blocks}


def codec_row(system: str, raw: Path, info: dict, tools: dict[str, Path], work: Path,
              env: dict[str, str]) -> dict:
    n, sha = info["raw_bytes"], info["raw_sha256"]
    work.mkdir(parents=True, exist_ok=True)
    out: dict = {"system": system, "raw_bytes": n, "raw_sha256": sha}
    # NCP2 candidate: native roundtrip, independent frame parser, truncation.
    frame = work / f"{system}.ncp"; restored = work / f"{system}.restored"
    enc = run([tools["ncp"], "e", raw, frame, "4"], env)
    dec = run([tools["ncp"], "d", frame, restored], env)
    native = {"sha256": digest(restored) if restored.exists() else None,
              "bytes": restored.stat().st_size if restored.exists() else 0,
              "exact": restored.exists() and digest(restored) == sha and restored.stat().st_size == n,
              "decode": dec}
    indep = independent_ncp_check(frame, sha, n, tools["zstd_lib"])
    trunc = work / f"{system}.ncp.trunc"; shutil.copyfile(frame, trunc); trunc.open("r+b").truncate(frame.stat().st_size - 1)
    neg = run([tools["ncp"], "d", trunc, work / f"{system}.ncp.bad"], env)
    out["ncp2"] = {"compressed_bytes": frame.stat().st_size, "encode": enc,
                    "native": native, "independent": indep,
                    "negative": {"rejected": neg["returncode"] != 0,
                                  "decode": neg}}
    restored.unlink(missing_ok=True); frame.unlink(missing_ok=True); trunc.unlink(missing_ok=True)
    # General codecs, one full trial each.  Decode is streamed into a hash.
    for name, cmd in (("xz", [tools["xz"], "-q", "-9e", "--threads=1", "-c", raw]),
                      ("zstd", [tools["zstd"], "-q", "-19", "--long=31", "--threads=1", "-c", raw])):
        frame = work / f"{system}.{name}"; enc = run(cmd, env, stdout=frame)
        # Long-mode frames can exceed zstd's default decoder window limit;
        # mirror the encoder's --long=31 setting on decode.
        dec = stream_hash_decode(([tools[name], "-q", "-d", "-c", frame] if name == "xz" else [tools[name], "-q", "-d", "--long=31", "-c", frame]), sha, n, env)
        trunc = work / f"{system}.{name}.trunc"; shutil.copyfile(frame, trunc); trunc.open("r+b").truncate(frame.stat().st_size - 1)
        neg = stream_hash_decode(([tools[name], "-q", "-d", "-c", trunc] if name == "xz" else [tools[name], "-q", "-d", "--long=31", "-c", trunc]), sha, n, env)
        out[name] = {"compressed_bytes": frame.stat().st_size, "encode": enc, "decode": dec,
                     "negative": {"rejected_or_wrong_hash": not neg["exact"], "decode": neg}}
        frame.unlink(missing_ok=True); trunc.unlink(missing_ok=True)
    # CLP complete archive footprint and exact extraction.
    archive = work / f"{system}.clp"; extract = work / f"{system}.clp.extract"
    enc = run([tools["clp"], "c", archive, "--compression-level", "19",
               "--remove-path-prefix", raw.parent, raw], env)
    files = [p for p in archive.rglob("*") if p.is_file()] if archive.exists() else []
    total = sum(p.stat().st_size for p in files)
    dec = run([tools["clp"], "x", archive, extract], env) if archive.exists() else {"returncode": 1}
    candidates = list(extract.rglob(raw.name)) if extract.exists() else []
    restored_path = candidates[0] if candidates else None
    restored_hash = digest(restored_path) if restored_path else None
    seg = next((p for p in files if p.stat().st_size and p.name not in {"metadata.db", "metadata"}), None)
    neg_ok = False; neg_detail = {}
    if seg:
        original = seg.read_bytes(); seg.write_bytes(original[:-1])
        bad_out = work / f"{system}.clp.bad"
        bad = run([tools["clp"], "x", archive, bad_out], env)
        bad_files = list(bad_out.rglob(raw.name)) if bad_out.exists() else []
        bad_sha = digest(bad_files[0]) if bad_files else None
        neg_ok = bad.get("returncode", 1) != 0 or bad_sha != sha
        neg_detail = {"returncode": bad.get("returncode", 1), "sha256": bad_sha, "rejected_or_wrong_hash": neg_ok}
        seg.write_bytes(original); shutil.rmtree(bad_out, ignore_errors=True)
    out["clp"] = {"archive_bytes": total, "archive_files": len(files), "encode": enc,
                   "decode": dec, "roundtrip": dec.get("returncode") == 0 and restored_hash == sha,
                   "restored_sha256": restored_hash, "negative": neg_detail}
    shutil.rmtree(archive, ignore_errors=True); shutil.rmtree(extract, ignore_errors=True)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--systems", nargs="+", default=list(SYSTEMS)); a = ap.parse_args()
    root = Path(tempfile.mkdtemp(prefix="log-compression-six-", dir="/tmp"))
    # This copy lives under worker/<attempt>; resolve the track root explicitly
    # so fleet-run can execute the attempt from its own subdirectory.
    # Keep the compute packet self-contained: the track's data symlink does
    # not follow through fleet-run's rsync boundary, and the original NCP2
    # binary carries this box's absolute zstd RPATH.  The pinned executables
    # and libraries are copied beside this script under tools/.
    script_dir = Path(__file__).resolve().parent
    bundle = script_dir if script_dir.name == "tools" else script_dir / "tools"
    out_rows = []; env = os.environ.copy()
    tools = {"ncp": bundle / "ncp/ncp", "xz": bundle / "xz/xz",
             "zstd": bundle / "zstd/zstd",
             "zstd_lib": bundle / "zstd/lib/libzstd.so.1",
             "clp": bundle / "clp/usr/bin/clp"}
    env["LD_LIBRARY_PATH"] = str(bundle / "zstd/lib") + ":" + str(bundle / "clp/usr/lib/clp") + ":" + env.get("LD_LIBRARY_PATH", "")
    try:
        for system in a.systems:
            print("ACQUIRE", system, flush=True)
            raw, info = acquire(root, system)
            print(json.dumps({"system": system, **info}, sort_keys=True), flush=True)
            # The archive is only an acquisition receipt; remove it before
            # codec work so the large raw file and one frame fit on small
            # shared fleet disks.
            (root / info["archive"]).unlink(missing_ok=True)
            row = codec_row(system, raw, info, tools, root / "frames", env)
            row["source"] = info; out_rows.append(row)
            print(json.dumps({"system": system, "ncp2": row["ncp2"]["compressed_bytes"], "xz": row["xz"]["compressed_bytes"], "zstd": row["zstd"]["compressed_bytes"], "clp": row["clp"]["archive_bytes"]}, sort_keys=True), flush=True)
            shutil.rmtree(raw.parent, ignore_errors=True); (root / info["archive"]).unlink(missing_ok=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    totals = {"systems": len(out_rows), "ncp2_exact": sum(r["ncp2"]["native"]["exact"] and r["ncp2"]["independent"]["passed"] for r in out_rows),
              "ncp2_negative": sum(r["ncp2"]["negative"]["rejected"] for r in out_rows),
              "xz_exact": sum(r["xz"]["decode"]["exact"] for r in out_rows), "zstd_exact": sum(r["zstd"]["decode"]["exact"] for r in out_rows),
              "clp_exact": sum(r["clp"]["roundtrip"] for r in out_rows)}
    result = {"schema": "full six-system NCP2 and four-comparator screen v1", "scope": "Android/BGL/HDFS/Spark/Thunderbird/Windows full public files", "systems": a.systems,
              "sources": {s: SYSTEMS[s] for s in a.systems}, "settings": {"ncp2_workers": 4, "xz": ["-9e", "--threads=1"], "zstd": ["-19", "--long=31", "--threads=1"], "clp": ["compression-level", "19"], "trials": 1},
              "binary_sha256": {k: digest(v) for k, v in tools.items() if k != "zstd_lib" and v.exists()}, "rows": out_rows, "totals": totals}
    a.out.parent.mkdir(parents=True, exist_ok=True); a.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(totals, sort_keys=True), flush=True)
    return 0 if len(out_rows) == len(a.systems) and totals["ncp2_exact"] == len(out_rows) and totals["xz_exact"] == len(out_rows) and totals["zstd_exact"] == len(out_rows) and totals["clp_exact"] == len(out_rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
