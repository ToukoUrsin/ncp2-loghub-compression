#!/usr/bin/env python3
"""Verify and summarize repaired LogShrink archives against pinned comparator rows."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import tarfile
from pathlib import Path

SYSTEMS = "Android Apache BGL HDFS HPC Hadoop HealthApp Linux Mac OpenSSH OpenStack Proxifier Spark Thunderbird Windows Zookeeper".split()


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def strict_gzip(path: Path) -> None:
    with gzip.open(path, "rb") as z:
        while z.read(1 << 20):
            pass


def find_archive(roots: list[Path], system: str) -> tuple[Path, Path]:
    for root in roots:
        d = root / system
        archive = d / f"{system}.complete.tar.gz"
        if archive.is_file():
            return d, archive
    raise FileNotFoundError(f"no complete archive for {system} under {roots}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("data/loghub"))
    ap.add_argument("--root", type=Path, action="append", required=True,
                    help="panel root, in precedence order when a retry exists")
    ap.add_argument("--baseline", type=Path, default=Path("results/baseline-005/baseline.json"))
    ap.add_argument("--ncp", type=Path, default=Path("results/ncp2-002/benchmark_with_clp.json"))
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    roots = [p.resolve() for p in a.root]
    baseline = json.loads(a.baseline.read_text())
    bmap = {s: {r["codec"]: r for r in baseline["rows"] if r["system"] == s} for s in SYSTEMS}
    ncp = json.loads(a.ncp.read_text())
    nmap = {r["system"]: r for r in ncp["rows"]}
    rows = []
    for system in SYSTEMS:
        panel, archive = find_archive(roots, system)
        raw = a.data / system / f"{system}_2k.log"
        restored = panel / f"{system}.restored"
        trunc = panel / f"{system}.trunc.tar.gz"
        raw_sha = sha(raw)
        strict_gzip(archive)
        with tarfile.open(archive, "r:gz") as t:
            members = t.getmembers()
            names = [m.name for m in members]
            if any(m.issym() or m.islnk() for m in members):
                raise ValueError(f"archive contains a link: {archive}")
            eol = t.extractfile("__logshrink_eol.bin")
            patch = t.extractfile("__logshrink_patch.bin")
            if eol is None or patch is None:
                raise ValueError(f"lossless metadata missing: {archive}")
            eol_bytes, patch_bytes = len(eol.read()), len(patch.read())
        if sha(restored) != raw_sha:
            raise ValueError(f"restored hash mismatch: {system}")
        try:
            strict_gzip(trunc)
        except Exception:
            trunc_rejected = True
        else:
            trunc_rejected = False
        if not trunc_rejected:
            raise ValueError(f"truncation accepted: {system}")
        n = nmap[system]
        row = {
            "system": system,
            "raw_bytes": raw.stat().st_size,
            "raw_sha256": raw_sha,
            "archive_bytes": archive.stat().st_size,
            "source_archive": str(archive),
            "template_members": sum(name.startswith("__template__/") for name in names),
            "eol_bytes": eol_bytes,
            "patch_bytes": patch_bytes,
            "roundtrip": True,
            "trunc_rejected": True,
            "restored_sha256": raw_sha,
            "xz_bytes": bmap[system]["xz9e"]["median_compressed_bytes"],
            "zstd19_bytes": bmap[system]["zstd19"]["median_compressed_bytes"],
            "clp_bytes": n["comparators"]["CLP"]["bytes"],
            "candidate_bytes": n["candidate_bytes"],
        }
        row["candidate_wins_four"] = row["candidate_bytes"] < min(
            row[k] for k in ("xz_bytes", "zstd19_bytes", "clp_bytes", "archive_bytes")
        )
        row["logshrink_smaller_than_xz"] = row["archive_bytes"] < row["xz_bytes"]
        rows.append(row)

    totals = {
        "raw_bytes": sum(r["raw_bytes"] for r in rows),
        "logshrink_bytes": sum(r["archive_bytes"] for r in rows),
        "xz_bytes": sum(r["xz_bytes"] for r in rows),
        "zstd19_bytes": sum(r["zstd19_bytes"] for r in rows),
        "clp_bytes": sum(r["clp_bytes"] for r in rows),
        "candidate_bytes": sum(r["candidate_bytes"] for r in rows),
        "roundtrip_pass": sum(r["roundtrip"] for r in rows),
        "truncation_controls_pass": sum(r["trunc_rejected"] for r in rows),
        "logshrink_smaller_than_xz": sum(r["logshrink_smaller_than_xz"] for r in rows),
        "candidate_four_way_wins": sum(r["candidate_wins_four"] for r in rows),
    }
    out = {
        "schema": "lossless LogShrink repaired comparator v1",
        "scope": "16 public LogHub repository 2k samples, same raw pins as baseline-005 and NCP2-002",
        "source_url": "https://github.com/logpai/loghub/tree/dd61d0952749ee7963bde2420d1be5ede023033",
        "comparator_url": "https://github.com/IntelligentDDS/LogShrink/tree/59ce49434eec06c709c7e16027a46214a6c37961",
        "adapter": "src/logshrink_adapter.py",
        "archive_contract": "gzip tar footprint includes upstream members, EOL sidecar, exact line patch, and four template files; strict gzip trailer check and one-byte truncation control",
        "rows": rows,
        "totals": totals,
        "wins_by_system": [r["system"] for r in rows if r["candidate_wins_four"]],
        "losses_by_system": [r["system"] for r in rows if not r["candidate_wins_four"]],
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(totals, sort_keys=True))


if __name__ == "__main__":
    main()
