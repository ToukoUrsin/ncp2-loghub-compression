# NCP2: numeric-prefix predictor + zstd on the full LogHub-2.0 logs

NCP2 replaces every digit run in a log line with a marker, keys each number by a hash of the
line prefix before it (numbers already masked), stores the zigzag difference from the last number
seen with the same key, and compresses 1 MiB blocks of text plus residuals with libzstd 1.5.7
level 17 (`src/ncp.cpp`, 128 lines, no trained data). It is lossless: every archive below decodes to the exact
raw SHA-256, an independent decoder re-checks it, and a one-byte truncation is rejected.

## Full LogHub-2.0 files (Zenodo record 8275861), 14 systems

Baselines: xz 5.8.4 `-9e --threads=1`, zstd 1.5.7 `-19 --long=31 --threads=1`, CLP v0.14.0
`--compression-level 19`, and LogShrink (commit 59ce494, through `src/logshrink_adapter.py`) where
measured. "best" is the smallest baseline archive.

| system | raw bytes | NCP2 | xz -9e | zstd -19 | CLP | NCP2 vs best |
|---|---:|---:|---:|---:|---:|---:|
| Apache | 4,975,683 | 149,228 | 152,012 | 171,819 | 281,182 | -1.83% |
| BGL | 719,447,452 | 24,210,260 | 27,501,584 | 32,738,959 | 52,501,576 | -11.97% |
| HDFS | 1,565,682,217 | 142,938,028 | 84,957,388 | 95,939,979 | 75,351,488 | +89.70% |
| HPC | 32,610,624 | 1,032,071 | 1,633,996 | 1,960,242 | 1,695,865 | -36.84% |
| Hadoop | 31,887,283 | 1,122,995 | 930,480 | 1,078,387 | 784,017 | +43.24% |
| HealthApp | 20,483,511 | 837,215 | 1,085,128 | 1,256,304 | 1,186,073 | -22.85% |
| Linux | 2,135,395 | 86,266 | 95,312 | 111,459 | 191,130 | -9.49% |
| Mac | 15,437,759 | 575,722 | 510,408 | 565,596 | 893,336 | +12.80% |
| OpenSSH | 70,536,064 | 1,312,800 | 2,276,668 | 2,907,728 | 2,989,891 | -42.34% |
| OpenStack | 61,407,564 | 5,146,687 | 3,511,128 | 3,786,123 | 4,027,513 | +46.58% |
| Proxifier | 2,519,391 | 126,352 | 111,840 | 120,666 | 209,417 | +12.98% |
| Spark | 1,629,352,119 | 35,742,263 | 48,769,008 | 58,041,995 | 48,408,242 | -26.16% |
| Thunderbird | 2,516,177,713 | 66,659,067 | 77,243,676 | 93,918,407 | 83,978,739 | -13.70% |
| Zookeeper | 10,330,307 | 197,197 | 208,464 | 266,263 | 230,487 | -5.40% |

NCP2 is the smallest on **9 of 14** systems. It loses on HDFS, OpenStack, Hadoop, Mac and
Proxifier, and HDFS dominates the total: summed over all 14 files NCP2 is 280.1 MB vs xz 249.0 MB
(+12.5%). LogShrink was measured on the 10 smaller systems (`results/full-fourway/`) and was
larger than xz on all 10; it was not run on BGL, HDFS, Spark or Thunderbird.

Speed: on the public OpenSSH log repeated to 100,000,000 bytes, NCP2 encodes at 234 MB/s median
with 4 worker threads (`results/full-fourway/speed_100m.json`). The xz and zstd baselines above
are single-threaded maximum-ratio settings, so this is not a like-for-like speed comparison.

## Files

- `src/ncp.cpp`, `src/build.sh` — encoder/decoder (`ncp e IN OUT WORKERS`, `ncp d IN OUT`)
- `src/full_system_runner.py` — download, hash, encode/decode/truncation checks for one system
- `results/daytona-20261010/` — BGL, HDFS, Spark, Thunderbird (fresh runs, 4 vCPU sandbox)
- `results/full-fourway/` — the other 10 systems with LogShrink, and the speed fixture

Windows and Android (LogHub 1.0 only) are not part of this table; Android was a loss (NCP2
11.96 MB vs CLP 6.11 MB) and Windows was not measured.
