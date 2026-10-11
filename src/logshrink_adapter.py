#!/usr/bin/env python3
"""Run the pinned LogShrink implementation with a lossless EOL/template wrapper."""
from __future__ import annotations
import argparse, gzip, hashlib, io, json, os, shutil, subprocess, tarfile, tempfile, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
LS=ROOT/'worker/worker2-10/logshrink'
VENDOR=ROOT/'worker/worker2-10/vendor'
VENDOR2=ROOT/'worker/worker2-9/vendor'
PYTHONPATH=os.pathsep.join(str(x) for x in (VENDOR,VENDOR2,LS))
HEADERS={'Android':6,'Apache':6,'BGL':9,'Hadoop':5,'HDFS':5,'HealthApp':3,'HPC':6,
         'Linux':5,'Mac':5,'OpenSSH':5,'OpenStack':7,'Proxifier':4,'Spark':4,
         'Thunderbird':9,'Windows':4,'Zookeeper':6}

def eol_sidecar(raw: bytes)->bytes:
    # one byte per physical line: 0=no terminator, 1=LF, 2=CRLF, 3=CR
    out=bytearray(); i=0
    while i<len(raw):
        j=i
        while j<len(raw) and raw[j] not in (10,13): j+=1
        if j==len(raw): out.append(0); break
        if raw[j]==13 and j+1<len(raw) and raw[j+1]==10: out.append(2); i=j+2
        elif raw[j]==10: out.append(1); i=j+1
        else: out.append(3); i=j+1
    if not raw: return b''
    return bytes(out)

def normalize_lf(raw: bytes)->bytes:
    return raw.replace(b'\r\n',b'\n').replace(b'\r',b'\n')

def line_endings(data: bytes, codes: bytes)->bytes:
    # decoded LogShrink emits one LF per logical line; use sidecar to recover exact EOL bytes.
    lines=data.split(b'\n')
    out=bytearray(); idx=0
    for line in lines:
        if idx>=len(codes):
            if line: out.extend(line)
            continue
        out.extend(line)
        c=codes[idx]; idx+=1
        if c==1: out.append(10)
        elif c==2: out.extend(b'\r\n')
        elif c==3: out.append(13)
        # c==0 denotes unterminated final line; split creates final empty item only after a terminator.
    return bytes(out)

def make_line_patch(raw:bytes, decoded:bytes)->bytes:
    a=normalize_lf(raw).splitlines(); b=decoded.splitlines()
    if len(a)!=len(b):
        raise ValueError(f'line count changed: raw={len(a)} decoded={len(b)}')
    entries=[(i,x) for i,(x,y) in enumerate(zip(a,b)) if x!=y]
    out=bytearray(b'LSFIX1'); out.extend(len(a).to_bytes(4,'little')); out.extend(len(entries).to_bytes(4,'little'))
    for i,x in entries:
        out.extend(i.to_bytes(4,'little')); out.extend(len(x).to_bytes(4,'little')); out.extend(x)
    return bytes(out)

def apply_line_patch(decoded:bytes, patch:bytes)->bytes:
    if not patch: return decoded
    if not patch.startswith(b'LSFIX1'): raise ValueError('bad patch magic')
    n=int.from_bytes(patch[6:10],'little'); k=int.from_bytes(patch[10:14],'little')
    lines=decoded.splitlines()
    if len(lines)!=n: raise ValueError(f'patch line count {n} != {len(lines)}')
    p=14
    for _ in range(k):
        i=int.from_bytes(patch[p:p+4],'little'); z=int.from_bytes(patch[p+4:p+8],'little'); p+=8
        lines[i]=patch[p:p+z]; p+=z
    if p!=len(patch): raise ValueError('patch trailing bytes')
    return b'\n'.join(lines)

def add_members(src:Path, dst:Path, raw:bytes, template:Path, patch:bytes=b''):
    codes=eol_sidecar(raw)
    with tarfile.open(src,'r:gz') as inp, tarfile.open(dst,'w:gz',compresslevel=9) as out:
        for m in inp.getmembers():
            f=inp.extractfile(m) if m.isfile() else None
            out.addfile(m,f)
        payload=codes
        m=tarfile.TarInfo('__logshrink_eol.bin'); m.size=len(payload); m.mode=0o600
        out.addfile(m,io.BytesIO(payload))
        m=tarfile.TarInfo('__logshrink_patch.bin'); m.size=len(patch); m.mode=0o600
        out.addfile(m,io.BytesIO(patch))
        for name in ('head.format','template.col','eventNum.json','template_mapping.json'):
            p=template/name
            if p.exists():
                payload=p.read_bytes(); m=tarfile.TarInfo('__template__/'+name); m.size=len(payload); m.mode=0o600
                out.addfile(m,io.BytesIO(payload))

def require_complete_gzip(path:Path)->None:
    """Reject archives whose gzip trailer is missing even if tarfile can read them."""
    # tarfile's streaming gzip reader accepts a missing trailer when all tar
    # members were already decoded.  The trailer is part of the archive's
    # integrity contract, so force gzip's strict end-of-stream check first.
    with gzip.open(path, 'rb') as z:
        while z.read(1 << 20):
            pass

def extract_sidecar(archive:Path):
    require_complete_gzip(archive)
    with tarfile.open(archive,'r:gz') as t:
        f=t.extractfile('__logshrink_eol.bin')
        eol=f.read() if f else None
        f=t.extractfile('__logshrink_patch.bin')
        return eol,(f.read() if f else b'')

def run_one(raw_path:Path, label:str, out_root:Path):
    raw_path=raw_path.resolve(); out_root=out_root.resolve()
    raw=raw_path.read_bytes(); ds=label
    inp=out_root/'input'/ds; inp.mkdir(parents=True)
    (inp/(ds+'.log')).symlink_to(raw_path)
    out=out_root/'out'; out.mkdir()
    cmd=['python3','run.py','-ds',ds,'-I',str(out_root/'input')+'/', '-E','E','-C','-V','-P','-S','-K','gzip','-wh','20','-th','4','-NC','16','-mt','0.5','-TN','1','-L',str(HEADERS.get(label,6)),'-outdir',str(out)]
    env={**os.environ,'PYTHONPATH':PYTHONPATH,'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1'}
    t=time.perf_counter(); p=subprocess.run(cmd,cwd=LS,env=env,capture_output=True,text=True,timeout=600); elapsed=time.perf_counter()-t
    if p.returncode: raise RuntimeError(f'encode {label} rc={p.returncode}\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}')
    base=out/ds/'0.tar.gz'; template=LS/'template'/ds
    augmented0=out_root/(ds+'.stage.tar.gz'); add_members(base,augmented0,raw,template)
    require_complete_gzip(augmented0)
    # decode through official restorer into normalized output, then recover original EOLs from archive sidecar.
    work=out_root/'restore_tmp'; work.mkdir()
    norm=out_root/(ds+'.normalized'); restored=out_root/(ds+'.restored')
    cmd2=['python3','decompression/restore.py','-I',str(augmented0),'-O',str(norm),'-T',str(template),'-t',str(work),'-K','gzip']
    p2=subprocess.run(cmd2,cwd=LS,env=env,capture_output=True,text=True,timeout=600)
    if p2.returncode: raise RuntimeError(f'decode rc={p2.returncode}\n{p2.stdout[-3000:]}\n{p2.stderr[-3000:]}')
    patch=make_line_patch(raw,norm.read_bytes())
    augmented=out_root/(ds+'.complete.tar.gz'); add_members(base,augmented,raw,template,patch)
    require_complete_gzip(augmented)
    cmd2[3]=str(augmented)
    p2=subprocess.run(cmd2,cwd=LS,env=env,capture_output=True,text=True,timeout=600)
    if p2.returncode: raise RuntimeError(f'patched decode rc={p2.returncode}\n{p2.stdout[-3000:]}\n{p2.stderr[-3000:]}')
    codes,patch_read=extract_sidecar(augmented)
    norm_bytes=apply_line_patch(norm.read_bytes(),patch_read)
    restored.write_bytes(line_endings(norm_bytes,codes))
    ok=restored.read_bytes()==raw
    # one-byte truncation must not pass exact restoration (or should reject).
    trunc=out_root/(ds+'.trunc.tar.gz'); trunc.write_bytes(augmented.read_bytes()[:-1])
    trunc_cmd=list(cmd2); trunc_cmd[3]=str(trunc)
    try:
        require_complete_gzip(trunc)
    except Exception as exc:
        p3=None
        trunc_bad=True
        trunc_error=f'{type(exc).__name__}: {exc}'
    else:
        p3=subprocess.run(trunc_cmd,cwd=LS,env=env,capture_output=True,text=True,timeout=600)
        trunc_bad=(p3.returncode!=0)
        trunc_error=''
    return {'system':label,'raw_bytes':len(raw),'archive_bytes':augmented.stat().st_size,'official_archive_bytes':base.stat().st_size,'patch_bytes':len(patch),'encode_seconds':elapsed,'roundtrip':ok,'raw_sha256':hashlib.sha256(raw).hexdigest(),'restored_sha256':hashlib.sha256(restored.read_bytes()).hexdigest(),'trunc_rejected':trunc_bad,'trunc_error':trunc_error,'stdout_tail':p.stdout[-1000:],'stderr_tail':p.stderr[-1000:]}

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--system',required=True); ap.add_argument('--raw',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
 a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True); print(json.dumps(run_one(a.raw,a.system,a.out),indent=2))
if __name__=='__main__': main()
