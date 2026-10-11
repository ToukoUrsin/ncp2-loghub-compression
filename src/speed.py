#!/usr/bin/env python3
"""Fresh-process end-to-end timing; fixture creation and verification are untimed."""
import hashlib,json,os,statistics,subprocess,time
from pathlib import Path
from benchmark import execute,digest,require
ROOT=Path(__file__).resolve().parents[2]
def make_fixture(seed,path):
    b=Path(seed).read_bytes();require(bool(b),'empty seed');q,r=divmod(100000000,len(b))
    with Path(path).open('wb') as f:
        for _ in range(q):f.write(b)
        f.write(b[:r])
def measure_seed(seed,binary,directory,workers,repeats=5,qualified=False):
    directory.mkdir(exist_ok=True,parents=True);raw=directory/'input.log';frame=directory/'frame.ncp';out=directory/'restored';make_fixture(seed,raw);source=digest(raw)
    trials=[]
    for i in range(repeats):
        trial=execute([binary,'e',raw,frame,str(workers)],timeout=30);require(trial['returncode']==0,'speed encode');trial.update(repeat=i,MBps=100/trial['seconds'],frame_bytes=frame.stat().st_size,frame_sha256=digest(frame));trials.append(trial)
    d=execute([binary,'d',frame,out],timeout=30);require(d['returncode']==0 and digest(out)==source,'speed roundtrip')
    bad=directory/'bad';bad.write_bytes(frame.read_bytes()[:-1]);n=execute([binary,'d',bad,directory/'negative'],timeout=30);require(n['returncode'] not in (None,0),'speed truncation')
    mem=execute(['/usr/bin/time','-v',binary,'e',raw,frame,str(workers)],timeout=30);require(mem['returncode']==0,'memory run')
    result={'qualified_seed':qualified,'seed_path':str(seed),'seed_bytes':Path(seed).stat().st_size,'seed_sha256':digest(seed),'raw_bytes':raw.stat().st_size,'raw_sha256':source,'workers':workers,'trials':trials,'median_MBps':100/statistics.median(t['seconds'] for t in trials),'minimum_MBps':min(t['MBps'] for t in trials),'roundtrip':True,'negative':True,'decode':d,'restored_sha256':digest(out),'truncation':n,'resource_run':mem,'filesystem':'warm page cache; read, transform, entropy, checksum, write, close and rename included; no fsync'}
    for p in [raw,out,bad]:p.unlink()
    return result
if __name__=='__main__':
    os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:4]);seed=ROOT/'data/OpenSSH_64lines_excerpt.log';results={'scope':'UNQUALIFIED 64-line excerpt repetition; never counts toward milestone','affinity':sorted(os.sched_getaffinity(0)),'measurements':[]}
    for binary,workers in [(ROOT/'bin/ncp1',1),(ROOT/'bin/ncp',1),(ROOT/'bin/ncp1',4),(ROOT/'bin/ncp',4)]:
        r=measure_seed(seed,binary,ROOT/f'results/speed_{binary.name}_{workers}',workers,5,False);r['binary']=str(binary);r['binary_sha256']=digest(binary);results['measurements'].append(r)
    (ROOT/'results/speed.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps([{'binary':r['binary'],'workers':r['workers'],'median_MBps':r['median_MBps'],'bytes':r['trials'][0]['frame_bytes']} for r in results['measurements']]))
