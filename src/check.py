#!/usr/bin/env python3
"""Fresh-process native checks, independent Python encode/decode, parser faults.
Assertions are deliberately not used: python -O retains every acceptance check.
"""
import hashlib,json,os,random,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src/ncp2'))
from reference import decode,frame_for_test,zcompress,BLOCK,MAXV,MASK
BIN=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/'bin/ncp'
TAG=sys.argv[2] if len(sys.argv)>2 else 'release'
if hasattr(os,'sched_getaffinity'):os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:4])
def check(ok,msg):
    if not ok:raise RuntimeError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def vi(v):
    b=bytearray()
    while v>=128:b.append((v&127)|128);v>>=7
    b.append(v);return bytes(b)
def independent_encode(raw):
    out=bytearray(b'NCP2')
    for off in range(0,len(raw),BLOCK):
        src=raw[off:off+BLOCK];lit=bytearray();num=bytearray();p=0;h=0;previous={}
        while p<len(src):
            c=src[p]
            if 48<=c<=57:
                q=p+1
                while q<len(src) and q-p<18 and 48<=src[q]<=57:q+=1
                v=int(src[p:q]);slot=((h*0x9e3779b97f4a7c15)&MASK)>>48
                d=v-previous.get(slot,0);num.extend(vi(2*d if d>=0 else -2*d-1));previous[slot]=v
                lit.extend((255,q-p));h=((h<<8)|255)&MASK;p=q
            else:
                lit.append(c)
                if c==255:lit.append(0)
                h=0 if c==10 else ((h<<8)|c)&MASK;p+=1
        z=zcompress(bytes(lit+num));out.extend(struct.pack('<IIII',len(src),len(lit),len(lit)+len(num),len(z)));out.extend(z)
    out.extend(b'\0'*4);out.extend(hashlib.sha256(out).digest());return bytes(out)
def rehash(b):return b[:-32]+hashlib.sha256(b[:-32]).digest()
rng=random.Random(20261007);start=time.perf_counter();results={'binary_sha256':sha(BIN.read_bytes()),'tag':TAG,'seed':20261007,'roundtrips':[],'negative_counts':{},'negative_log':f'negative_{TAG}.jsonl'}
with tempfile.TemporaryDirectory() as temp, (ROOT/'results'/results['negative_log']).open('w') as log:
    temp=Path(temp);inp=temp/'input';enc=temp/'frame';out=temp/'output';bad=temp/'bad'
    def run(mode,src,dst,threads=1):return subprocess.run([str(BIN),mode,str(src),str(dst),str(threads)],capture_output=True,timeout=20)
    cases=[('empty',b''),('all_bytes',bytes(range(256))*17),('leading_zeros',b'000 00 -000 +000\r\n001 1'),('integer_extremes',b'x=999999999999999999\nx=0\nx=999999999999999999\nx=00'),('long_integer',b'9'*10003),('line_endings',b'a1\ra2\na3\r\na4\x00\xff0\xff\x00'),('unicode','µ二 00012 🦊 11\n'.encode()),('literal_marker',b'\xff'*4097),('public_excerpt',(ROOT/'src/ncp2/data/OpenSSH_64lines_excerpt.log').read_bytes())]
    for n in [BLOCK-1,BLOCK,BLOCK+1,2*BLOCK+19]:cases.append((f'boundary_{n}',(b'12345 abc\r\n\xff 0000\n'*(n//18+2))[:n]))
    for i in range(100):cases.append((f'random_{i}',rng.randbytes(rng.randrange(4096))))
    for i in range(25):cases.append((f'numeric_{i}',b''.join(f'field_{rng.randrange(80)} = {rng.randrange(10**18):018d}\r\n'.encode() for _ in range(100))))
    for n in [1,17,18,19,35,36,37,255,256,257]:cases.append((f'numeric_run_{n}',b'9'*n))
    for name,b in cases:
        inp.write_bytes(b);p=run('e',inp,enc);check(p.returncode==0,f'{name}: encode {p.stderr!r}')
        frame=enc.read_bytes();p=run('d',enc,out);check(p.returncode==0,f'{name}: decode {p.stderr!r}')
        check(out.read_bytes()==b and decode(frame)==b,name+' roundtrip')
        independent=False
        if len(b)<20000:
            golden=independent_encode(b);check(golden==frame,name+' independent encoder bytes');independent=True
        results['roundtrips'].append({'name':name,'raw_bytes':len(b),'frame_bytes':len(frame),'raw_sha256':sha(b),'restored_sha256':sha(out.read_bytes()),'independent_decoder':True,'independent_encoder':independent})
    inp.write_bytes((ROOT/'src/ncp2/data/OpenSSH_64lines_excerpt.log').read_bytes());check(run('e',inp,enc).returncode==0,'excerpt');base=enc.read_bytes()
    def reject(group,name,data):
        bad.write_bytes(data);out.write_bytes(b'KEEP EXISTING OUTPUT');p=run('d',bad,out)
        check(p.returncode!=0,name+' accepted');check(out.read_bytes()==b'KEEP EXISTING OUTPUT',name+' overwrote destination')
        try:decode(data)
        except (ValueError,OverflowError):pass
        else:raise RuntimeError(name+' Python accepted')
        check(not list(temp.glob('output.tmp.*')),name+' leaked temporary output')
        results['negative_counts'][group]=results['negative_counts'].get(group,0)+1
        log.write(json.dumps({'group':group,'name':name,'bytes':len(data),'sha256':sha(data),'rc':p.returncode,'stderr':p.stderr.decode(errors='replace').strip(),'destination_preserved':True,'python_rejected':True})+'\n')
    for cut in range(len(base)):reject('truncation',str(cut),base[:cut])
    for pos in range(len(base)):
        # Exhaustive single-bit corruption, not merely the low bit.
        for bit in range(8):
            b=bytearray(base);b[pos]^=1<<bit;reject('single_bit',f'{pos}:{bit}',bytes(b))
    reject('framing','trailing',base+b'\0');reject('framing','concatenated',base+base)
    malformed=[('literal_digit',b'1',b'1',b''),('escape_missing',b'x',b'\xff',b''),('width19',b'1',b'\xff\x13',b'\x02'),('value_too_wide',b'0',b'\xff\1',b'\x14'),('negative_value',b'0',b'\xff\1',b'\1'),('varint_overlong',b'0',b'\xff\1',b'\x80\0'),('varint_missing',b'0',b'\xff\1',b''),('residual_unused',b'x',b'x',b'\0'),('varint_overflow',b'0',b'\xff\1',b'\xff'*9),('empty_literal',b'x',b'',b''),('short_raw',b'xx',b'x',b'')]
    for name,raw,lit,num in malformed:reject('rehashed_inner',name,frame_for_test(raw,lit,num))
    for off,v in [(4,BLOCK+1),(8,0xffffffff),(12,0xffffffff),(16,0xffffffff),(16,0)]:
        b=bytearray(base);struct.pack_into('<I',b,off,v);reject('rehashed_header',f'{off}:{v}',rehash(bytes(b)))
    # Extra zstd frame and false content lengths are tested with correct wire SHA.
    c=struct.unpack_from('<I',base,16)[0];zextra=zcompress(b'')
    b=bytearray(base[:20]+base[20:20+c]+zextra+base[20+c:]);struct.pack_into('<I',b,16,c+len(zextra));reject('rehashed_inner','extra_zstd_frame',rehash(bytes(b)))
    outputs=[];inp.write_bytes(b'123 00045 \xff\n'*200000)
    for t in range(1,5):
        check(run('e',inp,enc,t).returncode==0,'thread encoder');outputs.append(sha(enc.read_bytes()))
        check(run('d',enc,out).returncode==0 and out.read_bytes()==inp.read_bytes(),'thread decode')
    check(len(set(outputs))==1,'worker-count nondeterminism');results['thread_determinism_sha256']=outputs
    original=inp.read_bytes()
    for mode in ['e','d']:
        p=run(mode,inp,inp);check(p.returncode!=0 and inp.read_bytes()==original,'same path')
    alias=temp/'hardlink';os.link(inp,alias);check(run('e',inp,alias).returncode!=0 and inp.read_bytes()==original,'hardlink')
    alias.unlink();alias.symlink_to(inp);check(run('e',inp,alias).returncode!=0 and inp.read_bytes()==original,'symlink')
    for threads in ['0','5','-1','4junk','']:
        p=subprocess.run([str(BIN),'e',str(inp),str(out),threads],capture_output=True);check(p.returncode!=0,'invalid threads')
    results['path_alias_and_invalid_cli_controls']=9
results.update(elapsed_seconds=time.perf_counter()-start,roundtrip_count=len(results['roundtrips']),negative_count=sum(results['negative_counts'].values()),all_passed=True)
(ROOT/'results'/f'checks_{TAG}.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps({k:v for k,v in results.items() if k!='roundtrips'}))
