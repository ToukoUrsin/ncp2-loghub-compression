// NCP2: bounded, raw-only normalized-prefix numeric residual compression.
// C++17; dependencies: libzstd and OpenSSL libcrypto. No trained data.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <future>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <unistd.h>
#include <openssl/evp.h>
#include <zstd.h>
using B=std::vector<unsigned char>;
constexpr uint32_t BLOCK=1u<<20;
constexpr uint64_t MAXV=999999999999999999ULL;
void need(bool b,const char* s){if(!b)throw std::runtime_error(s);}
void put(B& b,uint64_t x,unsigned n){while(n--){b.push_back(x&255);x>>=8;}}
uint64_t get(const B& b,size_t& p,unsigned n){need(n<=b.size()-p,"short integer");uint64_t x=0;for(unsigned i=0;i<n;i++)x|=uint64_t(b[p++])<<(i*8);return x;}
void vi(B& b,uint64_t x){while(x>=128){b.push_back((x&127)|128);x>>=7;}b.push_back(x);}
uint64_t uv(const B& b,size_t& p){uint64_t x=0;for(unsigned k=0;k<9;k++){need(p<b.size(),"short varint");unsigned c=b[p++];x|=uint64_t(c&127)<<(k*7);if(!(c&128)){need(!k||(c&127),"noncanonical varint");need(x<=2*MAXV,"residual overflow");return x;}}throw std::runtime_error("long varint");}
void wr(FILE* f,const B& b){need(b.empty()||fwrite(b.data(),1,b.size(),f)==b.size(),"write failed");}
B rd(FILE* f,size_t n){B b(n);need(!n||fread(b.data(),1,n,f)==n,"truncated stream");return b;}
struct Hash{
 EVP_MD_CTX* c=EVP_MD_CTX_new();
 Hash(){need(c&&EVP_DigestInit_ex(c,EVP_sha256(),nullptr)==1,"SHA init");}
 ~Hash(){EVP_MD_CTX_free(c);}
 void add(const B& b){need(EVP_DigestUpdate(c,b.data(),b.size())==1,"SHA update");}
 B end(){B b(32);unsigned n=0;need(EVP_DigestFinal_ex(c,b.data(),&n)==1&&n==32,"SHA final");return b;}
};
unsigned ctx(uint64_t h){return unsigned((h*0x9e3779b97f4a7c15ULL)>>48);}
bool digit(unsigned c){return c>='0'&&c<='9';}
B encode_block(B raw){
 std::array<uint64_t,65536> prev{};B lit,num;lit.reserve(raw.size());num.reserve(raw.size()/3);
 uint64_t h=0;
 for(size_t i=0;i<raw.size();){unsigned c=raw[i];
  if(digit(c)){
   uint64_t v=0;unsigned w=0;
   do{v=v*10+(raw[i++]-'0');++w;}while(i<raw.size()&&w<18&&digit(raw[i]));
   unsigned k=ctx(h);uint64_t p=prev[k];vi(num,v>=p?2*(v-p):2*(p-v)-1);prev[k]=v;
   lit.push_back(255);lit.push_back(w);h=(h<<8)|255;
  }else{++i;lit.push_back(c);if(c==255)lit.push_back(0);h=c=='\n'?0:(h<<8)|c;}
 }
 uint32_t l=lit.size();lit.insert(lit.end(),num.begin(),num.end());
 B z(ZSTD_compressBound(lit.size()));thread_local std::unique_ptr<ZSTD_CCtx,decltype(&ZSTD_freeCCtx)> c(ZSTD_createCCtx(),ZSTD_freeCCtx);
 need(bool(c),"zstd allocation");size_t n=ZSTD_compressCCtx(c.get(),z.data(),z.size(),lit.data(),lit.size(),17);
 need(!ZSTD_isError(n),"zstd encode");z.resize(n);
 B out;out.reserve(16+z.size());put(out,raw.size(),4);put(out,l,4);put(out,lit.size(),4);put(out,z.size(),4);out.insert(out.end(),z.begin(),z.end());return out;
}
B decode_block(const B& z,uint32_t r,uint32_t l,uint32_t t){
 need(r&&r<=BLOCK&&l<=t&&t<=11ULL*r,"invalid block bounds");
 need(ZSTD_findFrameCompressedSize(z.data(),z.size())==z.size(),"extra zstd frame bytes");
 need(ZSTD_getFrameContentSize(z.data(),z.size())==t,"wrong zstd content size");
 B b(t);size_t n=ZSTD_decompress(b.data(),b.size(),z.data(),z.size());need(!ZSTD_isError(n)&&n==t,"zstd decode");
 B out;out.reserve(r);std::array<uint64_t,65536> prev{};uint64_t h=0;size_t p=l;
 for(size_t i=0;i<l;){unsigned c=b[i++];
  if(c==255){need(i<l,"short escape");unsigned w=b[i++];
   if(w){need(w<=18&&out.size()+w<=r,"bad width");uint64_t z0=uv(b,p),d=z0/2;unsigned k=ctx(h);uint64_t v;
    if(z0&1){need(prev[k]>d,"negative value");v=prev[k]-d-1;}
    else{need(d<=MAXV-prev[k],"large value");v=prev[k]+d;}
    prev[k]=v;size_t at=out.size();out.resize(at+w);
    for(unsigned j=w;j;j--){out[at+j-1]='0'+v%10;v/=10;}
    need(v==0,"value exceeds width");h=(h<<8)|255;continue;
   }
  }else need(!digit(c),"noncanonical literal digit");
  need(out.size()<r,"raw overflow");out.push_back(c);h=c=='\n'?0:(h<<8)|c;
 }
 need(p==b.size()&&out.size()==r,"unused data or wrong raw size");return out;
}
// A bounded pool retains one zstd context per worker, rather than spawning
// a new thread/context for every block. Queue depth is limited by encode().
class Pool {
 std::mutex mu;std::condition_variable cv;bool stop=false;
 std::deque<std::packaged_task<B()>> jobs;std::vector<std::thread> threads;
public:
 explicit Pool(unsigned n){try{for(unsigned i=0;i<n;++i)threads.emplace_back([this]{
  for(;;){std::packaged_task<B()> job;{std::unique_lock<std::mutex> lock(mu);
   cv.wait(lock,[this]{return stop||!jobs.empty();});if(stop&&jobs.empty())return;
   job=std::move(jobs.front());jobs.pop_front();}job();}
 });}catch(...){finish();throw;}}
 void finish(){ {std::lock_guard<std::mutex> lock(mu);stop=true;}cv.notify_all();for(auto& t:threads)if(t.joinable())t.join();}
 ~Pool(){finish();}
 std::future<B> submit(B b){std::packaged_task<B()> job([b=std::move(b)]()mutable{return encode_block(std::move(b));});auto f=job.get_future();
  {std::lock_guard<std::mutex> lock(mu);jobs.push_back(std::move(job));}cv.notify_one();return f;}
};
void encode(FILE* in,FILE* out,unsigned workers){
 Hash wire;auto wrw=[&](const B& b){wire.add(b);wr(out,b);};wrw(B{'N','C','P','2'});
 std::deque<std::future<B>> q;std::unique_ptr<Pool> pool;if(workers>1)pool=std::make_unique<Pool>(workers);
 auto flush=[&](){wrw(q.front().get());q.pop_front();};
 for(;;){B b(BLOCK);size_t n=fread(b.data(),1,b.size(),in);need(!ferror(in),"input read failed");if(!n)break;b.resize(n);
  if(workers==1)wrw(encode_block(std::move(b)));
  else{q.push_back(pool->submit(std::move(b)));if(q.size()==workers)flush();}
 }
 while(!q.empty())flush();
 B end;put(end,0,4);wrw(end);wr(out,wire.end());
}
void decode(FILE* in,FILE* out){
 Hash wire;auto rdw=[&](size_t n){B b=rd(in,n);wire.add(b);return b;};
 need(rdw(4)==B({'N','C','P','2'}),"bad magic");
 for(;;){B h0=rdw(4);size_t p=0;uint32_t r=get(h0,p,4);if(!r)break;
  B h=rdw(12);p=0;uint32_t l=get(h,p,4),t=get(h,p,4),n=get(h,p,4);
  need(r<=BLOCK&&l<=t&&t<=11ULL*r&&n&&n<=ZSTD_compressBound(t),"invalid frame bounds");
  wr(out,decode_block(rdw(n),r,l,t));
 }
 need(rd(in,32)==wire.end(),"encoded-stream SHA-256 mismatch");
 need(fgetc(in)==EOF&&!ferror(in),"trailing bytes or input error");
}
int main(int argc,char** argv){
 std::string tmp;bool created=false;FILE* in=nullptr;FILE* out=nullptr;
 try{
  if(argc==2&&std::string(argv[1])=="--version"){std::cout<<"NCP2 zstd "<<ZSTD_versionString()<<" block "<<BLOCK<<" level 17\n";return 0;}
  need(argc==4||argc==5,"usage: ncp e|d INPUT OUTPUT [threads:1..4]");std::string mode=argv[1];need(mode=="e"||mode=="d","bad mode");unsigned threads=1;
  if(argc==5){std::string s=argv[4];need(s.size()==1&&s[0]>='1'&&s[0]<='4',"threads must be 1..4");threads=s[0]-'0';}
  if(std::filesystem::exists(argv[3]))need(!std::filesystem::equivalent(argv[2],argv[3]),"input and output identical");
  in=fopen(argv[2],"rb");need(in,"cannot open input");tmp=std::string(argv[3])+".tmp.XXXXXX";std::vector<char> name(tmp.begin(),tmp.end());name.push_back(0);
  int fd=mkstemp(name.data());need(fd>=0,"cannot create output");tmp=name.data();created=true;out=fdopen(fd,"wb");if(!out){close(fd);throw std::runtime_error("fdopen");}
  if(mode=="e")encode(in,out,threads);else decode(in,out);
  int irc=fclose(in);in=nullptr;need(irc==0,"input close");int rc=fclose(out);out=nullptr;need(rc==0,"output close");need(rename(tmp.c_str(),argv[3])==0,"output rename");return 0;
 }catch(const std::exception& e){if(in)fclose(in);if(out)fclose(out);if(created)remove(tmp.c_str());std::cerr<<e.what()<<'\n';return 1;}
}
