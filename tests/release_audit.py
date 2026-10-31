"""Inspect public source, nested archives and class bytes without printing matches.

Supplement a secrets scanner with this structural/privacy gate. Private deny
patterns belong in an external --deny-file, never in distributed source.
"""
import argparse, hashlib, io, json, re, struct, subprocess, zipfile
from pathlib import Path, PurePosixPath

LIMIT=256*1024*1024
PATTERNS={
    'windows_user_path':r'(?i)[a-z]:[\\/]+Users[\\/]+[^\s"<>]+',
    'unix_user_path':r'/(?:home|Users)/[A-Za-z0-9_.-]+/',
    'private_ipv4':r'(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])',
    'private_hostname':r'(?i)\b[a-z0-9][a-z0-9.-]+\.(?:local|internal|lan)\b',
    'credential':r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)',
}

def inspect(files,deny=None):
    patterns={k:re.compile(v) for k,v in {**PATTERNS,**(deny or {})}.items()}
    inventory=[];findings=[];total=0
    def scan(name,data,depth=0):
        nonlocal total
        total+=len(data)
        if total>LIMIT or len(data)>64*1024*1024:raise ValueError('Scan size limit exceeded')
        inventory.append(dict(path=name,size=len(data),sha256=hashlib.sha256(data).hexdigest()))
        texts=[name,data.decode('latin1'),data.decode('utf-16-le',errors='ignore'),data.decode('utf-16-be',errors='ignore')]
        categories=[k for k,p in patterns.items() if any(p.search(t) for t in texts)]
        if name.endswith(('.xex','.xexp','.pdb','.xdb','.lib','.gpr','.rep')) or '.git' in PurePosixPath(name.replace('!','/')).parts:categories.append('prohibited_payload')
        for k in categories:findings.append(dict(path=name,classification=k,disposition='block',verification='detected'))
        if data.startswith(b'PK\x03\x04') or name.endswith(('.zip','.jar')):
            if depth>=4:raise ValueError('Archive nesting limit exceeded')
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names=set();expanded=0
                if z.comment:scan(name+'!<comment>',z.comment,depth+1)
                for e in z.infolist():
                    p=PurePosixPath(e.filename)
                    if p.is_absolute() or '..' in p.parts or '\\' in e.filename or ':' in e.filename or e.filename in names:raise ValueError('Unsafe or duplicate archive entry')
                    names.add(e.filename);expanded+=e.file_size
                    if e.file_size>64*1024*1024 or expanded>LIMIT:raise ValueError('Archive expansion limit exceeded')
                    if (e.external_attr>>16)&0o170000==0o120000:raise ValueError('Archive symbolic link rejected')
                    if e.comment or e.extra:scan(name+'!'+e.filename+'!<metadata>',e.comment+e.extra,depth+1)
                    if not e.is_dir():scan(name+'!'+e.filename,z.read(e),depth+1) # read verifies CRC
    for label,path in files:scan(label,path.read_bytes())
    return dict(schema='xenon360/public-safety-v1',result='FAIL' if findings else 'PASS',files_and_members=len(inventory),expanded_bytes=total,findings=findings,inventory=inventory)

def check_extension(path,target):
    if path.name!=f'ghidra_{target}_XenonVMX128_0.8.3.zip' or not 100_000<path.stat().st_size<20_000_000:raise ValueError('Unexpected extension filename or size')
    with zipfile.ZipFile(path) as z:
        prefix='XenonVMX128/';names=set(z.namelist())
        required=['extension.properties','Module.manifest','README.md','CHANGELOG.md','LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','licenses/LICENSE-GHIDRA.txt','XENON360_BUILD.json','lib/XenonVMX128.jar','data/languages/xenon.ldefs','data/languages/xenon_64_isa_altivec_be.sla','data/languages/xenon_64_isa_altivec_be.slaspec','assets/Xenon360_banner.png']
        if not all(prefix+n in names for n in required) or any(not n.startswith(prefix) for n in names):raise ValueError('Incomplete extension layout')
        for name in names:
            rel=name[len(prefix):]
            if rel in ('','data/','data/languages/','licenses/','lib/','assets/'):continue
            if rel not in required and not re.fullmatch(r'(?:licenses/[^/]+\.txt|data/languages/[^/]+\.(?:sinc|slaspec|sla|ldefs|pspec|cspec))',rel):raise ValueError('Unexpected extension content')
        if z.comment or any(e.comment for e in z.infolist()):raise ValueError('Unexpected archive comments')
        if hashlib.sha256(z.read(prefix+'assets/Xenon360_banner.png')).hexdigest()!='c6cb64c8fb55c4741aa8c58fb3746d80b5b52a58741e9b0be9f53cc08aa94f09':raise ValueError('Original banner changed')
        if '<p align="center">\n  <img src="assets/Xenon360_banner.png" alt="Xenon360" width="100%">\n</p>' not in z.read(prefix+'README.md').decode().replace('\r\n','\n'):raise ValueError('Original banner markup missing')
        info=json.loads(z.read(prefix+'XENON360_BUILD.json'));props=z.read(prefix+'extension.properties').decode()
        release={'12.1.4':21,'12.2':25}[target]
        if info['ghidra_version']!=target or info['loader_version']!='0.8.3' or info['java_release']!=release:raise ValueError('Build metadata mismatch')
        if f'version={target}' not in props.splitlines():raise ValueError('Extension version mismatch')
        jar=z.read(prefix+'lib/XenonVMX128.jar');sla=z.read(prefix+'data/languages/xenon_64_isa_altivec_be.sla')
        if hashlib.sha256(jar).hexdigest()!=info['loader_jar_sha256'] or hashlib.sha256(sla).hexdigest()!=info['sla_sha256']:raise ValueError('Implementation hash mismatch')
        with zipfile.ZipFile(io.BytesIO(jar)) as j:
            classes=[n for n in j.namelist() if n.endswith('.class')]
            if len(classes)<25 or 'xenon360/XenonXexLoader.class' not in classes:raise ValueError('Incomplete JAR')
            for n in classes:
                data=j.read(n)
                if data[:4]!=b'\xca\xfe\xba\xbe' or struct.unpack('>H',data[6:8])[0]!=release+44:raise ValueError('Incorrect Java class target')
        return dict(ghidra=target,java_release=release,classes=len(classes),entries=len(names),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),size=path.stat().st_size)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('paths',nargs='+',type=Path)
    p.add_argument('--target',choices=['12.1.4','12.2']);p.add_argument('--deny-file',type=Path);p.add_argument('--report',required=True,type=Path);a=p.parse_args()
    files=[]
    for path in a.paths:
        if path.is_dir():
            names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=path).decode().split('\0')
            files += [(n,path/n) for n in sorted(set(names)) if n and (path/n).is_file()]
        else:files.append((path.name,path))
    result=inspect(files,json.loads(a.deny_file.read_text()) if a.deny_file else None)
    if a.target:result['extensions']=[check_extension(path,a.target) for _,path in files]
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(result['result'],'inspected',result['files_and_members'],'files/members;',len(result['findings']),'findings')
    raise SystemExit(result['result']!='PASS')

if __name__=='__main__':main()
