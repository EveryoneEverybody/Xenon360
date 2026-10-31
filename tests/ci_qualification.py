"""Build two independent copies and publish only validated synthetic receipts."""
import hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
from release_audit import inspect,check_extension

target=sys.argv[1]
if target not in ('12.1.4','12.2'):raise ValueError('Unsupported target')
repo=Path(__file__).resolve().parents[1]
root=Path(os.environ['RUNNER_TEMP'])/('xenon qualification '+target)
root.mkdir(exist_ok=False)
names=subprocess.check_output(['git','ls-files','-z'],cwd=repo).decode().split('\0')
archives=[];receipts=[]
for index in (1,2):
    copy=root/f'build {index}';copy.mkdir()
    for name in names:
        if not name:continue
        dest=copy/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(repo/name,dest)
    subprocess.run(['bash','gradlew','--no-daemon','--console=plain','buildExtension','smokeTest'],cwd=copy,check=True)
    archive=copy/'dist'/f'ghidra_{target}_XenonVMX128_0.8.3.zip'
    audit=inspect([(archive.name,archive)])
    if audit['result']!='PASS':raise RuntimeError('Distribution privacy scan failed')
    structural=check_extension(archive,target)
    tests={}
    for name in ['option-compatibility','vmx-semantics','vmx-splats','vmx-splat-decompiler','vmx-merges','vmx-merge-decompiler','vmx-permute','vmx-permute-decompiler','vmx-permute-optimization','vmx-permute-structured','vmx-element-word','vmx-element-word-decompiler','vmx-unpack','vmx-unpack-decompiler','vmx-compare','vmx-compare-decompiler','fp-compare','fp-compare-decompiler','analysis-safety','switch-safety','halfword-safety','padded-byte-safety','absolute-word-safety']:
        value=json.loads((copy/'build/smoke'/f'{name}.json').read_text())
        if value.get('result',value.get('status'))!='PASS':raise RuntimeError('Failed native receipt')
        tests[name]={k:v for k,v in value.items() if k in ('result','status','checks','executions','pcode_executions','decompiler_cases','userop_emulation_callbacks','assertions','fixtures','cases') and isinstance(v,(str,int))}
    if (copy/'build/smoke/result.txt').read_text().strip()!='PASS':raise RuntimeError('Failed import receipt')
    archives.append(archive);receipts.append(dict(archive=structural,tests=tests,public_safety='PASS'))
if archives[0].read_bytes()!=archives[1].read_bytes():raise RuntimeError('Independent builds are not byte-identical')
dist=repo/'dist';dist.mkdir(exist_ok=False)
archive=dist/archives[0].name;shutil.copy2(archives[0],archive)
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
(dist/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n')
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
(dist/f'qualification-{target}.json').write_text(json.dumps(dict(schema='xenon360/ci-qualification-v1',commit=commit,ghidra=target,result='PASS',reproducible=True,builds=receipts),indent=2)+'\n')
for path in (archive,dist/(archive.name+'.sha256'),dist/f'qualification-{target}.json'):
    if not path.is_file() or path.stat().st_size==0:raise RuntimeError('Missing upload input')
print('QUALIFIED',target,digest)
