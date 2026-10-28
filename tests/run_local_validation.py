"""Reproducible isolated integration, with explicit local-only corpus paths.
No original project is opened. Use a new --output path for every installation.
"""
import argparse, json, os, pathlib, subprocess, sys, shutil
from process_metrics import run_measured

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--ghidra',required=True,type=pathlib.Path)
    p.add_argument('--java-home',required=True,type=pathlib.Path)
    p.add_argument('--output',required=True,type=pathlib.Path)
    p.add_argument('--input-a',type=pathlib.Path)
    p.add_argument('--input-b',type=pathlib.Path)
    p.add_argument('--reference',type=pathlib.Path)
    p.add_argument('--baseline',action='store_true',help='Use v07-compatible census only')
    p.add_argument('--analysis-timeout',type=int,default=3600,help='Per-file full-analysis limit in seconds (default: 3600)')
    p.add_argument('--zip',required=True,type=pathlib.Path)
    p.add_argument('--reuse-projects',type=pathlib.Path,help='Copy closed disposable corpus projects, then recheck the current candidate')
    args=p.parse_args();repo=pathlib.Path(__file__).resolve().parents[1]
    root=args.output.resolve()
    root.mkdir(parents=True,exist_ok=False)
    java=args.java_home/'bin'/('java.exe' if os.name=='nt' else 'java')
    utility=args.ghidra/'Ghidra/Framework/Utility/lib/Utility.jar'
    props=['-Djava.system.class.loader=ghidra.GhidraClassLoader','-Djava.awt.headless=true','-Dfile.encoding=UTF-8']
    props += [f'-Dapplication.{key}dir={root/name}' for key,name in [('settings','settings'),('cache','cache'),('temp','temp')]]
    base=[str(java),'-Xmx3g',*props]
    def run(name,command,required=True):
        print(f'RUN {name}',flush=True)
        (root/(name+'.command.json')).write_text(json.dumps(command,indent=2))
        with (root/(name+'.log')).open('w',encoding='utf-8') as log:
            receipt=run_measured(command,log,cwd=repo)
        (root/(name+'.process.json')).write_text(json.dumps(receipt,indent=2)+'\n')
        code=receipt['exit_code']
        print(f'EXIT {name} {code}',flush=True)
        if code and required: raise RuntimeError(f'{name}: {code}; see {root/(name+".log")}')
        return code
    archive=args.zip
    cp=os.pathsep.join(map(str,[utility,repo/'build/classes/java/main',repo/'build/classes/java/test']))
    run('install',base+['-cp',cp,'ghidra.Ghidra','xenon360.xex.CreateSmokeFixture',str(archive),str(root)])
    results={}
    for name,source in [('reference',args.reference),('input-a',args.input_a),('input-b',args.input_b)]:
        if source is None: continue
        folder=root/name;folder.mkdir()
        script='XenonBaselineCensus.java' if args.baseline else 'XenonCorpusGate.java'
        operation=['-import',str(source)]
        if args.reuse_projects:
            for suffix in ('.gpr','.rep'):
                original=args.reuse_projects/(name+suffix);destination=root/'project'/(name+suffix)
                if suffix=='.rep':shutil.copytree(original,destination)
                else:shutil.copy2(original,destination)
            operation=['-process',source.name];script='XenonRecheck.java'
        command=base+['-cp',str(utility),'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',str(root/'project'),name,
            *operation,'-max-cpu','2','-analysisTimeoutPerFile',str(args.analysis_timeout),'-scriptPath',str(repo/'tests'),
            '-postScript',script,str(folder),'-log',str(folder/'headless.log')]
        command += ['-noanalysis'] if name=='reference' or args.reuse_projects else ['-loader','XenonXexLoader']
        code=run(name,command,required=False)
        gate=folder/'gate.json'
        results[name]=json.loads(gate.read_text()) if gate.exists() else {'result':'FAIL_NO_GATE'}
        if code: results[name]={'result':'FAIL_PROCESS','exit_code':code}
        (root/'results.json').write_text(json.dumps(results,indent=2))
        # Continue independent specimens even after a script failure (headless may return zero).
    if any(r['result']!='PASS' for r in results.values()):return 1
    return 0
if __name__=='__main__':sys.exit(main())
