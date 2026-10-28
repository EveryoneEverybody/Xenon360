"""Run with PyGhidra from the selected Ghidra distribution in an isolated environment."""
import argparse,json,pathlib
from pyghidra.launcher import HeadlessPyGhidraLauncher
import pyghidra

p=argparse.ArgumentParser();p.add_argument('ghidra',type=pathlib.Path);p.add_argument('root',type=pathlib.Path)
args=p.parse_args();root=args.root.resolve()
launcher=HeadlessPyGhidraLauncher(install_dir=args.ghidra)
launcher.add_vmargs('-Xmx1g',*[f'-Dapplication.{key}dir={root/name}' for key,name in [('settings','settings'),('cache','cache'),('temp','temp')]])
launcher.start()
from xenon360.analysis import XenonEvidence
from ghidra.util.task import TaskMonitor
from java.nio.file import Path
with pyghidra.open_program(root/'synthetic.xex',project_location=root/'project',project_name='PyGhidraCanary',analyze=True,loader='xenon360.XenonXexLoader') as api:
    program=api.getCurrentProgram()
    assert str(program.getLanguageID())=='PowerPC:BE:64:Xenon-VMX128-32addr'
    functions=list(program.getFunctionManager().getFunctions(True))
    assert sum(str(f.getCallFixup())=='xenon_ppc_savegpr_noop' for f in functions)==16
    report=XenonEvidence.collect(program,True,TaskMonitor.DUMMY)
    XenonEvidence.writeAtomic(Path.of(str(root/'evidence.json')),report)
(root/'pyghidra-result.json').write_text(json.dumps({'result':'PASS','pyghidra':pyghidra.__version__,'helpers':16,'language':str(program.getLanguageID())},indent=2))
print('XENON_PYGHIDRA_CANARY_PASS')
