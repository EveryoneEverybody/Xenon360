"""Fetch an official, checksum-pinned Ghidra distribution for disposable builds."""
import argparse, hashlib, json, os, urllib.request, zipfile
from pathlib import Path

RELEASES = {
    '12.1.4': ('20260921', 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'),
    '12.2': ('20261016', '2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67'),
}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('version',choices=RELEASES);p.add_argument('--directory',type=Path);a=p.parse_args()
    root=(a.directory or Path(os.environ['RUNNER_TEMP'])/('ghidra with spaces '+a.version)).resolve()
    date,expected=RELEASES[a.version];name=f'ghidra_{a.version}_PUBLIC_{date}.zip'
    url=f'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_{a.version}_build/{name}'
    root.mkdir(parents=True,exist_ok=True);archive=root/name
    if not archive.exists():
        partial=archive.with_suffix('.partial')
        with urllib.request.urlopen(url,timeout=120) as response,partial.open('wb') as output:
            while chunk:=response.read(1024*1024):output.write(chunk)
        partial.replace(archive)
    with archive.open('rb') as source:actual=hashlib.file_digest(source,'sha256').hexdigest()
    if actual!=expected:raise RuntimeError('Ghidra download checksum mismatch')
    installation=root/f'ghidra_{a.version}_PUBLIC'
    if installation.exists():raise FileExistsError('Use a fresh directory; existing Ghidra installations will not be overwritten')
    with zipfile.ZipFile(archive) as bundle:
        for entry in bundle.infolist():
            if not (root/entry.filename).resolve().is_relative_to(root):raise ValueError('Unsafe archive path')
        bundle.extractall(root)
        if os.name!='nt':
            for entry in bundle.infolist():
                mode=(entry.external_attr>>16)&0o777
                if mode:(root/entry.filename).chmod(mode)
    if not (installation/'support/buildExtension.gradle').is_file():raise RuntimeError('Ghidra distribution is incomplete')
    (root/'download-receipt.json').write_text(json.dumps({'url':url,'sha256':actual},indent=2)+'\n')
    if os.environ.get('GITHUB_ENV'):
        with Path(os.environ['GITHUB_ENV']).open('a',encoding='utf-8') as output:output.write(f'GHIDRA_INSTALL_DIR={installation}\n')
    print(f'Ghidra {a.version} download verified.')

if __name__=='__main__':main()
