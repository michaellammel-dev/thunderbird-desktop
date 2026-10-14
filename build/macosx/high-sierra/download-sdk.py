import hashlib
import os
import pathlib
import shutil
import subprocess
import sys

url = 'https://swcdn.apple.com/content/downloads/09/08/047-91568-A_Y1CFZWQCD4/4xekpyz43i26dbp4enxfro8eb1q7wiujh5/CLTools_macOSNMOS_SDK.pkg'
expected = '5db8b5a06a489a7d3ec587ebb7e01be55163128029923fc24edcad47faecd67830193c0d91e2643ee0e92f2ccca37adf20e4c42cf8de5784666f8663638b5cc5'
root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
sdk = root / 'MacOSX26.5.sdk'
if not sdk.is_dir():
    package = root / 'CLToolsSDK.pkg'
    expanded = root / 'expanded'
    subprocess.run(['curl', '--fail', '--location', '--retry', '3', '--output', str(package), url], check=True)
    digest = hashlib.sha512()
    with package.open('rb') as handle:
        while chunk := handle.read(16 * 1024**2):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise RuntimeError('Apple SDK package checksum differs from the pinned Mozilla manifest')
    subprocess.run(['pkgutil', '--expand-full', str(package), str(expanded)], check=True)
    candidates = {p.resolve() for p in expanded.rglob('MacOSX26.5.sdk') if p.is_dir()}
    if len(candidates) != 1:
        raise RuntimeError(f'Expected one macOS 26.5 SDK, found {candidates}')
    candidate = candidates.pop()
    if expanded not in candidate.parents:
        raise RuntimeError('Expanded SDK is outside its working directory')
    shutil.move(str(candidate), str(sdk))
    if expanded.parent == root and expanded.name == 'expanded':
        shutil.rmtree(expanded)
    package.unlink()
if not (sdk / 'SDKSettings.plist').is_file():
    raise RuntimeError('SDKSettings.plist is missing')
with pathlib.Path(os.environ['GITHUB_ENV']).open('a') as handle:
    handle.write(f'MACOS_SDK_DIR={sdk}\n')
print(f'Using macOS SDK: {sdk}', flush=True)
