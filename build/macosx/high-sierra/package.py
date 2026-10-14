import hashlib
import pathlib
import plistlib
import re
import subprocess
import sys

dist, output = map(pathlib.Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
apps = list(dist.glob('*.app'))
if len(apps) != 1:
    raise RuntimeError(f'Expected one application bundle, found {apps}')
app = apps[0]
with (app / 'Contents/Info.plist').open('rb') as handle:
    info = plistlib.load(handle)

def version(value):
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * (3 - len(parts))

if version(info['LSMinimumSystemVersion']) > (10, 13, 0):
    raise RuntimeError('App metadata requires a newer macOS')

report, failures, count = [], [], 0
for path in sorted(app.rglob('*')):
    if not path.is_file() or path.is_symlink():
        continue
    description = subprocess.check_output(['/usr/bin/file', '-b', str(path)], text=True)
    if 'Mach-O' not in description:
        continue
    count += 1
    if 'x86_64' not in description or 'arm64' in description:
        failures.append(f'{path}: unexpected architecture {description.strip()}')
    commands = subprocess.check_output(['/usr/bin/otool', '-l', str(path)], text=True)
    targets = []
    for command in re.split(r'^Load command \d+\s*$', commands, flags=re.M):
        if re.search(r'^\s+cmd LC_BUILD_VERSION\s*$', command, re.M):
            field = 'minos'
        elif re.search(r'^\s+cmd LC_VERSION_MIN_MACOSX\s*$', command, re.M):
            field = 'version'
        else:
            continue
        match = re.search(r'^\s+' + field + r'\s+(\d+\.\d+(?:\.\d+)?)\s*$', command, re.M)
        if match:
            targets.append(match.group(1))
    report.append(f'{path.relative_to(app)}: targets={targets}, {description.strip()}')
    if not targets or any(version(target) > (10, 13, 0) for target in targets):
        failures.append(f'{path}: deployment targets {targets}')
    report.append(subprocess.check_output(['/usr/bin/otool', '-L', str(path)], text=True))
(output / 'macho-audit.txt').write_text('\n'.join(report), encoding='utf-8')
if not count or failures:
    raise RuntimeError('\n'.join(failures) or 'No Mach-O executables inspected')
executable = app / 'Contents/MacOS' / info['CFBundleExecutable']
subprocess.run([str(executable), '--version'], check=True, timeout=60)
archive = output / 'Thunderbird-High-Sierra-test.zip'
subprocess.run(['/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(app), str(archive)], check=True)
(output / 'SHA256SUMS.txt').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
(output / 'TESTEN.txt').write_text(
    'Experimenteller Thunderbird-Testbuild fuer Intel und macOS 10.13.\n'
    'Die Kompatibilitaet mit High Sierra ist noch nicht zur Laufzeit bestaetigt.\n'
    'ZIP entpacken und die enthaltene App in einen separaten Testordner kopieren.\n'
    'Mit einem neuen Profil starten, um vorhandene Maildaten zu erhalten:\n'
    f'"/absoluter/Pfad/{app.name}/Contents/MacOS/{info["CFBundleExecutable"]}" -no-remote -ProfileManager\n'
    'Ein neues Profil anlegen und damit Start, Mailabruf, Versand und Anhaenge testen.\n'
    'Bei Fehlern die genaue macOS-Version, Fehlermeldung und den Absturzbericht mitteilen.\n'
    'Offizielle automatische Updates sind fuer diesen Build deaktiviert.\n', encoding='utf-8')
