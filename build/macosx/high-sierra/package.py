import hashlib
import pathlib
import plistlib
import re
import subprocess
import sys


import contextlib
import posixpath
import stat
import struct
import zipfile


@contextlib.contextmanager
def mounted_release_app(dist):
    images = list(dist.glob('*.mac.dmg'))
    if len(images) != 1:
        raise RuntimeError(f'Expected one release disk image, found {images}')
    attached = plistlib.loads(subprocess.check_output([
        '/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-plist', str(images[0])
    ]))
    mounts = [pathlib.Path(e['mount-point']) for e in attached['system-entities']
              if 'mount-point' in e]
    with contextlib.ExitStack() as cleanup:
        for mount in mounts:
            cleanup.callback(subprocess.run, ['/usr/bin/hdiutil', 'detach', str(mount)], check=True)
        apps = [app for mount in mounts for app in mount.glob('*.app')]
        if len(apps) != 1:
            raise RuntimeError(f'Expected one release app in the disk image, found {apps}')
        yield apps[0]


def jar_entries(path):
    # Mozilla optimized omnijars place their central directory at byte 4.
    data = path.read_bytes()
    if data[4:8] != b'PK\x01\x02':
        with zipfile.ZipFile(path) as archive:
            return {e.filename: e.file_size for e in archive.infolist()}
    offset, entries = 4, {}
    while data[offset:offset + 4] == b'PK\x01\x02':
        if offset + 46 > len(data):
            raise RuntimeError('Truncated omnijar directory')
        name_len, extra_len, comment_len = struct.unpack_from('<HHH', data, offset + 28)
        size = struct.unpack_from('<I', data, offset + 24)[0]
        end = offset + 46 + name_len + extra_len + comment_len
        if end > len(data):
            raise RuntimeError('Invalid omnijar entry length')
        name = data[offset + 46:offset + 46 + name_len].decode('utf-8')
        entries[name] = size
        offset = end
    if not entries or data[offset:offset + 4] != b'PK\x05\x06':
        raise RuntimeError('Invalid optimized omnijar directory')
    return entries


def audit_resources(app):
    root = app.resolve()
    for path in app.rglob('*'):
        if path.is_symlink():
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError, RuntimeError) as error:
                raise RuntimeError(f'Broken or external app symlink: {path}') from error
    jar = app / 'Contents/Resources/omni.ja'
    if not jar.is_file() or jar.is_symlink():
        raise RuntimeError('The release app must contain its own Resources/omni.ja')
    entries = jar_entries(jar)
    for required in ['nsAsyncShutdown.sys.mjs', 'xul.css', 'html.css', 'profileSelection.js']:
        if not any(pathlib.PurePosixPath(name).name == required and size > 0
                   for name, size in entries.items()):
            raise RuntimeError(f'Missing core resource in omni.ja: {required}')
    return f'omni.ja: {len(entries)} entries; required startup resources present\n'


def audit_zip(path, app_name):
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if f'{app_name}/Contents/Resources/omni.ja' not in names:
            raise RuntimeError('Final ZIP is missing the core resource archive')
        for entry in archive.infolist():
            if not stat.S_ISLNK(entry.external_attr >> 16):
                continue
            target = archive.read(entry).decode('utf-8')
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(entry.filename), target))
            if posixpath.isabs(target) or not resolved.startswith(app_name + '/'):
                raise RuntimeError(f'External ZIP symlink: {entry.filename} -> {target}')
            if resolved not in names and not any(n.startswith(resolved.rstrip('/') + '/') for n in names):
                raise RuntimeError(f'Broken ZIP symlink: {entry.filename} -> {target}')
        if archive.testzip() is not None:
            raise RuntimeError('Final app ZIP failed its integrity check')


def package_app(app, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'resource-audit.txt').write_text(audit_resources(app), encoding='utf-8')
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
    try:
        audit_zip(archive, app.name)
    except Exception:
        archive.unlink(missing_ok=True)
        raise
    (output / 'SHA256SUMS.txt').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
    (output / 'TESTEN.txt').write_text(
        'Experimenteller Thunderbird-Testbuild fuer Intel und macOS 10.13.\n'
        'Die Kompatibilitaet mit High Sierra ist noch nicht zur Laufzeit bestaetigt.\n'
        'Die native Sprachausgabe der Web Speech API ist in diesem Testbuild deaktiviert.\n'
        'Die Metal-Beschleunigung fuer lokale KI-Modelle ist in diesem Testbuild deaktiviert.\n'
        'Die ONNX-Laufzeit fuer lokale KI-Funktionen ist nicht enthalten (benoetigt macOS 10.15).\n'
        'ZIP entpacken und die enthaltene App in einen separaten Testordner kopieren.\n'
        'Mit einem neuen Profil starten, um vorhandene Maildaten zu erhalten:\n'
        f'"/absoluter/Pfad/{app.name}/Contents/MacOS/{info["CFBundleExecutable"]}" -no-remote -ProfileManager\n'
        'Ein neues Profil anlegen und damit Start, Mailabruf, Versand und Anhaenge testen.\n'
        'Bei Fehlern die genaue macOS-Version, Fehlermeldung und den Absturzbericht mitteilen.\n'
        'Offizielle automatische Updates sind fuer diesen Build deaktiviert.\n', encoding='utf-8')


def main():
    dist, output = map(pathlib.Path, sys.argv[1:])
    with mounted_release_app(dist) as app:
        package_app(app, output)


if __name__ == '__main__':
    main()
