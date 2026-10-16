import io
import pathlib
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import package


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.app = self.root / 'mounted/Release.app'
        self.output = self.root / 'output'
        self.exe = self.app / 'Contents/MacOS/thunderbird'
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(b'executable')
        (self.exe.parent / 'libtest.dylib').write_bytes(b'library')
        self.jar = self.app / 'Contents/Resources/omni.ja'
        self.jar.parent.mkdir(parents=True)
        self.make_jar()
        with (self.app / 'Contents/Info.plist').open('wb') as output:
            plistlib.dump({'LSMinimumSystemVersion': '10.13', 'CFBundleExecutable': 'thunderbird'}, output)
        self.minimum = '10.13'
        self.architecture = 'x86_64'
        self.startup_fails = False

    def make_jar(self, omit=None):
        with zipfile.ZipFile(self.jar, 'w') as archive:
            for name in ['nsAsyncShutdown.sys.mjs', 'xul.css', 'html.css', 'profileSelection.js']:
                if name != omit:
                    archive.writestr('resources/' + name, b'nonempty resource')

    def inspect(self, command, **kwargs):
        if command[0].endswith('/file'):
            if command[-1].endswith(('.plist', '.ja')):
                return 'resource file'
            return f'Mach-O 64-bit executable {self.architecture}'
        if command[1] == '-L':
            return '/usr/lib/libSystem.B.dylib\n'
        target = self.minimum if command[-1].endswith('.dylib') else '10.13'
        return f'Load command 0\n cmd LC_VERSION_MIN_MACOSX\n version {target}\n sdk 26.5\n'

    def execute(self, command, **kwargs):
        if command[0].endswith('/ditto'):
            with zipfile.ZipFile(command[-1], 'w') as archive:
                for path in self.app.rglob('*'):
                    if path.is_file():
                        archive.write(path, self.app.name + '/' + path.relative_to(self.app).as_posix())
        elif command[-1] == '--version' and self.startup_fails:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    def build(self):
        with mock.patch('subprocess.check_output', side_effect=self.inspect), \
             mock.patch('subprocess.run', side_effect=self.execute):
            package.package_app(self.app, self.output)

    def test_complete_package(self):
        self.build()
        self.assertTrue((self.output / 'Thunderbird-High-Sierra-test.zip').is_file())
        self.assertTrue((self.output / 'resource-audit.txt').is_file())

    def test_missing_resource_rejected(self):
        self.make_jar(omit='nsAsyncShutdown.sys.mjs')
        with self.assertRaisesRegex(RuntimeError, 'nsAsyncShutdown'):
            self.build()
        self.assertFalse((self.output / 'Thunderbird-High-Sierra-test.zip').exists())

    def test_developer_bundle_without_omnijar_rejected(self):
        self.jar.unlink()
        with self.assertRaisesRegex(RuntimeError, 'omni.ja'):
            self.build()

    def test_newer_library_rejected(self):
        self.minimum = '10.15'
        with self.assertRaisesRegex(RuntimeError, 'deployment targets'):
            self.build()

    def test_wrong_architecture_rejected(self):
        self.architecture = 'arm64'
        with self.assertRaisesRegex(RuntimeError, 'architecture'):
            self.build()

    def test_failed_start_rejected(self):
        self.startup_fails = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.build()

    def test_external_zip_link_rejected(self):
        self.build()
        archive = self.output / 'Thunderbird-High-Sierra-test.zip'
        with zipfile.ZipFile(archive, 'a') as output:
            entry = zipfile.ZipInfo(self.app.name + '/Contents/Resources/build-link')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            output.writestr(entry, '/Users/runner/build/source')
        with self.assertRaisesRegex(RuntimeError, 'External ZIP symlink'):
            package.audit_zip(archive, self.app.name)

    def test_optimized_omnijar_directory(self):
        data = self.jar.read_bytes()
        end = data.rindex(b'PK\x05\x06')
        size, offset = struct.unpack_from('<II', data, end + 12)
        self.jar.write_bytes(struct.pack('<I', 0) + data[offset:offset + size] + data[end:] + data[:offset])
        self.assertEqual(len(package.jar_entries(self.jar)), 4)
        package.audit_resources(self.app)

    def test_mount_selects_release_app_not_developer_app(self):
        dist = self.root / 'dist'
        dist.mkdir()
        (dist / 'Developer.app').mkdir()
        (dist / 'thunderbird.en-US.mac.dmg').write_bytes(b'disk image fixture')
        mounted = plistlib.dumps({'system-entities': [{'mount-point': str(self.app.parent)}]})
        with mock.patch('subprocess.check_output', return_value=mounted), \
             mock.patch('subprocess.run') as detach:
            with package.mounted_release_app(dist) as app:
                self.assertEqual(app, self.app)
            detach.assert_called_once_with(['/usr/bin/hdiutil', 'detach', str(self.app.parent)], check=True)

    def test_mount_detached_on_validation_error(self):
        dist = self.root / 'dist'
        dist.mkdir()
        (dist / 'thunderbird.mac.dmg').write_bytes(b'disk image fixture')
        mounted = plistlib.dumps({'system-entities': [{'mount-point': str(self.app.parent)}]})
        with mock.patch('subprocess.check_output', return_value=mounted), \
             mock.patch('subprocess.run') as detach:
            with self.assertRaisesRegex(RuntimeError, 'test failure'):
                with package.mounted_release_app(dist):
                    raise RuntimeError('test failure')
            detach.assert_called_once()


if __name__ == '__main__':
    unittest.main()
