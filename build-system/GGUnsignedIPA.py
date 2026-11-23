"""Package a locally built device IPA on macOS, or verify the finished ZIP on any OS."""
import argparse
import os
import plistlib
import posixpath
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


APP = 'Payload/Ghostgram.app'
EXTENSIONS = {'Share', 'NotificationContent', 'NotificationService', 'SiriIntents', 'Widget', 'BroadcastUpload'}
MAGICS = {bytes.fromhex(s) for s in ('cffaedfe', 'feedfacf', 'cefaedfe', 'feedface',
                                     'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def macho(stream, path):
    # Device outputs here are single-slice. Reject other targets even if also labelled arm64.
    magic, cpu, subtype, kind, count, size, _, _ = struct.unpack('<8I', stream.read(32))
    require((magic, cpu, subtype & 0xffffff) == (0xfeedfacf, 0x100000c, 0), f'{path}: expected thin ARM64')
    require(kind in (2, 6, 8) and size <= 8 * 1024 * 1024, f'{path}: invalid Mach-O header')
    data = stream.read(size)
    require(len(data) == size, f'{path}: truncated load commands')
    offset, ios = 0, False
    dependencies, runpaths = [], []
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', data, offset)
        require(length >= 8 and offset + length <= size, f'{path}: malformed load command')
        chunk = data[offset:offset + length]
        if cmd == 0x32:
            require(struct.unpack_from('<I', chunk, 8)[0] == 2, f'{path}: wrong Apple platform')
            ios = True
        elif cmd == 0x25:
            ios = True
        elif cmd == 0x1d:
            raise ValueError(f'{path}: code signature still present')
        elif cmd in (0x21, 0x2c):
            require(struct.unpack_from('<I', chunk, 16)[0] == 0, f'{path}: encrypted Mach-O')
        elif cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20, 0x8000001c):
            start = struct.unpack_from('<I', chunk, 8)[0]
            name = chunk[start:].split(b'\0', 1)[0].decode()
            require(name, f'{path}: empty dynamic loader path')
            (runpaths if cmd == 0x8000001c else dependencies).append(name)
        offset += length
    require(ios and offset == size, f'{path}: invalid iPhoneOS load commands')
    return kind, dependencies, runpaths


def resolve_dependencies(images, executable, extra=()):
    def expand(path, loader):
        for key, base in (('@loader_path', loader), ('@executable_path', executable)):
            if path.startswith(key + '/'):
                return posixpath.normpath(posixpath.join(posixpath.dirname(base), path[len(key) + 1:]))
        return path

    def system(path):
        return path.startswith(('/usr/lib/', '/System/Library/'))

    visited = set()
    def visit(loader, inherited):
        if loader in visited:
            return
        visited.add(loader)
        _, deps, paths = images[loader]
        paths = [expand(path, loader) for path in paths] + inherited
        for dependency in deps:
            if dependency.startswith('@rpath/'):
                options = [posixpath.normpath(posixpath.join(base, dependency[7:])) for base in paths]
            else:
                options = [expand(dependency, loader)]
            match = next((p for p in options if p in images), None)
            if match:
                visit(match, paths)
            else:
                require(any(system(p) and (not dependency.startswith('@rpath/') or
                            (p.startswith('/usr/lib/swift/libswift') and p.endswith('.dylib'))) for p in options),
                        f'{loader}: unresolved {dependency}')
    visit(executable, [])
    for path in extra:  # The VLESS module is opened with dlopen.
        visit(path, [expand(r, executable) for r in images[executable][2]])
    return visited


def verify(ipa):
    images, applications, bundles = {}, {}, {}
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'Duplicate ZIP member')
        for item in archive.infolist():
            name = item.filename
            parts = PurePosixPath(name).parts
            require(parts and not name.startswith('/') and '..' not in parts and '\\' not in name,
                    f'Unsafe ZIP path {name}')
            if name == 'Payload/':
                continue
            require(name.startswith(APP + '/'), f'Unexpected file outside app: {name}')
            require('_CodeSignature' not in parts and not name.endswith(('.mobileprovision', '.provisionprofile')),
                    f'Signing material in IPA: {name}')
            if item.is_dir():
                continue
            with archive.open(item) as stream:
                magic = stream.read(4)
                if magic in MAGICS:
                    require(item.external_attr >> 16 & 0o111, f'{name}: missing executable bit')
                    stream.seek(0)
                    images[name] = macho(stream, name)
                elif name.endswith('/Info.plist') and parts[-2].endswith(('.app', '.appex', '.framework')):
                    stream.seek(0)
                    bundles[posixpath.dirname(name)] = plistlib.load(stream)
        require(APP in bundles, 'Missing application Info.plist')
        main = bundles[APP]
        require(main['CFBundleIdentifier'] == 'org.ghostgram.app' and main['CFBundlePackageType'] == 'APPL'
                and 1 in main['UIDeviceFamily'] and 'iPhoneOS' in main['CFBundleSupportedPlatforms']
                and main['MinimumOSVersion'] and main['CFBundleVersion'] and main['CFBundleShortVersionString'],
                'Unexpected application metadata')
        for bundle, info in bundles.items():
            executable = bundle + '/' + info['CFBundleExecutable']
            require(executable in images, f'{bundle}: missing Mach-O executable')
            if bundle.endswith('.appex'):
                require(bundle.startswith(APP + '/PlugIns/') and info['CFBundleIdentifier'].startswith(main['CFBundleIdentifier'] + '.')
                        and info['NSExtension']['NSExtensionPointIdentifier'] and info['CFBundleVersion'] == main['CFBundleVersion'],
                        f'{bundle}: invalid extension metadata')
                applications[info['CFBundleIdentifier']] = executable
        require(set(applications) == {main['CFBundleIdentifier'] + '.' + ext for ext in EXTENSIONS},
                'Missing or unexpected app extensions')
        core = APP + '/Frameworks/GGXrayCore.framework/GGXrayCore'
        require(core in images, 'Missing VLESS framework')
        main_executable = APP + '/' + main['CFBundleExecutable']
        reachable = resolve_dependencies(images, main_executable, [core])
        for executable in applications.values():
            reachable.update(resolve_dependencies(images, executable))
        for path in images.keys() - reachable:
            resolve_dependencies(images, main_executable, [path])
        require(archive.testzip() is None, 'ZIP CRC check failed')
    print(f"Verified {main['CFBundleShortVersionString']} ({main['CFBundleVersion']}), iOS {main['MinimumOSVersion']}+, "
          f"{len(images)} unsigned ARM64 iPhoneOS binaries, {len(applications)} extensions and VLESS.")


def package(source, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        stage = Path(tmp)
        subprocess.run(['ditto', '-x', '-k', str(source.resolve()), str(stage)], check=True)
        for path in (stage / APP).rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic in MAGICS:
                commands = subprocess.check_output(['xcrun', 'otool', '-l', str(path)], text=True)
                if 'cmd LC_CODE_SIGNATURE' in commands:
                    path.chmod(path.stat().st_mode | stat.S_IWUSR)
                    subprocess.run(['codesign', '--remove-signature', str(path)], check=True)
        for directory in (stage / APP).rglob('_CodeSignature'):
            shutil.rmtree(directory)
        archive = stage / 'unsigned.ipa'
        subprocess.run(['/usr/bin/zip', '-q', '-y', '-r', str(archive.resolve()), 'Payload'], cwd=stage, check=True)
        verify(archive)
        os.replace(archive, output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('verify').add_argument('ipa', type=Path)
    pack = sub.add_parser('package')
    pack.add_argument('source', type=Path)
    pack.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.action == 'verify':
        verify(args.ipa)
    else:
        package(args.source, args.output)
