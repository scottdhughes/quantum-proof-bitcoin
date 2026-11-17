# L actual Docker Desktop recovery evidence

The complete original selected packet is preserved unchanged inside
[`packet.tar.gz`](packet.tar.gz), under one `packet/` root. Its original README,
checksum seals, reports, source fixtures and POSIX modes are included. This
storage format keeps historical evidence files from being collected as live
repository code or patches by CI. No original evidence or lint rule was changed.

Archive SHA256: `234b59ed7eb8960a090de1a815755085bef97ddc41b5c56b8446c481f8aec812`.
The [checksum](packet.tar.gz.sha256) and [member index](packet-index.json) bind
the archive and every original member's bytes, type and mode. Hashes check
byte custody; they do not establish signer authenticity. Archive ownership and
timestamps are normalized for reproducibility, not asserted as historical
filesystem metadata.

This packet retains its original qualification scope and exclusions. It does
not qualify later source, establish a completed public soak, or claim human
review or production admission. The native/CI data cover selected Linux profiles
and private HTTP flows; the Desktop data cover actual Docker Desktop recovery
and explicitly exclude an operating-system reboot. The original README inside
the archive provides the packet-specific result, failed attempts and limits.
No private wallet records, credentials, runtime state, binaries or images are
added by this archive.

From this directory on a POSIX system, the following Python-standard-library
command verifies hashes and exact safe member closure, creates a fresh temporary
directory, restores original modes, and runs the original offline verifier and
negative controls. It never starts a node or Docker. The temporary directory is
retained for inspection; its path is printed. Python 3.11 or newer is suitable.

```sh
python3 -I -B - <<'PY'
"""Bounded, mode-preserving extraction used verbatim in the two wrapper READMEs."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import tarfile
import tempfile


def require(value, gate):
    if not value:
        raise ValueError(gate)


def extract_packet(folder, destination_parent=None):
    folder = Path(folder)
    index = json.loads((folder / 'packet-index.json').read_bytes())
    blob = (folder / 'packet.tar.gz').read_bytes()
    checksum = (folder / 'packet.tar.gz.sha256').read_text().split()
    require(index['schema'] == 'PQBTC-ARCHIVED-EVIDENCE-PACKET-1' and len(blob) <= 4 * 1024 * 1024, 'ARCHIVE_BOUND')
    require(checksum == [index['archive_sha256'], 'packet.tar.gz']
            and hashlib.sha256(blob).hexdigest() == checksum[0], 'ARCHIVE_HASH')
    require(type(index['tar_bytes']) is int and 0 < index['tar_bytes'] <= 8 * 1024 * 1024, 'TAR_BOUND')
    with gzip.GzipFile(fileobj=io.BytesIO(blob)) as compressed:
        raw = compressed.read(index['tar_bytes'] + 1)
        require(len(raw) == index['tar_bytes'] and not compressed.read(1), 'TAR_SIZE')
    records = index['members']
    require(type(records) is list and 0 < len(records) <= 256, 'MEMBER_COUNT')
    expected = {}
    for record in records:
        name = record['path']
        path = PurePosixPath(name)
        require(type(name) is str and path.parts and path.parts[0] == 'packet' and not path.is_absolute()
                and path.as_posix() == name and '\\' not in name and not {'.', '..'}.intersection(path.parts), 'UNSAFE_MEMBER_PATH')
        require(name not in expected, 'DUPLICATE_MEMBER')
        require(record['type'] in ('file', 'directory') and len(record['mode']) == 4
                and all(value in '01234567' for value in record['mode'])
                and int(record['mode'], 8) <= 0o777, 'MEMBER_TYPE_MODE')
        require(type(record['bytes']) is int and 0 <= record['bytes'] <= 1024 * 1024, 'MEMBER_SIZE')
        expected[name] = record
    require(expected.get('packet', {}).get('type') == 'directory', 'PACKET_ROOT')
    files, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            require(member.name in expected and member.name not in seen, 'EXACT_MEMBER_CLOSURE')
            record = expected[member.name]
            require(not member.linkname and not member.pax_headers
                    and member.type in (tarfile.REGTYPE, tarfile.DIRTYPE), 'LINK_OR_SPECIAL_MEMBER')
            require(('file' if member.isfile() else 'directory') == record['type']
                    and member.mode == int(record['mode'], 8) and member.size == record['bytes'], 'MEMBER_METADATA')
            if member.isfile():
                value = archive.extractfile(member).read(record['bytes'] + 1)
                require(len(value) == record['bytes'] and hashlib.sha256(value).hexdigest() == record['sha256'], 'MEMBER_HASH')
                files[member.name] = value
            seen.add(member.name)
    require(seen == set(expected) and len(files) == index['file_count'], 'EXACT_MEMBER_CLOSURE')
    output = Path(tempfile.mkdtemp(prefix='pqbtc-packet-', dir=destination_parent)).resolve()
    for name in sorted(expected, key=lambda value: (len(PurePosixPath(value).parts), value)):
        record, target = expected[name], output.joinpath(*PurePosixPath(name).parts)
        if record['type'] == 'directory':
            target.mkdir(mode=0o700)
        else:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(files[name])
    for name in sorted(expected, key=lambda value: -len(PurePosixPath(value).parts)):
        os.chmod(output.joinpath(*PurePosixPath(name).parts), int(expected[name]['mode'], 8))
    return output / 'packet'

import subprocess
import sys

packet = extract_packet(Path.cwd())
print("Extracted original packet:", packet, flush=True)
subprocess.run([sys.executable, "-I", "-B", str(packet / "verify.py")], check=True)
subprocess.run([sys.executable, "-I", "-B", str(packet / "negative-controls.py")], check=True)
PY
```
