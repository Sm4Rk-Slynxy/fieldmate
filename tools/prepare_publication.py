#!/usr/bin/env python3
"""Create a source-only publication ZIP from an explicit allowlist, without git or network."""
import argparse
import hashlib
import re
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    '.gitignore', 'README.md', 'PUBLISHING.md', 'SECURITY.md', 'REVIEW.md',
    'VERIFICATION.md', 'pyproject.toml', 'launch.sh',
    'examples/network.xml', 'examples/issues.xml', 'examples/session.jsonl',
    'integrations/burp/build.gradle', 'integrations/burp/settings.gradle',
    'integrations/burp/src/main/java/fieldmate/FieldmateExtension.java',
    'docs/screenshots/overview.png',
}
TREES = {'fieldmate': {'.py', '.html', '.js', '.css', '.svg'},
         'tests': {'.py', '.cjs'}, 'tools': {'.py'}, '.github/workflows': {'.yml', '.yaml'}}
RULES = {
    'GitHub credential': re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})'),
    'AWS access key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'Slack credential': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b'),
    'private key material': re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----'),
    'personal home path': re.compile(r'(?:/home/[A-Za-z0-9_.-]+/|/Users/[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+\\)'),
    'credential in URL': re.compile(r'(?i)https?://[^\s/@:]+:[^\s/@]+@'),
}
# Deliberately synthetic fixtures are reviewed source. Production files have no exceptions.
FIXTURE_MATCHES = {'tests/test_fieldmate.py': {'https://' + 'user:password@', 'http://' + 'user:key@'}}


def public_files(root=ROOT):
    root = Path(root)
    selected = set()
    for name in FILES:
        path = root / name
        if not path.is_file() or path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
            raise ValueError(f'Missing or linked publication file: {name}')
        selected.add(path)
    for name, suffixes in TREES.items():
        directory = root / name
        if not directory.exists():
            continue
        for path in directory.rglob('*'):
            relative = path.relative_to(root)
            if '__pycache__' in relative.parts or any(part.startswith('.') for part in relative.parts[1:]):
                continue
            if path.is_file() and path.suffix in suffixes:
                if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root):
                    raise ValueError(f'Linked publication source: {relative.as_posix()}')
                selected.add(path)
    return sorted(selected, key=lambda p: p.relative_to(root).as_posix())


def audit(files, root=ROOT):
    findings = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.suffix == '.png':
            continue  # Only the explicitly selected and visually reviewed demo image.
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            for label, rule in RULES.items():
                for match in rule.finditer(line):
                    if match.group(0) not in FIXTURE_MATCHES.get(relative, set()):
                        findings.append(f'{relative}:{number}: {label}')
    return findings


def prepare(root=ROOT, output=None):
    root = Path(root).resolve()
    files = public_files(root)
    findings = audit(files, root)
    if findings:
        raise ValueError('Publication audit failed (matched values withheld):\n' + '\n'.join(findings))
    if output is not None:
        output = Path(output).resolve()
        if output in files:
            raise ValueError('Output must not overwrite publication source')
        with ZipFile(output, 'w', compression=ZIP_DEFLATED) as archive:
            manifest = []
            for path in files:
                name = path.relative_to(root).as_posix()
                data = path.read_bytes()
                entry = ZipInfo('fieldmate/' + name, date_time=(2026, 1, 1, 0, 0, 0))
                entry.compress_type = ZIP_DEFLATED
                entry.external_attr = (0o100755 if name == 'launch.sh' else 0o100644) << 16
                archive.writestr(entry, data)
                manifest.append(hashlib.sha256(data).hexdigest() + '  ' + name)
            archive.writestr('fieldmate/MANIFEST.sha256', '\n'.join(manifest) + '\n')
    return [p.relative_to(root).as_posix() for p in files]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional destination ZIP, outside the source allowlist')
    args = parser.parse_args()
    try:
        names = prepare(output=args.output)
    except ValueError as exc:
        parser.exit(1, str(exc) + '\n')
    print(f'Audited {len(names)} source/demo files. No matching credentials or personal home paths.')
    if args.output:
        print(f'Created {args.output.name}; runtime evidence and generated binaries are excluded.')
    else:
        print('\n'.join(names))
