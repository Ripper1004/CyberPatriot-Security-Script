#!/usr/bin/env bash
# Syntax-checks the shell blocks in the checklists: bash for the Linux ones,
# POSIX sh (dash + shellcheck) for FreeBSD. Also flags <placeholders> that a
# beginner would paste as-is (bash reads "<" as a redirect).
#   bash tests/checklists/check-shell.sh
cd "$(dirname "$0")/../.." || exit 1
python3 - <<'PY'
import json, re, subprocess, sys, pathlib, tempfile
sys.path.insert(0, 'tests/checklists')
from extract import blocks
bad = n = 0
for f, shells in (('linux-mint', ('bash',)), ('debian', ('bash',)), ('ubuntu', ('bash',)), ('freebsd', ('sh',))):
    for b in blocks(f'docs/checklists/{f}.md'):
        if b['lang'] not in ('bash', 'sh'):
            continue
        n += 1
        # a <placeholder> outside quotes and comments
        for ln in b['code'].split('\n'):
            code = ln.split('#')[0]
            if re.search(r"<[A-Za-z][A-Za-z _-]*>", re.sub(r"(['\"]).*?\1", '', code)):
                bad += 1; print(f"PLACEHOLDER {f}.md:{b['line']} [{b['step']}] {ln.strip()[:80]}")
        interp = 'bash' if b['lang'] == 'bash' else 'dash'
        r = subprocess.run([interp, '-n'], input=b['code'], text=True, capture_output=True)
        if r.returncode and '<' not in b['code']:
            bad += 1; print(f"SYNTAX {f}.md:{b['line']} [{b['step']}] {r.stderr.strip().splitlines()[0]}")
        if b['lang'] == 'sh':
            with tempfile.NamedTemporaryFile('w', suffix='.sh') as t:
                t.write('#!/bin/sh\n' + b['code'] + '\n'); t.flush()
                r = subprocess.run(['shellcheck', '-s', 'sh', '-S', 'error', t.name], text=True, capture_output=True)
                if r.returncode:
                    bad += 1; print(f"SHELLCHECK {f}.md:{b['line']} [{b['step']}]\n" + r.stdout.strip()[:400])
print(f'checked {n} shell blocks: {bad} problem(s)')
sys.exit(1 if bad else 0)
PY
