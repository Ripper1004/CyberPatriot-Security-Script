#!/usr/bin/env python3
"""Checks the structure of the checklists, so edits can't silently break ticks or links.

  python3 tests/checklists/check-format.py                 # all six
  python3 tests/checklists/check-format.py docs/checklists/debian.md

Errors (exit 1):  duplicate heading ids (saved ticks would collide), a step with no
                  "**Script:**" tag (the site build fails on this), numbering
                  gaps/repeats (2.1, 2.2, 2.4 ...). With --strict also: no "**What:**".
Warnings:         example names other than alice, bob, carol, erin, mallory in a
                  user command (the "use your names" feature only swaps those five).
"""
import pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from extract import steps, HEADING

ALLOWED = {'alice', 'bob', 'carol', 'erin', 'mallory'}
USERCMD = re.compile(r'\b(?:userdel|deluser|adduser|useradd|usermod|chage|pw (?:userdel|usermod|useradd)|Remove-LocalUser|New-LocalUser|Disable-LocalUser|Enable-LocalUser|Add-LocalGroupMember|Remove-LocalGroupMember|net user)\b(.*)')


STRICT = '--strict' in sys.argv


def check(path):
    errs, warns = [], []
    text = pathlib.Path(path).read_text().splitlines()
    heads = [(n, m.group(1), m.group(2)) for n, l in enumerate(text, 1) if (m := HEADING.match(l)) and not l.startswith('```')]
    # code fences hide fake headings (e.g. "# comment" lines) - HEADING only matches ##..####, fine
    seen = {}
    for s in steps(path):
        if s['id'] in seen:
            errs.append(f"{path}:{s['line']} duplicate heading id '{s['id']}' (also line {seen[s['id']]})")
        seen[s['id']] = s['line']
        if s['done'] and not s['script'] and 'fast path' not in s['heading'].lower():
            errs.append(f"{path}:{s['line']} step '{s['heading']}' has no **Script:** tag")
    # What: present for every step with a Done box
    cur = None; body = {}
    in_code = False
    for n, l in enumerate(text, 1):
        if l.startswith('```'):
            in_code = not in_code
        if in_code:
            continue
        m = HEADING.match(l)
        if m:
            cur = (n, m.group(2)); body[cur] = []
        elif cur:
            body[cur].append(l)
    for (n, h), lines in body.items():
        if STRICT and '- [ ] Done' in lines and not any(l.startswith('**What:**') for l in lines):
            errs.append(f"{path}:{n} step '{h}' has no **What:**")
    # numbering: "## N. Title" then "### N.M Title"
    sec = None; last = {}
    prev_sec = None
    for n, lvl, h in heads:
        m = re.match(r'(\d+)\.\s', h)
        if lvl == '##' and m:
            k = int(m.group(1))
            if prev_sec is not None and k != prev_sec + 1:
                errs.append(f"{path}:{n} section numbering jumps from {prev_sec} to {k}")
            prev_sec = k; sec = k; last[sec] = 0
        m = re.match(r'(\d+)\.(\d+)\s', h)
        if lvl == '###' and m:
            a, b = int(m.group(1)), int(m.group(2))
            if a != sec:
                errs.append(f"{path}:{n} step '{h}' sits in section {sec}")
            elif b != last.get(a, 0) + 1 and not (b == 1 and last.get(a, 0) == 0):
                errs.append(f"{path}:{n} step numbering in section {a}: {last.get(a, 0)} -> {b}")
            last[a] = b
    # example names: the argument that names the user in a user command
    in_code = False
    SYSTEM = {'root', 'administrator', 'guest', 'defaultaccount', 'wdagutilityaccount', 'admin', 'krbtgt', 'daemon', 'nobody', 'toor', 'www', 'sudo', 'adm', 'wheel', 'operator', 'users', 'administrators', 'sysadmin', 'shadow', 'disk', 'lpadmin', 'sambashare', 'docker'}
    for n, l in enumerate(text, 1):
        if l.startswith('```'):
            in_code = not in_code
            continue
        if not in_code:
            continue
        code = l.split('#')[0]
        cands = []
        m = re.search(r'\b(?:sudo\s+)?(?:userdel|deluser|adduser|useradd|chage|usermod|pw\s+(?:userdel|usermod|useradd)|passwd|chpasswd)\b(.*)', code)
        if m:
            bare = [t for t in re.findall(r'(?:^|\s)([A-Za-z_][\w.-]*)(?=\s|$)', m.group(1)) if not t.startswith('-')]
            if bare:
                cands.append(bare[-1])
        m = re.search(r'\bnet\s+user\s+([A-Za-z_][\w.-]*)', code)
        if m:
            cands.append(m.group(1))
        m = re.search(r'\b(?:New|Remove|Disable|Enable|Set|Get)-LocalUser\b.*?-(?:Name)\s+([A-Za-z_][\w.-]*)', code)
        if m:
            cands.append(m.group(1))
        for tok in cands:
            if tok.lower() not in ALLOWED and tok.lower() not in SYSTEM and not tok.startswith('$') and tok.isidentifier() or (tok.lower() not in ALLOWED and tok.lower() not in SYSTEM and re.fullmatch(r'[a-z][a-z0-9_-]+', tok)):
                warns.append(f"{path}:{n} example name '{tok}' (use alice, bob, carol, erin or mallory) in: {l.strip()[:70]}")
    return errs, warns


if __name__ == '__main__':
    files = sys.argv[1:] or sorted(str(p) for p in pathlib.Path(__file__).resolve().parents[2].glob('docs/checklists/*.md'))
    E = W = 0
    for f in files:
        e, w = check(f)
        for x in e: print('ERROR  ', x)
        for x in w: print('warning', x)
        E += len(e); W += len(w)
    print(f'{len(files)} checklist(s): {E} error(s), {W} warning(s)')
    sys.exit(1 if E else 0)
