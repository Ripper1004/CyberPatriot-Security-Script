#!/usr/bin/env python3
"""Pull the code blocks (and step metadata) out of the checklists.

  python3 tests/checklists/extract.py docs/checklists/linux-mint.md           # code blocks, JSON lines
  python3 tests/checklists/extract.py --steps docs/checklists/linux-mint.md   # steps with their Script tag

Each code block is {file, step, line, lang, code}; "step" is the nearest heading.
"""
import json, pathlib, re, sys

HEADING = re.compile(r'^(#{2,4})\s+(.*?)\s*$')
FENCE = re.compile(r'^```\s*([A-Za-z0-9_+-]*)\s*$')
SCRIPT = re.compile(r'^\*\*Script:\*\*\s*(✅|🔎|✋)')


def slug(text):
    """Close to github-slugger: what Starlight uses for heading ids."""
    return re.sub(r'[^\w\- ]', '', text.lower()).replace(' ', '-')


def blocks(path):
    step, in_code, lang, buf, start = '', False, '', [], 0
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        if in_code:
            if line.startswith('```'):
                yield {'file': str(path), 'step': step, 'line': start, 'lang': lang, 'code': '\n'.join(buf)}
                in_code = False
            else:
                buf.append(line)
            continue
        m = HEADING.match(line)
        if m:
            step = m.group(2)
            continue
        m = FENCE.match(line)
        if m:
            in_code, lang, buf, start = True, m.group(1).lower() or 'text', [], n


def steps(path):
    """One record per heading that carries a '- [ ] Done' item, or per inline checklist section."""
    cur = None
    out = []
    in_code = False
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        if line.startswith('```'):
            in_code = not in_code
        if in_code:
            continue
        m = HEADING.match(line)
        if m:
            cur = {'file': str(path), 'line': n, 'heading': m.group(2), 'id': slug(m.group(2)), 'script': None, 'check': '', 'done': False, 'items': 0}
            out.append(cur)
            continue
        if not cur:
            continue
        if line.strip() == '- [ ] Done':
            cur['done'] = True
        elif line.startswith('- [ ] '):
            cur['items'] += 1
        s = SCRIPT.match(line)
        if s:
            cur['script'] = {'✅': 'auto', '🔎': 'review', '✋': 'manual'}[s.group(1)]
        if line.startswith('**Check it worked:**'):
            cur['check'] = line[len('**Check it worked:**'):].strip()
    return [s for s in out if s['done'] or s['items']]


if __name__ == '__main__':
    args = sys.argv[1:]
    mode = steps if args and args[0] == '--steps' else blocks
    for p in (args[1:] if mode is steps else args):
        for rec in mode(p):
            print(json.dumps(rec, ensure_ascii=False))
