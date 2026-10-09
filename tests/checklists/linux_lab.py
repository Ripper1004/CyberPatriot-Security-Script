#!/usr/bin/env python3
"""Run a Linux checklist's commands, in order, inside a throwaway container
that has the practice problems planted (tests/linux/plant-vulns.sh).

  python3 tests/checklists/linux_lab.py linux-mint            # Mint 21.3
  python3 tests/checklists/linux_lab.py debian
  python3 tests/checklists/linux_lab.py ubuntu
  python3 tests/checklists/linux_lab.py linux-mint --mode hardened   # run harden.sh --apply first
  python3 tests/checklists/linux_lab.py linux-mint --only "2."       # only steps whose heading starts "2."
  python3 tests/checklists/linux_lab.py linux-mint --install "cinnamon-desktop-data libpam-pwquality"
  python3 tests/checklists/linux_lab.py linux-mint --json out.json   # keep the raw results

What it reports (the exit code is 1 if there is any BUG):
  BUG      command not found, unrecognized option, usage error, unknown package,
           unknown gsettings schema/key, syntax error.
  CHECK    a missing file or an unknown service. Often fine (not installed on
           this image) - read it.
  ENV      expected in a container with no systemd, no GUI, no firewall rights.
  NOTE     a command exited non-zero without an error message (e.g. grep found nothing).
  SKIPPED  blocks with nothing runnable. Interactive/disruptive LINES (nano, reboot, ufw
           enable...) are replaced by a no-op and listed at the end - read them by hand.
  Also: every package named in apt install/purge/remove, every gsettings key and
  every /etc path is checked statically.

Needs Docker. Behind an HTTPS proxy with its own certificate (only needed for
--install) set TEST_CA=/path/ca.crt and https_proxy=http://host:port.
"""
import argparse, json, os, pathlib, re, subprocess, sys, uuid

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
from extract import blocks  # noqa: E402

IMAGES = {
    'linux-mint': 'cp-test-mint213',
    'debian': 'cp-test-debian12',
    'ubuntu': 'cp-test-ubuntu2204',
}

SKIP = [
    # an interactive program in command position (start of line, after sudo or a pipe), not a word in a grep pattern
    (r'(?:^|[;&|]\s*|\bsudo\s+)(?:nano|vim?|visudo|less|more|top|htop|watch)\b(?![-.])|\btail\s+-f\b', 'interactive'),
    (r'\b(reboot|shutdown|halt|poweroff|init [06])\b', 'reboots the machine'),
    (r'^\s*(sudo\s+)?(su|passwd\s+\w+|adduser\s+\w+|sudo -i|sudo su)\s*(#.*)?$', 'interactive'),
    (r'apt(-get)?\s+(full-)?(dist-)?upgrade|do-release-upgrade|apt(-get)?\s+update', 'slow, needs network'),
    (r'harden\.sh', 'the script itself is tested by tests/linux/run-tests.sh'),
    (r'\b(wget|curl|git clone)\b', 'needs network'),
    (r'\bufw\s+(--force\s+)?(reset|enable)|iptables', 'firewall: not possible in a container'),
    (r'\bnc\b.*-l|\bnetcat\b.*-l', 'starts a listener that never exits'),
    (r'\bmount\b.*-o\s+remount', 'remounts a filesystem'),
]

BUG = [
    (r'command not found', 'command not found'),
    (r'(unrecognized|invalid|unknown|illegal) option', 'bad option'),
    (r'^Usage:|usage:', 'usage error (wrong arguments?)'),
    (r'missing operand|unknown primary or operator|syntax error|unexpected (token|EOF)', 'syntax/argument error'),
    (r'Unable to locate package|has no installation candidate', 'unknown package'),
    (r'No such schema|No such key|is not installed.*schema', 'unknown gsettings schema/key'),
    (r'unknown user|invalid user|user .* does not exist', 'unknown user'),
]
CHECK = [
    (r'No such file or directory', 'missing file or directory'),
    (r'Unit .* (could not be found|not found)|not-found|Loaded: not-found', 'service not installed'),
]
ENV = [
    (r'not been booted with systemd|Failed to connect to bus|Running in chroot|System has not been booted', 'no systemd'),
    (r'Read-only file system|sysctl: .*(permission denied|cannot stat)', 'read-only /proc/sys'),
    (r'Operation not permitted|Permission denied', 'container permissions'),
    (r'Cannot autolaunch D-Bus|dconf-WARNING|Can.t open display|Failed to execute child process|No protocol specified', 'no desktop session'),
    (r'ERROR: .*(iptables|ufw)|Couldn.t determine iptables|ip6tables', 'no firewall in container'),
    (r'systemd-sysv|policy-rc\.d', 'no systemd'),
]


def sh(*cmd, input=None, timeout=None, check=False):
    return subprocess.run(cmd, input=input, text=True, capture_output=True, timeout=timeout, check=check)


def classify(rc, err):
    """Return (category, reason, offending line)."""
    for cat, table in (('BUG', BUG), ('ENV', ENV), ('CHECK', CHECK)):
        for line in err.splitlines():
            for pat, why in table:
                if re.search(pat, line, re.I):
                    return cat, why, line.strip()
    if rc not in (0, None):
        last = [l for l in err.splitlines() if 'does not have a stable CLI' not in l]
        return ('CHECK' if last else 'NOTE'), f'exit code {rc}', (last or [''])[-1]
    return 'OK', '', ''


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('checklist', choices=sorted(IMAGES))
    ap.add_argument('--mode', choices=['raw', 'hardened'], default='raw', help='raw = planted problems only; hardened = also run harden.sh --apply first')
    ap.add_argument('--only', help='only run steps whose heading starts with this text, e.g. "2."')
    ap.add_argument('--install', default='', help='extra apt packages to install first (needs network)')
    ap.add_argument('--json', help='write the raw results here')
    ap.add_argument('--keep', action='store_true', help='leave the container running afterwards (docker rm -f cplab-...)')
    ap.add_argument('--timeout', type=int, default=25)
    a = ap.parse_args()

    image = IMAGES[a.checklist]
    name = f'cplab-{a.checklist}-{uuid.uuid4().hex[:6]}'
    net = []
    if os.environ.get('TEST_CA'):
        net = ['--network', 'host', '-v', f"{os.environ['TEST_CA']}:/ca.crt:ro", '-e', f"https_proxy={os.environ.get('https_proxy', '')}"]
    sh('docker', 'run', '-d', '--name', name, *net, '-v', f'{REPO}:/repo:ro', image, 'sleep', 'infinity', check=True)

    def ex(code, timeout=None):
        try:
            r = sh('docker', 'exec', '-i', name, 'bash', '-s', input='export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8\nset +e\n' + code, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, '', f'timed out after {timeout}s'

    try:
        print(f'== {a.checklist} on {image}  (container {name})')
        if a.install:
            if os.environ.get('TEST_CA'):
                ex("sed -i 's#http://#https://#g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; echo 'Acquire::https::CAInfo \"/ca.crt\";' >/etc/apt/apt.conf.d/99ca")
            rc, out, err = ex(f'apt-get update -q >/dev/null 2>&1; apt-get install -y -q {a.install} 2>&1 | tail -3', 600)
            print(f'   installed extras: {out.strip() or err.strip()}')
        ex('bash /repo/tests/linux/plant-vulns.sh >/dev/null 2>&1', 120)
        if a.mode == 'hardened':
            rc, out, err = ex('cd /repo/scripts/linux && SUDO_USER=alice bash harden.sh --apply --yes --no-color --config /repo/tests/linux/test.conf >/tmp/apply.txt 2>&1; tail -3 /tmp/apply.txt', 900)
            print('   hardened first:', out.strip().replace('\n', ' | '))

        results = []
        pkgs, gkeys, paths, skips = {}, {}, {}, []
        for b in blocks(REPO / 'docs' / 'checklists' / f'{a.checklist}.md'):
            if b['lang'] not in ('bash', 'sh'):
                continue
            if a.only and not b['step'].startswith(a.only):
                continue
            code = b['code']
            tag = f"{b['step'][:48]} (line {b['line']})"
            # static facts to verify afterwards
            for m in re.finditer(r'apt(?:-get)?\s+(?:-\S+\s+)*(install|purge|remove)\s+([^\n#|;&]+)', code):
                for p in m.group(2).split():
                    if re.fullmatch(r'[a-z0-9][a-z0-9+.\-]+', p) and not p.startswith('-'):
                        pkgs.setdefault(p, tag)
            for m in re.finditer(r'gsettings\s+(?:get|set|reset)\s+(\S+)\s+(\S+)', code):
                gkeys.setdefault((m.group(1), m.group(2)), tag)
            for m in re.finditer(r'(?<![\w/.-])(/(?:etc|var|usr|lib|boot)/[A-Za-z0-9_./*-]+)', code):
                if '*' not in m.group(1) and not m.group(1).endswith('/'):
                    paths.setdefault(m.group(1), tag)

            # Skip only the interactive / disruptive lines, run the rest of the block.
            kept, skipped_lines = [], []
            for ln in code.split('\n'):
                why = next((w for pat, w in SKIP if re.search(pat, ln)), None)
                if why:
                    skipped_lines.append(f"{ln.strip()[:70]}  <- {why}")
                    kept.append(f": 'skipped: {why}'")
                else:
                    kept.append(ln)
            if skipped_lines:
                skips.append((tag, skipped_lines))
            if all(k.startswith(": 'skipped") or not k.strip() or k.lstrip().startswith('#') for k in kept):
                results.append({**b, 'cat': 'SKIPPED', 'why': skipped_lines[0] if skipped_lines else 'nothing to run', 'line_text': '', 'tag': tag})
                continue
            code = '\n'.join(kept)
            rc, out, err = ex(code, a.timeout)
            cat, why, line = classify(rc, err)
            results.append({**b, 'cat': cat, 'why': why, 'line_text': line, 'rc': rc, 'tag': tag, 'stderr': err[-600:]})

        # --- static checks
        static = []
        if pkgs:
            rc, out, err = ex('for p in ' + ' '.join(sorted(pkgs)) + '; do c=$(apt-cache policy "$p" 2>/dev/null | sed -n "s/^ *Candidate: //p"); echo "$p|${c:-NONE}"; done')
            for line in out.splitlines():
                p, c = line.split('|', 1)
                if c in ('NONE', '(none)'):
                    static.append(('BUG', f'package "{p}" does not exist on {image}', pkgs[p]))
        for (schema, key), where in sorted(gkeys.items()):
            rc, out, err = ex(f'gsettings list-keys {schema} 2>&1 | grep -qx {key} && echo ok || (gsettings list-schemas 2>/dev/null | grep -qx {schema} && echo nokey || echo noschema)')
            r = out.strip()
            if r == 'nokey':
                static.append(('BUG', f'gsettings schema {schema} has no key "{key}"', where))
            elif r == 'noschema':
                static.append(('CHECK', f'gsettings schema {schema} is not installed here (install cinnamon-desktop-data / gnome schemas to verify "{key}")', where))
        if paths:
            rc, out, err = ex('for p in ' + ' '.join(f"'{p}'" for p in sorted(paths)) + '; do [ -e "$p" ] || echo "$p"; done')
            for p in out.split():
                static.append(('CHECK', f'path {p} does not exist on this image (created by an earlier step, or by a package not installed here?)', paths[p]))

        # --- report
        order = {'BUG': 0, 'CHECK': 1, 'ENV': 2, 'NOTE': 3, 'SKIPPED': 4, 'OK': 5}
        counts = {}
        for r in results:
            counts[r['cat']] = counts.get(r['cat'], 0) + 1
        print(f"\n== {len(results)} blocks run: " + ', '.join(f'{k} {counts.get(k, 0)}' for k in order))
        for cat in ('BUG', 'CHECK', 'ENV', 'NOTE', 'SKIPPED'):
            rows = [r for r in results if r['cat'] == cat]
            if not rows:
                continue
            print(f'\n---- {cat} ({len(rows)})')
            for r in rows:
                detail = r['why'] + (f": {r['line_text'][:150]}" if r['line_text'] else '')
                print(f"  {r['tag']}\n      {detail}")
        if skips:
            print(f'\n---- LINES NOT RUN ({sum(len(x[1]) for x in skips)}) - read these by hand')
            for tag, lines in skips:
                for ln in lines:
                    print(f'  {tag}: {ln}')
        if static:
            print(f'\n---- STATIC CHECKS ({len(static)})')
            for cat, msg, where in sorted(static, key=lambda x: order[x[0]]):
                print(f'  {cat}: {msg}\n      in {where}')
        bugs = counts.get('BUG', 0) + sum(1 for s in static if s[0] == 'BUG')
        print(f"\n== {'FAIL' if bugs else 'PASS'}: {bugs} bug(s)")
        if a.json:
            pathlib.Path(a.json).write_text(json.dumps({'results': results, 'static': static}, indent=1, ensure_ascii=False))
        return 1 if bugs else 0
    finally:
        if not a.keep:
            sh('docker', 'rm', '-f', name)


if __name__ == '__main__':
    sys.exit(main())
