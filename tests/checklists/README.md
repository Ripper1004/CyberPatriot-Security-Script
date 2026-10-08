# Checklist tests

Tools that check the six checklists in `docs/checklists/` the way a student would use them.

| Tool | What it checks | Needs |
|---|---|---|
| `linux_lab.py linux-mint` (or `debian`, `ubuntu`) | Runs every command of the checklist, in order, in a container with the practice problems planted. Reports commands that don't exist, wrong options, unknown packages, wrong `gsettings` keys, missing paths. Interactive and disruptive lines are listed, not run. | Docker |
| `check-shell.sh` | `bash -n` / `dash -n` / `shellcheck` on every shell block, and `<placeholder>` text that a beginner would paste as-is | shellcheck |
| `check-powershell.ps1` | The real PowerShell parser on every PowerShell block, plus placeholders | `pwsh` |
| `check-format.py` | Heading numbering, unique heading ids (saved ticks are keyed by them), a `**Script:**` tag on every step, example names | python3 |
| `extract.py` | Pulls code blocks or steps out of the Markdown (used by the others) | python3 |

```bash
python3 tests/checklists/check-format.py
bash tests/checklists/check-shell.sh
pwsh -NoProfile -File tests/checklists/check-powershell.ps1
python3 tests/checklists/linux_lab.py linux-mint            # ~1.5 min; add --mode hardened to run harden.sh --apply first
# behind an HTTPS proxy with its own certificate, only for --install:
TEST_CA=/path/ca.crt https_proxy=http://host:port python3 tests/checklists/linux_lab.py debian --install "ufw auditd"
```

## What these can and can't prove

* **Linux (Mint 21.3, Debian 12, Ubuntu 22.04):** commands really run, in a container. Containers have no systemd, no desktop and no firewall rights, so service, `sysctl`, `ufw` and GUI settings show up as `ENV` and need checking on a real image.
* **Windows and FreeBSD:** only syntax-checked here (no Windows or FreeBSD image is available to run them). Everything else about those checklists is reviewed by reading, not by running. Run them on a real image before relying on them.
