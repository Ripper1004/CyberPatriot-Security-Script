# Forensics questions

Forensics questions are text files on the desktop (`Forensics Question 1.txt`, …). Each one asks something about the computer, and you type the answer into the file. They're often worth **more than any single fix**, so do them **first**, before anything you change destroys the evidence.

## How to answer
1. Open the file. Read the **whole** question, including the example answer format.
2. Find the answer.
3. Type it after `ANSWER:` **exactly** in the format asked: same capitals, full path if asked, no extra spaces.
4. **Save** the file (Ctrl+S). Check the Scoring Report: a correct answer shows up within a minute or two.

> [!TIP]
> If there's a question you can't answer in 10 minutes, move on and come back later. A question often becomes obvious once you've explored the system.

---

## The common question types

### "What is the hash of file X?"

| | Linux | Windows (PowerShell) | FreeBSD |
|---|---|---|---|
| SHA-256 | `sha256sum file` | `Get-FileHash file -Algorithm SHA256` | `sha256 file` |
| SHA-1 | `sha1sum file` | `Get-FileHash file -Algorithm SHA1` | `sha1 file` |
| MD5 | `md5sum file` | `Get-FileHash file -Algorithm MD5` | `md5 file` |

Copy only the long string of letters and numbers. Windows prints it in **upper case**. If the question shows a lower-case example, type it in lower case.

### "Decode this message"
Look at the text and guess the encoding:

| Looks like | Probably | Decode with |
|---|---|---|
| Letters, numbers, `+` `/`, often ends with `=` or `==` | **Base64** | Linux: `echo 'aGVsbG8=' \| base64 -d` · Windows: `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8='))` |
| Only `0-9` and `a-f`, even length | **Hex** | `echo '68656c6c6f' \| xxd -r -p` |
| Only `0` and `1` in groups of 8 | **Binary** | `echo '01101000 01101001' \| perl -lape '$_=pack"(B8)*",@F'` |
| Normal letters but scrambled words | **ROT13 / Caesar** | `echo 'uryyb' \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| `%20`, `%3A` | **URL encoding** | `python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))" 'hi%20there'` |

Several layers are common (e.g. base64 of hex). Decode one layer at a time. **CyberChef** (gchq.github.io/CyberChef) does all of these in a browser, and its "Magic" operation guesses the encoding for you.

### "Find the file that…" / "What is the name of the hidden file…"

| | Linux | Windows |
|---|---|---|
| By name | `sudo find / -iname '*secret*' 2>/dev/null` | `Get-ChildItem C:\ -Recurse -Force -Filter *secret* -ErrorAction SilentlyContinue` |
| Containing text | `sudo grep -rIl 'needle' /home /etc /opt 2>/dev/null` | `Get-ChildItem C:\Users -Recurse -File -Force -ErrorAction SilentlyContinue \| Select-String 'needle' -List \| Select Path` |
| Changed recently | `sudo find / -xdev -mmin -120 -type f 2>/dev/null` (last 2 hours) | `Get-ChildItem C:\Users -Recurse -File -Force -EA 0 \| Where LastWriteTime -gt (Get-Date).AddDays(-2)` |
| Hidden files | names start with `.`: `ls -la` | `Get-ChildItem -Force`, or Explorer → View → Hidden items |

### "Which user…" / "What is the UID / group of…"
```bash
id bob                         # Linux: UID, groups
getent passwd bob              # Linux: home folder, shell
getent group sudo
```
```powershell
Get-LocalUser bob | Format-List *          # Windows: description, last logon, SID
Get-LocalGroupMember Administrators
Get-ADUser bob -Properties *               # Domain Controller
```

### "What port / program is the backdoor using?"
```bash
sudo ss -tulpn                 # Linux: port + program name + PID
ls -l /proc/<PID>/exe          # which file the program is
```
```powershell
Get-NetTCPConnection -State Listen | Select LocalPort, OwningProcess
Get-Process -Id <PID> | Select Name, Path
```

### "Who logged in / what did the attacker do?" (logs)
| Where | Look at |
|---|---|
| Linux (Mint/Ubuntu) | `/var/log/auth.log` (logins, sudo), `/var/log/syslog`, `last`, `lastb` (failed) |
| Debian 12 | `journalctl _COMM=sshd`, `journalctl _COMM=sudo`, `last` |
| Shell history | `/home/*/.bash_history`, `/root/.bash_history` |
| Windows | **Event Viewer** (`eventvwr.msc`) → Windows Logs → **Security**. Event **4624** = logon, **4625** = failed logon, **4720** = user created, **4732** = added to group |
| Windows PowerShell history | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| Web server | `/var/log/apache2/access.log`, `C:\inetpub\logs\LogFiles\` |

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} | Format-List TimeCreated, Message   # who was created
```

### "What's in this picture / document?"
- Hidden text in a file: `strings file | less`
- Picture details (camera, GPS, author): `exiftool photo.jpg` (Linux: `sudo apt install libimage-exiftool-perl`), or on Windows right-click → **Properties → Details**
- Office documents are ZIP files: copy, rename to `.zip`, and look inside.

### "What is the password / key for…"
Often in a text file, browser saved passwords, a script, or shell history:
```bash
sudo grep -rIi 'password' /home /opt /var/www 2>/dev/null | head
cat /home/*/.bash_history
```

### "Which package / program installed…"
```bash
dpkg -S /usr/bin/somefile       # which package owns a file
grep ' install ' /var/log/dpkg.log     # what was installed and when
```
Windows: **Settings → Apps** sorted by **Install date**, or **Event Viewer → Application** log (source **MsiInstaller**).

---

## Don't lose the evidence

- Don't delete a user, file or program until you've checked whether a question mentions it.
- If you must change something, **copy it first** (`cp file ~/evidence/`).
- Don't empty the Recycle Bin / Trash until forensics is finished.
