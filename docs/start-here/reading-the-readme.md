# Reading the README (always first!)

The README on the desktop is the most important thing on the image. **Every decision you make depends on it.** If the README says Bob is an administrator, then removing Bob's admin rights *loses* points, even though "fewer admins" is normally safer.

Take 5–10 minutes. Read it **twice**. Write things down.

## What to pull out of the README

Make a note (paper, or a text file on your own computer) with these headings:

### 1. Authorized administrators
Usually a list under "Authorized Administrators". **Write down each name exactly** (spelling and capitals matter).

The first admin is often **you**, the account you're logged in as. The README usually gives your password next to your name.

### 2. Authorized users
Usually under "Authorized Users". These people keep their accounts but should **not** be admins.

> [!TIP]
> Anyone on the computer who is **not** in either list is probably an unauthorized user that should be removed. Some READMEs also say things like "Remove the account of the employee who left" or "Create an account for new hire Erin". Do exactly what it says.

### 3. Critical services
Look for sentences like:
- "This computer is the company **web server**" → Apache / Nginx / IIS must keep working.
- "Users need to transfer files with **FTP**" → the FTP server must keep working.
- "Staff connect remotely with **SSH** / **Remote Desktop**" → keep SSH / RDP.
- "The server provides **DNS** and **Active Directory**" → never touch those services.

Write down every service the README mentions. **Never disable, uninstall, or firewall-block these.**

### 4. Required software
"Users need Firefox, LibreOffice and VLC" → don't uninstall them; update them instead.

### 5. Policy hints
Sentences that tell you what is *prohibited*:
- "Media files are not allowed on company computers" → delete music and videos.
- "Hacking tools and games are prohibited" → uninstall them.
- "Passwords must be at least 12 characters" → set that exact length.

### 6. Special instructions
Anything unusual: "Do not change the password of user X", "The database must allow remote connections", "Group Y must exist and contain users A and B". These are often worth points or prevent penalties.

## Example

> *Company: Cyber Plumbing Co. This Linux Mint workstation is used by the office team. Authorized administrators: **alice** (you, password: Pl@mb3r!), **bob**. Authorized users: carol, dave, erin. The office uses **SSH** to manage this computer remotely. Prohibited files such as music must not be stored. Hacking tools and games are not allowed.*

Your notes:
```
Admins:            alice (me)  bob
Users:             carol dave erin
Critical services: ssh
Prohibited:        media files, hacking tools, games
```

That is exactly what the scripts ask for when they start.

## After the README: the Forensics Questions
Open each Forensics Question file and **answer them before fixing anything**. Fixing things can destroy evidence: deleting a user deletes the clue that was in their home folder. See [Forensics questions](../guides/forensics-questions.md).
