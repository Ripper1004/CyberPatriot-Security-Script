# Linux critical service hardening

When the README says a service **must keep working**, you don't remove it. You make it **safer**. This guide covers the services that appear most often on Mint, Debian and Ubuntu images.

> [!IMPORTANT]
> Rules for every service:
> 1. **Back up the config file first:** `sudo cp file file.bak`
> 2. **Test the config** before restarting (each section shows the test command).
> 3. **Check the service still works** after restarting: `systemctl status <name>`. If it's red or "failed", restore the backup.
> 4. **Check the Scoring Report.** If the score dropped, undo your last change.

The script's **"Critical service hardening"** section (`apps`) does the safest of these automatically, but only for services you listed as critical.

---

## Apache web server (`apache2`)

| What | Where | Change to |
|---|---|---|
| Hide the version number | `/etc/apache2/conf-available/security.conf` | `ServerTokens Prod` and `ServerSignature Off` |
| Disable TRACE requests | same file | `TraceEnable Off` |
| No folder listings | `/etc/apache2/apache2.conf` (and site files) | In `Options` lines, remove the word `Indexes` (e.g. `Options FollowSymLinks`) |
| Turn off the listing module | — | `sudo a2dismod -f autoindex` |
| Turn off user home pages | — | `sudo a2dismod userdir` (if enabled) |
| Run as www-data, not root | `/etc/apache2/envvars` | `APACHE_RUN_USER=www-data` and `APACHE_RUN_GROUP=www-data` |
| Security headers | new file `/etc/apache2/conf-available/security-headers.conf` | see below |

```bash
sudo a2enmod headers
echo '<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
</IfModule>' | sudo tee /etc/apache2/conf-available/security-headers.conf
sudo a2enconf security security-headers
sudo apache2ctl configtest          # must say "Syntax OK"
sudo systemctl reload apache2
```

Also check:
- **Web files shouldn't be writable by the web server:** `sudo find /var/www -user www-data -type f`. Usually they should be owned by root: `sudo chown -R root:root /var/www/html` (careful: upload folders for an app like WordPress need write access).
- **Web shells** (hacker control pages hidden in the site): `sudo grep -rlE 'eval\(|base64_decode|shell_exec|system\(\$_' /var/www`
- **`.htaccess` files** that redirect visitors somewhere else: `sudo find /var/www -name .htaccess -exec cat {} \;`

---

## Nginx web server

```bash
sudo nano /etc/nginx/nginx.conf
```
In the `http { ... }` block: `server_tokens off;`

In the site files (`/etc/nginx/sites-enabled/*`): change `autoindex on;` to `autoindex off;`, and optionally add:
```
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
```
```bash
sudo nginx -t                       # must say "test is successful"
sudo systemctl reload nginx
```

---

## PHP (used by the website)

Edit the **web** PHP settings, not the command-line ones: `/etc/php/<version>/apache2/php.ini` (Apache) or `/etc/php/<version>/fpm/php.ini` (Nginx).

| Setting | Value | Why |
|---|---|---|
| `expose_php` | `Off` | Hide the PHP version |
| `display_errors` | `Off` | Don't show error details to visitors |
| `log_errors` | `On` | …but do log them |
| `allow_url_fopen` | `Off` | Pages can't download remote code |
| `allow_url_include` | `Off` | Pages can't include remote code |
| `disable_functions` | `exec,passthru,shell_exec,system,proc_open,popen` | A hacked page can't run system commands |
| `session.cookie_httponly` | `1` | JavaScript can't steal login cookies |
| `session.use_strict_mode` | `1` | Rejects made-up session IDs |

Then `sudo systemctl reload apache2` (or `php8.1-fpm` etc.).

> [!WARNING]
> `disable_functions` can break some web apps. If the site stops working after the change, remove functions from the list one at a time.

---

## MySQL / MariaDB

### Built-in hardening tool
```bash
sudo mysql_secure_installation
```
Answer **yes** to: remove anonymous users, disallow root login remotely, remove the test database, reload privileges.

### Settings file
`/etc/mysql/mysql.conf.d/mysqld.cnf` (MySQL) or `/etc/mysql/mariadb.conf.d/50-server.cnf` (MariaDB), under `[mysqld]`:
```
bind-address = 127.0.0.1      # only this computer can connect (skip if the README says others connect)
local_infile = 0              # SQL can't read files from the server's disk
```
```bash
sudo systemctl restart mysql      # or mariadb
```

### Look at the database users
```bash
sudo mysql
```
```sql
SELECT user, host, plugin FROM mysql.user;          -- every database account
DROP USER ''@'localhost';                            -- an anonymous account
DROP USER 'root'@'%';                                -- root allowed from anywhere
ALTER USER 'webapp'@'localhost' IDENTIFIED BY 'A-Str0ng!Passw0rd';
SHOW GRANTS FOR 'webapp'@'localhost';                -- what this account can do
FLUSH PRIVILEGES;
EXIT;
```
Accounts that aren't needed, or that have `ALL PRIVILEGES` without needing them, are common planted problems.

---

## vsftpd (FTP server)

```bash
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
sudo nano /etc/vsftpd.conf
```
| Setting | Value | Why |
|---|---|---|
| `anonymous_enable` | `NO` | No logins without an account |
| `anon_upload_enable` | `NO` | Anonymous users can't upload |
| `anon_mkdir_write_enable` | `NO` | …or make folders |
| `local_enable` | `YES` | Real users can log in (if the README needs it) |
| `chroot_local_user` | `YES` | Users are locked into their home folder |
| `allow_writeable_chroot` | `YES` | Needed with the line above, or logins fail |
| `xferlog_enable` | `YES` | Log every file transfer |
| `ssl_enable` | `YES` | Encrypt passwords and files (only if a certificate is set in `rsa_cert_file`) |

```bash
sudo systemctl restart vsftpd && systemctl status vsftpd
```
Also check `/etc/ftpusers` (users **not** allowed to use FTP; `root` should be in it) and the `userlist_*` settings.

## ProFTPD
In `/etc/proftpd/proftpd.conf`: `DefaultRoot ~`, `RootLogin off`, `ServerIdent off`, and comment out (`#`) the whole `<Anonymous ~ftp> ... </Anonymous>` block. Test with `sudo proftpd -t`.

## Pure-FTPd
```bash
echo yes | sudo tee /etc/pure-ftpd/conf/NoAnonymous
echo yes | sudo tee /etc/pure-ftpd/conf/ChrootEveryone
sudo systemctl restart pure-ftpd
```

---

## Samba (Windows file sharing)

```bash
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
sudo nano /etc/samba/smb.conf
```
In `[global]`:
```
   restrict anonymous = 2
   map to guest = never
   usershare allow guests = no
   server min protocol = SMB2
```
In each share (`[sharename]`): `guest ok = no` (or remove `public = yes`). Check `read only` and `valid users` match what the README says.
```bash
testparm -s                    # check the file
sudo systemctl restart smbd
sudo pdbedit -L                # Samba users: remove any that aren't authorized
sudo smbpasswd -x mallory
```

---

## BIND DNS server

In `/etc/bind/named.conf.options`, inside `options { ... };`:
```
        version "none";                 // hide the version
        allow-transfer { none; };       // don't hand out the zone to anyone
        allow-recursion { localhost; localnets; };
```
```bash
sudo named-checkconf && sudo systemctl reload named
```
Also look in `/etc/bind/named.conf.local` for zones with `allow-transfer { any; };` or `allow-update { any; };`.

---

## Postfix mail server

```bash
sudo postconf -e 'disable_vrfy_command = yes'        # can't ask "does user X exist?"
sudo postconf -e 'smtpd_helo_required = yes'
sudo postconf -e 'smtpd_banner = $myhostname ESMTP'  # hide the version
postconf mynetworks                                  # must NOT contain 0.0.0.0/0 (open relay)
sudo postfix check && sudo systemctl reload postfix
```

---

## SSH
See section 9 of the [Linux Mint checklist](../checklists/linux-mint.md#9-ssh-server-only-if-installed).

---

## WordPress (and other web apps)
- Update WordPress, plugins and themes from the admin dashboard.
- Delete admin accounts in WordPress that the README doesn't list (**Users** page).
- In `wp-config.php`, add `define('DISALLOW_FILE_EDIT', true);` so the dashboard can't edit PHP files.
- Make sure `wp-config.php` isn't readable by everyone: `sudo chmod 640 wp-config.php`.
