# Cisco networking and Packet Tracer

Most CyberPatriot rounds have a Cisco Networking Challenge next to the operating system images. It has two parts: a multiple-choice quiz on networking theory and a hands-on activity in Cisco Packet Tracer, where you set up routers, switches and PCs in a simulator. This page covers the basics you need for both, plus a cheat sheet of the Cisco commands that come up again and again.

## What the Cisco part of a round is

| Part | What you do | What helps most |
|---|---|---|
| **Quiz** | Answer multiple-choice questions about networking | Knowing the ideas: layers, addresses, ports, subnetting, how devices work |
| **Packet Tracer activity** | Open a `.pka` file and configure the devices it describes | Typing Cisco commands quickly and correctly, and checking your work |

The challenge is based on material from the **Cisco Networking Academy** (NetAcad), Cisco's free online training program. The topics change from round to round. Check what your round covers (your coach gets this information) and study those topics first.

### How to prepare

1. Make a free account at **netacad.com**. Packet Tracer is a free download for NetAcad users.
2. Build small networks yourself: two PCs, a switch and a router is enough to practice almost everything on this page.
3. Practice the **security tasks** (passwords, SSH, banners) until you can type them without looking.
4. Do subnetting problems by hand until they feel easy. They show up in quizzes all the time.

> [!TIP]
> Skills beat memorizing. If you understand *why* a router needs a default gateway or *why* a port is down, you can answer questions you have never seen before.

## Networking basics

### The OSI and TCP/IP models

A **model** splits networking into layers. Each layer does one job and hands its work to the next layer. The **OSI** model (Open Systems Interconnection) has 7 layers. The **TCP/IP** model, which the internet really uses, has 4.

| # | OSI layer | What it does | Examples | Data unit (PDU) | TCP/IP layer |
|---|---|---|---|---|---|
| 7 | Application | The network services programs use | HTTP, DNS, FTP, SSH, DHCP | Data | Application |
| 6 | Presentation | Formats, compresses and encrypts data | JPEG, ASCII, encryption | Data | Application |
| 5 | Session | Starts, manages and ends conversations | Sessions between apps | Data | Application |
| 4 | Transport | Splits data up, uses port numbers, can resend lost data | TCP, UDP | Segment (TCP) / datagram (UDP) | Transport |
| 3 | Network | Logical addresses and routing between networks | IPv4, IPv6, ICMP, routers | Packet | Internet |
| 2 | Data Link | Physical (MAC) addresses, delivery on the local network | Ethernet, Wi-Fi frames, switches | Frame | Network Access |
| 1 | Physical | Bits as electrical, light or radio signals | Cables, connectors, hubs | Bits | Network Access |

**PDU** means Protocol Data Unit: the name for a chunk of data at each layer. To remember the OSI layers from 1 to 7: **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way.

> [!NOTE]
> Some books call the bottom TCP/IP layer "Link" instead of "Network Access". They mean the same thing.

### Network devices

| Device | Layer | What it does |
|---|---|---|
| **Hub** | 1 | Repeats every signal out every port. Old and slow, because everyone shares the bandwidth. |
| **Switch** | 2 | Connects devices in the same network. Learns MAC addresses and sends each frame only out the right port. |
| **Router** | 3 | Connects *different* networks and picks the path for each packet using IP addresses. |
| **Access point (AP)** | 2 | Lets wireless devices join a wired network. |
| **Firewall** | 3 and up | Allows or blocks traffic based on rules. |

### Addresses and traffic types

- A **MAC address** (Media Access Control) is the physical address burned into a network card. It is 48 bits, written as 12 hexadecimal digits, like `00:1A:2B:3C:4D:5E`. Switches use it. It only matters on the local network.
- An **IP address** (Internet Protocol) is the logical address you set in software, like `192.168.1.10`. Routers use it to move packets between networks.
- **Unicast** goes to one device. **Broadcast** goes to every device on the local network (the MAC address `FF:FF:FF:FF:FF:FF`). **Multicast** goes to a group of devices that asked for it.
- Routers do **not** forward broadcasts. Each router interface is the edge of a **broadcast domain**.

### TCP vs UDP

| | TCP (Transmission Control Protocol) | UDP (User Datagram Protocol) |
|---|---|---|
| Connection | Sets up a connection first (three-way handshake: SYN, SYN-ACK, ACK) | No setup, just sends |
| Reliable? | Yes. Numbers the data, confirms delivery, resends lost pieces | No. Lost data stays lost |
| Speed | Slower, more overhead | Faster, less overhead |
| Used for | Web pages, email, file transfer, SSH | DNS lookups, DHCP, video calls, streaming, online games |

### The protocols that make a network work

- **DHCP** (Dynamic Host Configuration Protocol) gives a device its IP address, subnet mask, default gateway and DNS server automatically. The four steps are **DORA**: **D**iscover (the client broadcasts "is there a DHCP server?"), **O**ffer (a server offers an address), **R**equest (the client asks for that address), **A**cknowledge (the server confirms).
- **DNS** (Domain Name System) turns names like `www.example.com` into IP addresses.
- **ARP** (Address Resolution Protocol) finds the MAC address that goes with an IPv4 address on the local network. The question is a broadcast ("who has 192.168.1.1?"), the answer is unicast.
- **NAT** (Network Address Translation) lets many devices with private addresses share one public address on the internet. The router rewrites the addresses as traffic passes through.
- **ICMP** (Internet Control Message Protocol) carries error and test messages. `ping` and `traceroute` use it.
- The **default gateway** is the router address a device sends traffic to when the destination is on a *different* network. If it's wrong or missing, a PC can reach its own network but nothing beyond it.

## IPv4 addressing and subnetting

An IPv4 address is **32 bits**, written as four numbers (octets) from 0 to 255: `192.168.1.10`. The **subnet mask** says which part is the **network** and which part is the **host** (the device).

### Binary in one minute

Each octet is 8 bits. The bit values, left to right, are:

| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
|---|---|---|---|---|---|---|---|

Add up the values where the bit is 1. For example, `11000000` = 128 + 64 = **192**, and `10101100` = 128 + 32 + 8 + 4 = **172**.

### Classes (historical) and special ranges

Classes are an old system that modern networks no longer use, but quizzes still ask about them.

| Class | First octet | Default mask | Use |
|---|---|---|---|
| A | 1 to 126 | 255.0.0.0 (/8) | Very large networks |
| B | 128 to 191 | 255.255.0.0 (/16) | Medium networks |
| C | 192 to 223 | 255.255.255.0 (/24) | Small networks |
| D | 224 to 239 | none | Multicast |
| E | 240 to 255 | none | Experimental |

| Range | Meaning |
|---|---|
| `10.0.0.0/8` (10.0.0.0 to 10.255.255.255) | Private |
| `172.16.0.0/12` (172.16.0.0 to 172.31.255.255) | Private |
| `192.168.0.0/16` (192.168.0.0 to 192.168.255.255) | Private |
| `127.0.0.0/8` | Loopback (the device itself, usually `127.0.0.1`) |
| `169.254.0.0/16` | APIPA (Automatic Private IP Addressing): a PC gives itself one when it can't reach a DHCP server |

**Private** addresses are free to use inside any network but are not routed on the internet. NAT translates them to a public address.

### CIDR and subnet masks

**CIDR** (Classless Inter-Domain Routing) notation writes the mask as a slash and the number of network bits: `/24` means the first 24 bits are network bits, so the mask is `255.255.255.0`. Usable hosts = 2^(host bits) − 2, because the first address is the network address and the last is the broadcast address.

| CIDR | Subnet mask | Usable hosts | Block size (octet it changes in) |
|---|---|---|---|
| /8 | 255.0.0.0 | 16,777,214 | 1 (octet 1) |
| /9 | 255.128.0.0 | 8,388,606 | 128 (octet 2) |
| /10 | 255.192.0.0 | 4,194,302 | 64 (octet 2) |
| /11 | 255.224.0.0 | 2,097,150 | 32 (octet 2) |
| /12 | 255.240.0.0 | 1,048,574 | 16 (octet 2) |
| /13 | 255.248.0.0 | 524,286 | 8 (octet 2) |
| /14 | 255.252.0.0 | 262,142 | 4 (octet 2) |
| /15 | 255.254.0.0 | 131,070 | 2 (octet 2) |
| /16 | 255.255.0.0 | 65,534 | 1 (octet 2) |
| /17 | 255.255.128.0 | 32,766 | 128 (octet 3) |
| /18 | 255.255.192.0 | 16,382 | 64 (octet 3) |
| /19 | 255.255.224.0 | 8,190 | 32 (octet 3) |
| /20 | 255.255.240.0 | 4,094 | 16 (octet 3) |
| /21 | 255.255.248.0 | 2,046 | 8 (octet 3) |
| /22 | 255.255.252.0 | 1,022 | 4 (octet 3) |
| /23 | 255.255.254.0 | 510 | 2 (octet 3) |
| /24 | 255.255.255.0 | 254 | 1 (octet 3) |
| /25 | 255.255.255.128 | 126 | 128 (octet 4) |
| /26 | 255.255.255.192 | 62 | 64 (octet 4) |
| /27 | 255.255.255.224 | 30 | 32 (octet 4) |
| /28 | 255.255.255.240 | 14 | 16 (octet 4) |
| /29 | 255.255.255.248 | 6 | 8 (octet 4) |
| /30 | 255.255.255.252 | 2 | 4 (octet 4) |

> [!TIP]
> Memorize the last-octet mask values: **128, 192, 224, 240, 248, 252, 254, 255**. Block size is always **256 minus the mask value** in the octet that isn't 255 or 0.

### Step-by-step: find the network, broadcast and hosts

1. Find the **interesting octet**: the one where the mask is not 255 and not 0.
2. **Block size** = 256 − the mask value in that octet.
3. List the multiples of the block size (0, block, 2 × block, …). The **network address** is the biggest multiple that is less than or equal to the IP's value in that octet. Octets after it become 0.
4. The **broadcast address** is the next network address minus 1. Octets after the interesting one become 255.
5. **First host** = network address + 1. **Last host** = broadcast address − 1.
6. **Number of hosts** = 2^(32 − prefix) − 2.

### Worked example 1: 192.168.10.77/26

- /26 = mask `255.255.255.192`. The interesting octet is the 4th.
- Block size = 256 − 192 = **64**. Networks: .0, .64, .128, .192.
- 77 falls between 64 and 128, so the network is **192.168.10.64**.
- Broadcast = 128 − 1 = **192.168.10.127**.
- Hosts: **192.168.10.65** to **192.168.10.126**. That is 2^6 − 2 = **62** hosts.

### Worked example 2: 172.16.45.200/20

- /20 = mask `255.255.240.0`. The interesting octet is the 3rd.
- Block size = 256 − 240 = **16**. Networks in the 3rd octet: 0, 16, 32, 48, …
- 45 falls between 32 and 48, so the network is **172.16.32.0**.
- Broadcast: the next network is 172.16.48.0, so the broadcast is **172.16.47.255**.
- Hosts: **172.16.32.1** to **172.16.47.254**. That is 2^12 − 2 = **4,094** hosts.

### Worked example 3: 10.1.1.5/30

- /30 = mask `255.255.255.252`. Block size = **4**. Networks: .0, .4, .8, …
- Network **10.1.1.4**, broadcast **10.1.1.7**, hosts **10.1.1.5** and **10.1.1.6** (2 hosts).
- A /30 is common on a link between two routers, because the link needs exactly two addresses.

### Picking a mask for a number of hosts

Find the smallest number of host bits where 2^(host bits) − 2 is at least the number of hosts you need. Example: you need 50 hosts. 2^5 − 2 = 30 is too small, 2^6 − 2 = 62 is enough. That's 6 host bits, so the prefix is 32 − 6 = **/26**.

### IPv6 basics

- An IPv6 address is **128 bits**, written as 8 groups of 4 hexadecimal digits separated by colons: `2001:0db8:0000:0000:0000:ff00:0042:8329`.
- **Shortening rule 1:** drop leading zeros in any group (`0db8` becomes `db8`, `0042` becomes `42`).
- **Shortening rule 2:** replace **one** run of consecutive all-zero groups with `::`. You may only use `::` once in an address.
- So the address above becomes `2001:db8::ff00:42:8329`.

| Address | Meaning |
|---|---|
| `::1` | Loopback (like 127.0.0.1) |
| `fe80::/10` | Link-local: works only on the local link. Every IPv6 interface makes one automatically. |
| `2000::/3` | Global unicast: public addresses, routed on the internet |
| `fc00::/7` | Unique local: private addresses, like 10.x.x.x in IPv4 |

A normal IPv6 network (LAN) uses a **/64** prefix. IPv6 has no broadcast. It uses multicast instead.

## Common ports

A **port** number tells the receiving computer which program the traffic is for. Ports 0 to 1023 are the "well-known" ports.

| Port | Protocol | TCP / UDP | What it is |
|---|---|---|---|
| 20, 21 | FTP (File Transfer Protocol) | TCP | File transfer. 21 = commands, 20 = data. Not encrypted. |
| 22 | SSH (Secure Shell) | TCP | Encrypted remote login. Also SFTP and SCP. |
| 23 | Telnet | TCP | Remote login with **no** encryption. Replace with SSH. |
| 25 | SMTP (Simple Mail Transfer Protocol) | TCP | Sending email between servers |
| 53 | DNS (Domain Name System) | UDP and TCP | Name lookups (UDP); big replies and zone transfers (TCP) |
| 67, 68 | DHCP (Dynamic Host Configuration Protocol) | UDP | 67 = server, 68 = client |
| 69 | TFTP (Trivial File Transfer Protocol) | UDP | Simple file transfer, often used to back up Cisco configs |
| 80 | HTTP (Hypertext Transfer Protocol) | TCP | Web pages, not encrypted |
| 110 | POP3 (Post Office Protocol 3) | TCP | Downloading email |
| 123 | NTP (Network Time Protocol) | UDP | Clock sync |
| 143 | IMAP (Internet Message Access Protocol) | TCP | Reading email on the server |
| 161, 162 | SNMP (Simple Network Management Protocol) | UDP | Device monitoring. 162 = traps (alerts) |
| 389 | LDAP (Lightweight Directory Access Protocol) | TCP (also UDP) | Directory lookups, like Active Directory |
| 443 | HTTPS (HTTP Secure) | TCP | Encrypted web pages |
| 445 | SMB (Server Message Block) | TCP | Windows file sharing |
| 514 | Syslog | UDP | Sending log messages to a log server |
| 636 | LDAPS (LDAP over TLS) | TCP | Encrypted LDAP |
| 3306 | MySQL | TCP | MySQL database |
| 3389 | RDP (Remote Desktop Protocol) | TCP (also UDP) | Windows Remote Desktop |

## Cisco IOS basics

**IOS** (Internetwork Operating System) is the software on Cisco routers and switches. You talk to it through a command line, the **CLI** (command-line interface). In Packet Tracer, click a device and open the **CLI** tab.

### Modes and prompts

The prompt tells you which mode you are in. Each mode allows different commands.

| Mode | Prompt | How to get there | What you can do |
|---|---|---|---|
| User EXEC | `Router>` | Where you start | A few basic `show` commands, `ping` |
| Privileged EXEC | `Router#` | `enable` | All `show` commands, save, reload, debug |
| Global configuration | `Router(config)#` | `configure terminal` | Settings for the whole device |
| Interface configuration | `Router(config-if)#` | `interface g0/0` | Settings for one port |
| Line configuration | `Router(config-line)#` | `line console 0` or `line vty 0 4` | Console and remote login settings |
| VLAN configuration | `Switch(config-vlan)#` | `vlan 10` | Name a VLAN |

```text
Router> enable
Router# configure terminal
Router(config)# interface gigabitEthernet 0/0
Router(config-if)# exit
Router(config)# end
Router#
```

- `exit` goes back **one** level. `end` (or **Ctrl+Z**) jumps straight back to privileged EXEC.
- `disable` goes from privileged EXEC back to user EXEC.
- `?` lists the commands you can type here. `show ?` lists everything that can follow `show`.
- **Tab** finishes a command word for you.
- You can **shorten** any word as long as it's unique: `conf t`, `int g0/0`, `sh ip int br`.
- `do` runs a privileged EXEC command from any config mode, so you don't have to leave: `do show ip interface brief`.
- `no` in front of a command undoes it: `no shutdown`, `no ip address`.

> [!TIP]
> Mistyped a word in privileged EXEC and the router freezes for a while "Translating..."? It thinks you typed a host name and tries to look it up. Run `no ip domain-lookup` in global config to stop that.

### Show commands

All of these run in privileged EXEC (`Router#`), or with `do` in config mode.

| Command | What it shows |
|---|---|
| `show running-config` | The **current** configuration in RAM (memory). Lost on reboot unless you save. |
| `show startup-config` | The **saved** configuration in NVRAM (non-volatile memory). Loaded at boot. |
| `show ip interface brief` | Every interface, its IP address and whether it is up. The most useful command. |
| `show interfaces` | Detailed status and counters for each interface |
| `show vlan brief` | VLANs on a switch and which ports are in each |
| `show interfaces trunk` | Which switch ports are trunks and which VLANs they carry |
| `show ip route` | The routing table: which networks the router knows and how to reach them |
| `show version` | IOS version, uptime, model, memory and the configuration register |
| `show mac address-table` | Which MAC address the switch learned on which port |
| `show cdp neighbors` | Directly connected Cisco devices (CDP = Cisco Discovery Protocol) |
| `show port-security` | Port security settings and violation counts |
| `show ip ssh` | Whether SSH is turned on and which version |
| `show history` | The last commands you typed |

### Reading `show ip interface brief`

| Status / Protocol | Meaning | Usual fix |
|---|---|---|
| up / up | Working | Nothing |
| administratively down / down | Someone typed `shutdown` (router ports start this way) | `no shutdown` on the interface |
| down / down | No cable, or the other end is off | Check the cable and the device on the other end |
| up / down | Cable is fine but the link doesn't work | Check the other side's settings (for example, clock rate on a serial link) |

## Securing a device

These are the classic Packet Tracer security tasks. The examples use simple passwords. Always type exactly the passwords and names the activity instructions give you, because the grader checks for them.

### Set the hostname

Gives the device a name. The prompt changes right away.

```text
Router(config)# hostname R1
R1(config)#
```

### Set the enable secret

Protects privileged EXEC mode. `enable secret` stores the password as a hash.

```text
R1(config)# enable secret Cl@ss123
```

> [!WARNING]
> Don't use `enable password`. It is stored in plain text in the config. If both are set, the device uses `enable secret` and ignores `enable password`.

### Protect the console line

The console is the physical port you plug a console cable into. `login` makes the device actually ask for the password.

```text
R1(config)# line console 0
R1(config-line)# password C0nsole!
R1(config-line)# login
R1(config-line)# exec-timeout 5 0
R1(config-line)# exit
```

`exec-timeout 5 0` logs out an idle session after 5 minutes and 0 seconds.

### Protect the VTY lines (remote login)

VTY (virtual terminal) lines are used for remote logins with Telnet or SSH. Routers usually have lines `0 4`. Many switches have `0 15`.

```text
R1(config)# line vty 0 4
R1(config-line)# password Vty!pass
R1(config-line)# login
R1(config-line)# transport input ssh
R1(config-line)# exit
```

`transport input ssh` allows SSH only, so nobody can log in with unencrypted Telnet. To use SSH you also need the setup in the SSH section below.

### Encrypt the plain-text passwords

Hides the console, VTY and `enable password` passwords in the config.

```text
R1(config)# service password-encryption
```

This uses weak "type 7" encryption that's easy to reverse. It only stops someone reading the password over your shoulder. That's why `enable secret` is still needed.

### Add a login banner

Shows a warning to everyone who connects. The `#` marks the start and end of the message. Any character works as long as it isn't in the message.

```text
R1(config)# banner motd #Authorized access only. Violators will be prosecuted.#
```

MOTD means "message of the day".

### Require a minimum password length

New passwords shorter than this are rejected.

```text
R1(config)# security passwords min-length 10
```

### Block repeated failed logins

Blocks all login attempts for 120 seconds if there are 3 failed attempts within 60 seconds.

```text
R1(config)# login block-for 120 attempts 3 within 60
```

### Shut down unused interfaces

A port that isn't used can't be used by an attacker. `interface range` configures many ports at once.

```text
S1(config)# interface range fastEthernet 0/10 - 24
S1(config-if-range)# shutdown
```

### Configure SSH

SSH (Secure Shell) is encrypted remote login. It needs a hostname that isn't the default, a domain name, RSA keys and a local user.

```text
R1(config)# ip domain-name cyberpatriot.local
R1(config)# crypto key generate rsa
How many bits in the modulus [512]: 1024
R1(config)# username admin secret Adm1nPass!
R1(config)# ip ssh version 2
R1(config)# line vty 0 4
R1(config-line)# transport input ssh
R1(config-line)# login local
R1(config-line)# exit
```

- The key must be at least **768 bits** for SSH version 2. Use 1024 or 2048. You can also type it in one line: `crypto key generate rsa general-keys modulus 1024`.
- `login local` checks the username and password you created with `username`, instead of the line password.
- Optional extras: `ip ssh time-out 60` and `ip ssh authentication-retries 3`.
- Test from a PC in Packet Tracer (**Desktop > Command Prompt**):

```powershell
ssh -l admin 192.168.1.1
```

### Save the configuration

Everything you type changes the **running-config** only. If the device reloads, unsaved changes are gone. Save to the **startup-config**:

```text
R1# copy running-config startup-config
Destination filename [startup-config]?
Building configuration...
[OK]
```

Press **Enter** at the question. `write memory` (or just `wr`) does the same thing. From config mode, use `do copy running-config startup-config`.

> [!IMPORTANT]
> Some Packet Tracer activities check the startup-config. Save on **every** device when you're done, and again after any later change.

## Interfaces and addressing

### Router interface

Router interfaces are **shut down by default**, so `no shutdown` is required.

```text
R1(config)# interface gigabitEthernet 0/0
R1(config-if)# description Link to LAN 1
R1(config-if)# ip address 192.168.1.1 255.255.255.0
R1(config-if)# no shutdown
R1(config-if)# exit
```

The router's interface address is usually the **default gateway** for the PCs on that LAN.

For IPv6, turn on IPv6 routing once, then give the interface an address:

```text
R1(config)# ipv6 unicast-routing
R1(config)# interface gigabitEthernet 0/0
R1(config-if)# ipv6 address 2001:db8:acad:1::1/64
```

> [!NOTE]
> On a serial link between two routers, the end with the **DCE** cable (data communications equipment, shown with a clock icon in Packet Tracer) needs `clock rate 64000` on its interface. Without it, the link shows up / down.

### Switch management address (SVI)

A switch's ports don't have IP addresses. To manage a switch remotely, give it an address on an **SVI** (switched virtual interface), which is a virtual interface for a VLAN. Switch ports are **up by default**, but the SVI needs `no shutdown`.

```text
S1(config)# interface vlan 1
S1(config-if)# ip address 192.168.1.2 255.255.255.0
S1(config-if)# no shutdown
S1(config-if)# exit
S1(config)# ip default-gateway 192.168.1.1
```

`ip default-gateway` lets the switch answer devices on other networks.

### PC addressing in Packet Tracer

1. Click the PC, open the **Desktop** tab, then **IP Configuration**.
2. Choose **Static** and type the IPv4 address, subnet mask, default gateway and DNS server. Or choose **DHCP** to get them from a DHCP server.
3. Check it in **Desktop > Command Prompt**:

```powershell
ipconfig /all
ping 192.168.1.1
```

## VLANs and trunks

A **VLAN** (virtual LAN) splits one switch into separate networks. Devices in different VLANs can't talk to each other without a router (or a multilayer switch). VLAN 1 is the default VLAN that every port starts in.

### Create a VLAN and put ports in it

```text
S1(config)# vlan 10
S1(config-vlan)# name Students
S1(config-vlan)# exit
S1(config)# interface fastEthernet 0/1
S1(config-if)# switchport mode access
S1(config-if)# switchport access vlan 10
S1(config-if)# exit
```

An **access** port belongs to one VLAN. Use `interface range fastEthernet 0/1 - 10` to set many ports at once.

### Trunks

A **trunk** carries traffic for many VLANs over one link, usually between switches or from a switch to a router. It adds an **802.1Q** tag to each frame that says which VLAN it belongs to.

```text
S1(config)# interface gigabitEthernet 0/1
S1(config-if)# switchport mode trunk
S1(config-if)# switchport trunk native vlan 99
S1(config-if)# switchport trunk allowed vlan 10,20,99
```

The **native VLAN** is the one VLAN whose traffic crosses the trunk without a tag. It must match on both ends. Changing it away from VLAN 1 is a common security task.

> [!NOTE]
> On some multilayer switches (such as the 3560), you must type `switchport trunk encapsulation dot1q` before `switchport mode trunk`. On 2960 switches that command doesn't exist, because they only support 802.1Q.

### Port security

Port security limits which devices (MAC addresses) can use a switch port. It only works on a port set to access (or trunk) mode.

```text
S1(config)# interface fastEthernet 0/1
S1(config-if)# switchport mode access
S1(config-if)# switchport port-security
S1(config-if)# switchport port-security maximum 2
S1(config-if)# switchport port-security mac-address sticky
S1(config-if)# switchport port-security violation shutdown
```

- `maximum 2` allows at most 2 MAC addresses on the port.
- `mac-address sticky` remembers the MAC addresses it learns and adds them to the running-config.
- Violation modes: **shutdown** (the default: the port turns off, "err-disabled"), **restrict** (drops the bad traffic, logs it and counts it), **protect** (drops the bad traffic silently).
- To turn a shut-down port back on, remove the bad device, then type `shutdown` and `no shutdown` on the interface.
- Check with `show port-security interface fastEthernet 0/1`.

### Router-on-a-stick

To let VLANs talk to each other, one router port can route for several VLANs using **subinterfaces**, one per VLAN. The switch port going to the router must be a trunk.

```text
R1(config)# interface gigabitEthernet 0/0.10
R1(config-subif)# encapsulation dot1Q 10
R1(config-subif)# ip address 192.168.10.1 255.255.255.0
R1(config-subif)# exit
R1(config)# interface gigabitEthernet 0/0.20
R1(config-subif)# encapsulation dot1Q 20
R1(config-subif)# ip address 192.168.20.1 255.255.255.0
R1(config-subif)# exit
R1(config)# interface gigabitEthernet 0/0
R1(config-if)# no shutdown
```

`encapsulation dot1Q 10` must come **before** the IP address. Each PC uses its own VLAN's subinterface address as its default gateway.

## Routing and DHCP

### Static and default routes

A router knows its directly connected networks automatically. For other networks, you add a **static route**: the destination network, its mask, and the next-hop address (the next router's IP).

```text
R1(config)# ip route 192.168.20.0 255.255.255.0 10.0.0.2
```

A **default route** matches every destination the router doesn't have a better route for. It's usually pointed at the internet provider.

```text
R1(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1
```

You can also name the exit interface instead of the next hop: `ip route 192.168.20.0 255.255.255.0 serial0/0/0`.

In `show ip route`, the code letter says where each route came from: **C** = directly connected, **L** = local (the router's own address), **S** = static, **S\*** = static default route.

### DHCP server on a router

```text
R1(config)# ip dhcp excluded-address 192.168.1.1 192.168.1.10
R1(config)# ip dhcp pool LAN1
R1(dhcp-config)# network 192.168.1.0 255.255.255.0
R1(dhcp-config)# default-router 192.168.1.1
R1(dhcp-config)# dns-server 192.168.1.5
R1(dhcp-config)# exit
```

- `excluded-address` keeps addresses (like the router's own and servers') from being handed out. Type it in global config, not inside the pool.
- `network` is the range to hand out. `default-router` is the gateway the PCs get. `dns-server` is the DNS server they get.
- Check which addresses were handed out with `show ip dhcp binding`.
- If the DHCP server is on a different network, the router interface facing the clients needs `ip helper-address` followed by the server's IP, because routers don't forward the DHCP broadcast otherwise.

## Troubleshooting checklist

Work from the bottom layer up.

1. **Cables.** In Packet Tracer use a **copper straight-through** cable between different kinds of devices (PC to switch, switch to router). Use a **copper crossover** cable between similar devices (switch to switch, PC to PC, router to router, PC to router). The lightning-bolt cable picks the type for you. A **console** cable connects a PC's RS-232 port to a device's console port, then you use **Desktop > Terminal** on the PC.
2. **Link lights.** Green = up. Orange (amber) = the switch port is still starting up, wait a few seconds. Red = down.
3. **Interfaces up/up.** Run `show ip interface brief`. Fix any port that's administratively down with `no shutdown`.
4. **Addresses.** Check the IP address, subnet mask and default gateway on every PC. The gateway must be the router's address on the **same** network as the PC. A typo in one octet is the most common mistake.
5. **VLANs.** Check that each port is in the right VLAN with `show vlan brief`, and that trunks are trunks with `show interfaces trunk`.
6. **Routes.** Check `show ip route` on each router. Every router needs a route to every network, and the replies need a route back.
7. **Test.** Ping from a PC to its gateway, then further away. Use `tracert` to see where packets stop. On a router, the commands are `ping` and `traceroute`.
8. **Save** the config on every device, then click **Check Results**.

```powershell
ping 192.168.1.1
tracert 192.168.20.10
arp -a
```

> [!TIP]
> The first ping often loses a packet or two while ARP finds the MAC address. On a router you'll see `.!!!!`. Ping again before you start changing things.

## Packet Tracer tips

- **Read the instructions twice** before you start. Write down every name, password and address. Spelling and capital letters must match exactly.
- The **Check Results** button in the instructions window shows your completion percentage and which assessment items are correct. Check it often.
- **Don't click Reset Activity.** It erases all your work.
- **Save the `.pka` file** often with **File > Save** (Ctrl+S), and save it where your instructions say.
- Watch the **timer** if the activity has one. Do the tasks you know first, then come back to the hard ones.
- Click the **Fast Forward Time** button at the bottom of the window to skip ahead in the simulation, for example while links come up or DHCP hands out addresses.
- Use **Tab** and short commands to type faster, and `do` to run `show` commands without leaving config mode.
- When a task doesn't score, compare your `show running-config` with the instructions line by line.

For more terms, see the [glossary](glossary.md).
