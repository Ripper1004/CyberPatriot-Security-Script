// Cisco IOS commands for the Command finder (os: 'cisco').
import type { Command } from './commands';

export const CISCO_COMMANDS: Command[] = [
  // ---------------------------------------------------------------- Modes and info
  { os: 'cisco', cat: 'System info', task: 'Go from user EXEC (>) to privileged EXEC (#)', cmd: 'enable' },
  { os: 'cisco', cat: 'System info', task: 'Enter global configuration mode', cmd: 'configure terminal', note: 'Run in privileged EXEC (Router#). Short form: conf t.' },
  { os: 'cisco', cat: 'System info', task: 'Jump back to privileged EXEC from any config mode', cmd: 'end', note: 'Ctrl+Z does the same. exit only goes back one level.' },
  { os: 'cisco', cat: 'System info', task: 'Run a show command without leaving config mode', cmd: 'do show ip interface brief', note: 'Put do in front of any privileged EXEC command.' },
  { os: 'cisco', cat: 'System info', task: 'Show the current (unsaved) configuration', cmd: 'show running-config', note: 'Run in privileged EXEC (Router#).' },
  { os: 'cisco', cat: 'System info', task: 'Show the saved configuration', cmd: 'show startup-config', note: 'This is what loads after a reload.' },
  { os: 'cisco', cat: 'System info', task: 'Show IOS version, model and uptime', cmd: 'show version' },
  { os: 'cisco', cat: 'System info', task: 'Stop the CLI looking up mistyped commands as host names', cmd: 'no ip domain-lookup', note: 'Run in global config mode (Router(config)#).' },
  { os: 'cisco', cat: 'System info', task: 'Set the device name', cmd: 'hostname R1', note: 'Run in global config mode. Use the exact name from the instructions.' },

  // ---------------------------------------------------------------- Passwords & lockout
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Set the privileged EXEC password (encrypted)', cmd: 'enable secret Str0ng!Pass', note: 'Run in global config mode (Router(config)#). Use this, not enable password.' },
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Set a console password', cmd: 'line console 0; password C0nsole!; login', note: 'login makes the device actually ask for the password.' },
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Set a password for remote (VTY) logins', cmd: 'line vty 0 4; password Vty!pass; login', note: 'Many switches have lines 0 15.' },
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Hide plain-text passwords in the config', cmd: 'service password-encryption', note: 'Run in global config mode. Weak (type 7) encryption, but graders check for it.' },
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Require passwords of at least 10 characters', cmd: 'security passwords min-length 10', note: 'Run in global config mode.' },
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Block logins after repeated failures', cmd: 'login block-for 120 attempts 3 within 60', note: 'Blocks logins for 120 seconds after 3 failures within 60 seconds.' },
  { os: 'cisco', cat: 'Passwords & lockout', task: 'Log out idle sessions after 5 minutes', cmd: 'exec-timeout 5 0', note: 'Run in line mode (line console 0 or line vty 0 4). Minutes, then seconds.' },

  // ---------------------------------------------------------------- Users & groups
  { os: 'cisco', cat: 'Users & groups', task: 'Create a local user with a hashed password', cmd: 'username admin secret Adm1nPass!', note: 'Run in global config mode. Used by login local.' },
  { os: 'cisco', cat: 'Users & groups', task: 'Make VTY lines ask for a local username and password', cmd: 'line vty 0 4; login local', note: 'Create a user with username ... secret first.' },
  { os: 'cisco', cat: 'Users & groups', task: 'See who is logged in to the device', cmd: 'show users' },

  // ---------------------------------------------------------------- Remote access
  { os: 'cisco', cat: 'Remote access', task: 'Set a domain name (needed for SSH keys)', cmd: 'ip domain-name cyberpatriot.local', note: 'Run in global config mode. Set a non-default hostname first.' },
  { os: 'cisco', cat: 'Remote access', task: 'Generate RSA keys for SSH', cmd: 'crypto key generate rsa general-keys modulus 1024', note: 'SSH version 2 needs at least 768 bits.' },
  { os: 'cisco', cat: 'Remote access', task: 'Use SSH version 2 only', cmd: 'ip ssh version 2', note: 'Run in global config mode after generating RSA keys.' },
  { os: 'cisco', cat: 'Remote access', task: 'Allow only SSH on the VTY lines (no Telnet)', cmd: 'line vty 0 4; transport input ssh' },
  { os: 'cisco', cat: 'Remote access', task: 'Check that SSH is on', cmd: 'show ip ssh' },
  { os: 'cisco', cat: 'Remote access', task: 'Show a warning banner when someone connects', cmd: 'banner motd #Authorized access only#', note: 'Run in global config mode. The # marks the start and end.' },

  // ---------------------------------------------------------------- Network & ports
  { os: 'cisco', cat: 'Network & ports', task: 'See every interface, its IP and up/down status', cmd: 'show ip interface brief', note: 'administratively down = needs no shutdown.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Give a router interface an IP address and turn it on', cmd: 'interface g0/0; ip address 192.168.1.1 255.255.255.0; no shutdown', note: 'Router interfaces are shut down by default.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Give a switch a management address', cmd: 'interface vlan 1; ip address 192.168.1.2 255.255.255.0; no shutdown', note: 'Then set ip default-gateway in global config.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Set the default gateway on a switch', cmd: 'ip default-gateway 192.168.1.1', note: 'Run in global config mode on the switch.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Shut down unused switch ports', cmd: 'interface range fa0/10 - 24; shutdown', risk: true, note: 'Make sure no needed device is on these ports.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Create and name a VLAN', cmd: 'vlan 10; name Students', note: 'Run in global config mode on the switch.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Put a switch port in a VLAN', cmd: 'switchport mode access; switchport access vlan 10', note: 'Run in interface config mode.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Make a switch port a trunk', cmd: 'switchport mode trunk', note: 'Run in interface config mode. Some multilayer switches need switchport trunk encapsulation dot1q first.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Show VLANs and their ports', cmd: 'show vlan brief' },
  { os: 'cisco', cat: 'Network & ports', task: 'Show the routing table', cmd: 'show ip route', note: 'C = connected, L = local, S = static, S* = default route.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Add a static route', cmd: 'ip route 192.168.20.0 255.255.255.0 10.0.0.2', note: 'Destination network, mask, then next-hop address.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Add a default route', cmd: 'ip route 0.0.0.0 0.0.0.0 203.0.113.1', note: 'Run in global config mode.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Show directly connected Cisco devices', cmd: 'show cdp neighbors' },
  { os: 'cisco', cat: 'Network & ports', task: 'Test reachability from a router', cmd: 'ping 192.168.1.10', note: 'The first ping may show a dot (.) while ARP resolves.' },

  // ---------------------------------------------------------------- Firewall (port security)
  { os: 'cisco', cat: 'Network & ports', task: 'Turn on port security with sticky MAC addresses', cmd: 'switchport mode access; switchport port-security; switchport port-security maximum 2; switchport port-security mac-address sticky', note: 'Run in interface config mode on the switch port.' },
  { os: 'cisco', cat: 'Network & ports', task: 'Shut a port down when a wrong device connects', cmd: 'switchport port-security violation shutdown', note: 'Other modes: restrict (drop and log), protect (drop silently).' },
  { os: 'cisco', cat: 'Network & ports', task: 'Check port security on a port', cmd: 'show port-security interface fa0/1' },

  // ---------------------------------------------------------------- Files & permissions (config files)
  { os: 'cisco', cat: 'Files & permissions', task: 'Save the configuration', cmd: 'copy running-config startup-config', note: 'Run in privileged EXEC. Press Enter at the filename question. write memory does the same.' },
  { os: 'cisco', cat: 'Files & permissions', task: 'Erase the saved configuration', cmd: 'erase startup-config', risk: true, note: 'The device starts blank after the next reload.' },
  { os: 'cisco', cat: 'Files & permissions', task: 'Restart the device', cmd: 'reload', risk: true, note: 'Unsaved changes are lost. Save first unless you mean to discard them.' },
];
