// Single place that describes the site's content. Used by the docs sync
// script (Node) and by the Astro pages, so it is plain JavaScript.

export const REPO = 'Ripper1004/CyberPatriot-Security-Script';
export const REPO_URL = `https://github.com/${REPO}`;
export const BRANCH = 'main';

/** CyberPatriot 19 (2026-27) competition rounds and their images. */
export const SEASON = {
  name: 'CyberPatriot 19',
  years: '2026–27',
  rounds: [
    { id: 'r1', name: 'Round 1', dates: 'Oct 22–25, 2026', images: ['windows', 'mint'] },
    { id: 'r2', name: 'Round 2', dates: 'Nov 12–15, 2026', images: ['windows', 'server', 'debian'] },
    { id: 'state', name: 'State Round', dates: 'Dec 10–13, 2026', images: ['server', 'mint', 'debian'] },
    { id: 'semis', name: 'Semifinals', dates: 'Jan 21–23, 2027', images: ['mint', 'server', 'debian', 'freebsd'] },
  ],
};

/**
 * One entry per checklist page in docs/checklists.
 * `image` links the checklist to the SEASON.rounds image ids.
 */
export const CHECKLISTS = [
  {
    id: 'windows-10-11',
    image: 'windows',
    name: 'Windows 10 / 11',
    short: 'Windows',
    family: 'windows',
    blurb: 'Users, local security policy, Defender, firewall, services, backdoors.',
    script: 'windows',
  },
  {
    id: 'windows-server',
    image: 'server',
    name: 'Windows Server',
    short: 'Server',
    family: 'windows',
    blurb: 'Everything on Windows 11, plus Active Directory, roles and Domain Controllers.',
    script: 'windows',
  },
  {
    id: 'linux-mint',
    image: 'mint',
    name: 'Linux Mint',
    short: 'Mint',
    family: 'linux',
    blurb: 'The most detailed Linux checklist. Start here even for Debian or Ubuntu.',
    script: 'linux',
  },
  {
    id: 'debian',
    image: 'debian',
    name: 'Debian',
    short: 'Debian',
    family: 'linux',
    blurb: 'The Debian differences: no sudo by default, GNOME, root account.',
    script: 'linux',
  },
  {
    id: 'freebsd',
    image: 'freebsd',
    name: 'FreeBSD',
    short: 'FreeBSD',
    family: 'freebsd',
    blurb: 'pf firewall, rc.conf services, pkg, and how BSD differs from Linux.',
    script: 'freebsd',
  },
  {
    id: 'ubuntu',
    image: 'ubuntu',
    name: 'Ubuntu',
    short: 'Ubuntu',
    family: 'linux',
    blurb: 'For older images. Short: Ubuntu is almost the same as Mint.',
    script: 'linux',
  },
];

/** The beginner learning path, in order. Paths are relative to docs/. */
export const LEARNING_PATH = [
  { path: 'start-here/what-is-cyberpatriot.md', label: 'What is CyberPatriot?', minutes: 8 },
  { path: 'guides/things-that-lose-points.md', label: 'Things that lose points', minutes: 6 },
  { path: 'start-here/reading-the-readme.md', label: 'Reading the README', minutes: 6 },
  { path: 'start-here/round-game-plan.md', label: 'Round game plan', minutes: 5 },
  { path: 'start-here/linux-terminal-basics.md', label: 'Linux terminal basics', minutes: 10 },
  { path: 'start-here/powershell-basics.md', label: 'PowerShell basics', minutes: 10 },
  { path: 'start-here/using-the-scripts.md', label: 'Using the scripts safely', minutes: 10 },
];

/** Hardening scripts offered on the downloads page. */
export const SCRIPTS = [
  {
    id: 'linux',
    name: 'Linux hardening script',
    file: 'scripts/linux/harden.sh',
    config: 'scripts/linux/config.example.conf',
    worksOn: 'Linux Mint 20–22, Debian 11–12, Ubuntu 20.04–24.04',
    language: 'Bash',
    tested: 'Tested automatically on Debian 12, Ubuntu 22.04 and Linux Mint 21.3 (55 checks).',
    testedLevel: 'tested',
    run: 'sudo bash harden.sh',
  },
  {
    id: 'windows',
    name: 'Windows hardening script',
    file: 'scripts/windows/Harden.ps1',
    config: 'scripts/windows/config.example.psd1',
    worksOn: 'Windows 10 / 11, Windows Server 2016–2022 (Domain Controller aware)',
    language: 'PowerShell 5.1+',
    tested: 'Logic tests pass (38 checks), but it has not been run on a real Windows image yet. Use Audit mode first.',
    testedLevel: 'partial',
    run: 'powershell -ExecutionPolicy Bypass -File .\\Harden.ps1',
  },
  {
    id: 'freebsd',
    name: 'FreeBSD hardening script',
    file: 'scripts/freebsd/harden.sh',
    config: null,
    worksOn: 'FreeBSD 13 / 14',
    language: 'POSIX sh',
    tested: 'Passes shellcheck, but it has not been run on a real FreeBSD system yet. Use --audit first.',
    testedLevel: 'untested',
    run: 'sh harden.sh',
  },
];
