#!/usr/bin/env node
// Checks the built site in dist/ (run after `npm run build`):
//   - every internal link and image points to a file that exists
//   - every #anchor on an internal link exists on the target page
//   - every checklist step id matches a heading on its page
//   - every script download exists and matches its checksum
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(SITE, 'dist');
const errors = [];

if (!existsSync(DIST)) {
  console.error('verify-build: dist/ not found. Run `npm run build` first.');
  process.exit(1);
}

function htmlFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return htmlFiles(full);
    return name.endsWith('.html') ? [full] : [];
  });
}

/** URL path -> file in dist, or null. */
function resolvePath(path) {
  const clean = decodeURIComponent(path.split(/[?#]/)[0]);
  const candidates = [join(DIST, clean), join(DIST, clean, 'index.html')];
  return candidates.find((p) => existsSync(p) && statSync(p).isFile()) ?? null;
}

const idCache = new Map();
function idsIn(file) {
  if (!idCache.has(file)) {
    const html = readFileSync(file, 'utf8');
    idCache.set(file, new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1])));
  }
  return idCache.get(file);
}

const pages = htmlFiles(DIST);
let links = 0;
for (const file of pages) {
  const html = readFileSync(file, 'utf8');
  const page = `/${relative(DIST, file).replace(/index\.html$/, '')}`;
  for (const m of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
    const url = m[1].replace(/&amp;/g, '&');
    if (/^(https?:|mailto:|data:|javascript:|\/\/)/.test(url)) continue;
    if (url.startsWith('#')) {
      const id = decodeURIComponent(url.slice(1));
      if (id && id !== '_top' && !idsIn(file).has(id)) errors.push(`${page}: missing anchor ${url}`);
      continue;
    }
    if (!url.startsWith('/')) continue;
    links++;
    const target = resolvePath(url);
    if (!target) {
      errors.push(`${page}: broken link ${url}`);
      continue;
    }
    const hash = url.split('#')[1];
    if (hash && target.endsWith('.html') && !idsIn(target).has(decodeURIComponent(hash))) {
      errors.push(`${page}: link ${url} points to a missing anchor`);
    }
  }
}

// Checklist steps
const checklists = JSON.parse(readFileSync(join(SITE, 'src/data/generated/checklists.json'), 'utf8'));
let steps = 0;
for (const [slug, c] of Object.entries(checklists)) {
  const file = join(DIST, slug, 'index.html');
  const html = readFileSync(file, 'utf8');
  for (const s of c.steps) {
    steps++;
    if (!html.includes(`data-cp-step="${s.id}"`)) errors.push(`${slug}: step ${s.id} has no marker`);
    if (!idsIn(file).has(s.id.replace(/--\d+$/, ''))) errors.push(`${slug}: step ${s.id} has no matching heading`);
  }
}

// Downloads
const downloads = JSON.parse(readFileSync(join(SITE, 'src/data/generated/downloads.json'), 'utf8'));
for (const d of downloads) {
  const file = resolvePath(d.url);
  if (!file) errors.push(`download missing: ${d.url}`);
  else if (createHash('sha256').update(readFileSync(file)).digest('hex') !== d.sha256) errors.push(`checksum mismatch: ${d.url}`);
}

if (errors.length) {
  console.error(`verify-build: ${errors.length} problem(s)`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(
  `verify-build: OK (${pages.length} pages, ${links} internal links, ${steps} checklist steps, ${downloads.length} downloads)`,
);
