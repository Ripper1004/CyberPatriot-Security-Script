#!/usr/bin/env node
// Copies the repository's Markdown docs (../docs) into the Starlight content
// folder and turns GitHub-flavoured extras into website features:
//   - "# Title" line            -> `title` frontmatter
//   - > [!NOTE] / [!WARNING]... -> Starlight asides (:::note, :::caution...)
//   - links to other .md files  -> site URLs (other repo files -> GitHub)
//   - "- [ ] Done" task items    -> interactive "mark as done" steps
// It also writes data files used by the site (checklist steps, glossary,
// script downloads). docs/ stays the single source of truth: edit there.

import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import GithubSlugger from 'github-slugger';
import { BRANCH, CHECKLISTS, LEARNING_PATH, REPO_URL, SCRIPTS } from '../src/data/catalog.mjs';

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(SITE, '..');
const DOCS = join(ROOT, 'docs');
const OUT_DOCS = join(SITE, 'src/content/docs');
const OUT_DATA = join(SITE, 'src/data/generated');
const OUT_DOWNLOADS = join(SITE, 'public/files');
const SYNCED_DIRS = ['start-here', 'checklists', 'guides'];

const ALERTS = {
  NOTE: { type: 'note', title: 'Note' },
  TIP: { type: 'tip', title: 'Tip' },
  IMPORTANT: { type: 'note', title: 'Important' },
  WARNING: { type: 'caution', title: 'Warning' },
  CAUTION: { type: 'danger', title: 'Careful' },
};

const fail = (msg) => {
  console.error(`sync-docs: ${msg}`);
  process.exit(1);
};

/** All .md files under dir, as paths relative to dir (posix separators). */
function listMarkdown(dir, base = dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...listMarkdown(full, base));
    else if (name.endsWith('.md')) out.push(relative(base, full).split('\\').join('/'));
  }
  return out;
}

/** Plain text of inline Markdown (what ends up in the rendered heading). */
function inlineText(md) {
  return md
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/(\*\*|__)(.+?)\1/g, '$2')
    .replace(/(^|[\s(])[*_]([^*_\s][^*_]*?)[*_](?=[\s).,:;!?]|$)/g, '$1$2')
    .replace(/<[^>]+>/g, '')
    .trim();
}

/** docs-relative .md path -> site route ("checklists/debian.md" -> "/checklists/debian/"). */
function routeFor(docPath) {
  const noExt = docPath.replace(/\.md$/, '');
  if (noExt === 'index') return '/';
  return `/${noExt.replace(/\/index$/, '')}/`;
}

function rewriteLink(target, fromDoc) {
  if (/^([a-z]+:|#|\/)/i.test(target)) return target;
  const [pathPart, hash = ''] = target.split('#');
  const resolved = posix.normalize(posix.join(posix.dirname(`docs/${fromDoc}`), pathPart));
  const anchor = hash ? `#${hash}` : '';
  if (resolved.startsWith('docs/') && resolved.endsWith('.md')) {
    const docPath = resolved.slice('docs/'.length);
    if (!existsSync(join(DOCS, docPath))) fail(`${fromDoc}: broken link to ${target}`);
    return routeFor(docPath) + anchor;
  }
  if (!existsSync(join(ROOT, resolved))) fail(`${fromDoc}: broken link to ${target}`);
  const kind = statSync(join(ROOT, resolved)).isDirectory() ? 'tree' : 'blob';
  return `${REPO_URL}/${kind}/${BRANCH}/${resolved}${anchor}`;
}

const yamlString = (s) => JSON.stringify(s);

/**
 * Converts one docs file. Returns { markdown, title, description, steps }.
 */
function convert(docPath, source) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  const slugger = new GithubSlugger();
  const steps = [];
  let title = '';
  let description = '';
  let inFence = false;
  let fenceMarker = '';
  let heading = { slug: '', text: '', level: 0 };
  let section = '';
  let itemsUnderHeading = 0;
  let alert = null; // { indent, lines[] }

  const flushAlert = () => {
    if (!alert) return;
    const { indent, kind, body } = alert;
    out.push(`${indent}:::${kind.type}[${kind.title}]`);
    for (const l of body) out.push(l === '' ? '' : `${indent}${l}`);
    out.push(`${indent}:::`);
    alert = null;
  };

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // GitHub alert body: every following "> " line belongs to the alert.
    if (alert) {
      const m = line.match(/^(\s*)>\s?(.*)$/);
      if (m && m[1] === alert.indent) {
        alert.body.push(m[2].replace(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewriteLink(target, docPath)})`));
        continue;
      }
      flushAlert();
    }

    // Code fences: copy verbatim, never rewrite inside them.
    const fence = line.match(/^\s*(```+|~~~+)/);
    if (fence) {
      if (!inFence) {
        inFence = true;
        fenceMarker = fence[1];
      } else if (line.trim().startsWith(fenceMarker)) {
        inFence = false;
      }
      out.push(line);
      continue;
    }
    if (inFence) {
      out.push(line);
      continue;
    }

    // GitHub alerts -> Starlight asides
    const alertStart = line.match(/^(\s*)>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/);
    if (alertStart) {
      alert = { indent: alertStart[1], kind: ALERTS[alertStart[2]], body: [] };
      continue;
    }

    // Title
    const h1 = !title && line.match(/^#\s+(.+?)\s*#*\s*$/);
    if (h1) {
      title = inlineText(h1[1]);
      continue;
    }

    // Headings: track the slug Starlight will give them.
    const h = line.match(/^(#{2,6})\s+(.+?)\s*#*\s*$/);
    if (h) {
      const text = inlineText(h[2]);
      heading = { slug: slugger.slug(text), text, level: h[1].length };
      if (heading.level === 2) section = text;
      itemsUnderHeading = 0;
    }

    // Description: first plain paragraph after the title.
    if (title && !description && line.trim() && !/^(#|>|\||-|\*|\d+\.|:::|<|---)/.test(line.trim())) {
      description = inlineText(line).replace(/\s+/g, ' ');
      if (description.length > 180) description = `${description.slice(0, 177).replace(/\s+\S*$/, '')}…`;
    }

    // Links
    line = line.replace(/\]\(([^)\s]+)\)/g, (_, target) => `](${rewriteLink(target, docPath)})`);

    // Task items -> interactive steps
    const task = line.match(/^(\s*)- \[[ xX]\] (.+)$/);
    if (task && heading.slug) {
      itemsUnderHeading += 1;
      const isDone = task[2].trim() === 'Done';
      const id = isDone ? heading.slug : `${heading.slug}--${itemsUnderHeading}`;
      if (steps.some((s) => s.id === id)) fail(`${docPath}: duplicate step id ${id}`);
      steps.push({ id, title: isDone ? heading.text : inlineText(task[2]), section: section || heading.text });
      if (isDone) {
        out.push(
          `<div class="cp-step" data-cp-step="${id}"><label class="cp-step__label"><input type="checkbox" class="cp-step__box" /><span class="cp-step__text">Mark this step done</span></label></div>`,
        );
      } else {
        out.push(`${task[1]}- [ ] <span class="cp-step-inline" data-cp-step="${id}"></span>${task[2]}`);
      }
      continue;
    }

    out.push(line);
  }
  flushAlert();
  if (inFence) fail(`${docPath}: unclosed code fence`);
  if (!title) fail(`${docPath}: missing "# Title" line`);

  // Tidy blank lines around the HTML step blocks (HTML blocks need them).
  const markdown = out
    .join('\n')
    .replace(/\n*(<div class="cp-step"[^\n]*<\/div>)\n*/g, '\n\n$1\n\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return { markdown, title, description, steps };
}

function frontmatter(fields) {
  const lines = ['---'];
  for (const [key, value] of Object.entries(fields)) {
    if (value === undefined) continue;
    if (typeof value === 'object') {
      lines.push(`${key}:`);
      for (const [k, v] of Object.entries(value)) {
        if (v === undefined) continue;
        if (typeof v === 'object') {
          lines.push(`  ${k}:`);
          for (const [k2, v2] of Object.entries(v)) lines.push(`    ${k2}: ${typeof v2 === 'string' ? yamlString(v2) : v2}`);
        } else lines.push(`  ${k}: ${typeof v === 'string' ? yamlString(v) : v}`);
      }
    } else lines.push(`${key}: ${typeof value === 'string' ? yamlString(value) : value}`);
  }
  lines.push('---', '');
  return lines.join('\n');
}

/** Parse the first Markdown table in glossary.md into [{ term, meaning }]. */
function parseGlossary(source) {
  const rows = source.split('\n').filter((l) => /^\|.*\|\s*$/.test(l));
  return rows
    .slice(2)
    .map((row) => row.slice(1, -1).split('|').map((c) => c.trim()))
    .filter((cells) => cells.length >= 2)
    .map(([term, meaning]) => ({
      term: inlineText(term),
      meaning: inlineText(meaning),
    }));
}

function main() {
  if (!existsSync(DOCS)) fail(`docs folder not found at ${DOCS}`);

  for (const dir of SYNCED_DIRS) rmSync(join(OUT_DOCS, dir), { recursive: true, force: true });
  rmSync(OUT_DATA, { recursive: true, force: true });
  rmSync(OUT_DOWNLOADS, { recursive: true, force: true });
  mkdirSync(OUT_DATA, { recursive: true });

  const checklistIds = new Set(CHECKLISTS.map((c) => c.id));
  const pathOrder = LEARNING_PATH.map((p) => p.path);
  const pages = {};
  const checklists = {};
  let glossary = [];

  for (const docPath of listMarkdown(DOCS)) {
    if (docPath === 'index.md') continue; // the site has its own home page
    const top = docPath.split('/')[0];
    if (!SYNCED_DIRS.includes(top)) fail(`${docPath}: put docs in one of ${SYNCED_DIRS.join(', ')}`);

    const source = readFileSync(join(DOCS, docPath), 'utf8');
    const { markdown, title, description, steps } = convert(docPath, source);
    const slug = docPath.replace(/\.md$/, '');
    const id = slug.split('/').pop();
    const isChecklist = top === 'checklists' && checklistIds.has(id);
    const lesson = pathOrder.indexOf(docPath);

    const fm = frontmatter({
      title,
      description: description || undefined,
      editUrl: `${REPO_URL}/edit/${BRANCH}/docs/${docPath}`,
      tableOfContents: isChecklist ? { minHeadingLevel: 2, maxHeadingLevel: 2 } : undefined,
      cp: {
        kind: isChecklist ? 'checklist' : top === 'start-here' ? 'lesson' : 'guide',
        id,
        lesson: lesson >= 0 ? lesson + 1 : undefined,
        steps: steps.length || undefined,
      },
    });

    const outFile = join(OUT_DOCS, `${slug}.md`);
    mkdirSync(dirname(outFile), { recursive: true });
    writeFileSync(outFile, `${fm}${markdown}\n`);

    pages[slug] = { title, description, route: routeFor(docPath), steps: steps.length };
    if (steps.length) checklists[slug] = { title, route: routeFor(docPath), steps };
    if (docPath === 'guides/glossary.md') glossary = parseGlossary(source);
  }

  for (const c of CHECKLISTS) {
    if (!checklists[`checklists/${c.id}`]) fail(`catalog.mjs lists checklist "${c.id}" but docs/checklists/${c.id}.md has no steps`);
  }
  for (const p of LEARNING_PATH) {
    if (!existsSync(join(DOCS, p.path))) fail(`catalog.mjs LEARNING_PATH: docs/${p.path} not found`);
  }

  // Script downloads
  const downloads = [];
  for (const s of SCRIPTS) {
    for (const file of [s.file, s.config].filter(Boolean)) {
      const src = join(ROOT, file);
      if (!existsSync(src)) fail(`catalog.mjs SCRIPTS: ${file} not found`);
      const rel = file.replace(/^scripts\//, '');
      const dest = join(OUT_DOWNLOADS, rel);
      mkdirSync(dirname(dest), { recursive: true });
      cpSync(src, dest);
      const buf = readFileSync(src);
      downloads.push({
        script: s.id,
        file,
        url: `/files/${rel}`,
        name: rel.split('/').pop(),
        bytes: buf.length,
        lines: buf.toString('utf8').split('\n').length,
        sha256: createHash('sha256').update(buf).digest('hex'),
      });
    }
  }

  writeFileSync(join(OUT_DATA, 'pages.json'), `${JSON.stringify(pages, null, 2)}\n`);
  writeFileSync(join(OUT_DATA, 'checklists.json'), `${JSON.stringify(checklists, null, 2)}\n`);
  writeFileSync(join(OUT_DATA, 'glossary.json'), `${JSON.stringify(glossary, null, 2)}\n`);
  writeFileSync(join(OUT_DATA, 'downloads.json'), `${JSON.stringify(downloads, null, 2)}\n`);

  const stepCount = Object.values(checklists).reduce((n, c) => n + c.steps.length, 0);
  console.log(
    `sync-docs: ${Object.keys(pages).length} pages, ${Object.keys(checklists).length} with steps (${stepCount} steps), ${glossary.length} glossary terms, ${downloads.length} downloads`,
  );
}

main();
