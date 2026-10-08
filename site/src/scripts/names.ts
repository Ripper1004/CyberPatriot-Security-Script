// "Use your names in commands": swaps the example names in code blocks
// (alice, bob, mallory...) for the real names from the README, including in
// what the copy buttons copy.
import { getValue, onProgressChange, setValue } from './store';

/** Example names used in the docs and the role each one plays in the commands. */
const EXAMPLES: { name: string; role: string; source?: ['admins' | 'users', number] }[] = [
  { name: 'alice', role: 'an admin from the README', source: ['admins', 0] },
  { name: 'bob', role: 'a normal user from the README', source: ['users', 0] },
  { name: 'carol', role: 'another normal user', source: ['users', 1] },
  { name: 'erin', role: 'a user you need to create' },
  { name: 'mallory', role: 'an account NOT in the README' },
];
const NAME_RE = new RegExp(`\\b(${EXAMPLES.map((e) => e.name).join('|')})\\b`, 'g');
const VALID = /^[a-z_][a-z0-9._-]*\$?$/i;

type NameMap = Record<string, string>;

function splitNames(s: unknown): string[] {
  return typeof s === 'string' ? s.split(/[\s,;]+/).filter(Boolean) : [];
}

/** Saved mapping, falling back to the names typed into the README config builder. */
function currentMap(): NameMap {
  const saved = getValue<NameMap | null>('name-map', null);
  if (saved) return saved;
  const cb = getValue<{ admins?: string; users?: string } | null>('config-builder', null);
  const lists = { admins: splitNames(cb?.admins), users: splitNames(cb?.users) };
  const map: NameMap = {};
  for (const e of EXAMPLES) if (e.source) map[e.name] = lists[e.source[0]][e.source[1]] ?? '';
  return map;
}

export function initNames(content: HTMLElement) {
  const panel = document.querySelector<HTMLElement>('[data-cp-names]');
  const blocks = [...content.querySelectorAll<HTMLElement>('.expressive-code')];
  if (!panel || !blocks.length) return;

  // Wrap every example name inside code blocks so it can be swapped.
  const found = new Set<string>();
  for (const block of blocks) {
    const walker = document.createTreeWalker(block.querySelector('pre') ?? block, NodeFilter.SHOW_TEXT);
    const nodes: Text[] = [];
    while (walker.nextNode()) nodes.push(walker.currentNode as Text);
    for (const node of nodes) {
      const text = node.data;
      NAME_RE.lastIndex = 0;
      if (!NAME_RE.test(text)) continue;
      const frag = document.createDocumentFragment();
      let last = 0;
      text.replace(NAME_RE, (m, _n, i: number) => {
        frag.append(text.slice(last, i));
        const span = document.createElement('span');
        span.className = 'cp-name';
        span.dataset.cpName = m;
        span.textContent = m;
        frag.append(span);
        found.add(m);
        last = i + m.length;
        return m;
      });
      frag.append(text.slice(last));
      node.replaceWith(frag);
    }
    const copy = block.querySelector<HTMLButtonElement>('button[data-code]');
    if (copy) copy.dataset.cpOrigCode = copy.dataset.code ?? '';
  }
  if (!found.size) return;

  // The panel: one input per example name that appears on this page.
  const examples = EXAMPLES.filter((e) => found.has(e.name));
  panel.hidden = false;
  panel.innerHTML = `
    <details class="cp-names__details">
      <summary><span>Use your names in commands</span><span class="cp-names__state" data-cp-names-state></span></summary>
      <p class="cp-names__hint">The commands on this page use example names. Type the real names from your README and every command (and its Copy button) uses them. Leave a box empty to keep the example.</p>
      <div class="cp-names__grid">
        ${examples
          .map(
            (e) => `<label class="cp-names__row"><code>${e.name}</code><span class="cp-names__role">${e.role}</span>
              <input class="cp-input" type="text" spellcheck="false" autocomplete="off" data-cp-name-input="${e.name}" placeholder="${e.name}" /></label>`,
          )
          .join('')}
      </div>
      <div class="cp-names__actions">
        <button type="button" class="cp-btn cp-btn--sm" data-cp-names-fill>Fill from README config builder</button>
        <button type="button" class="cp-btn cp-btn--sm cp-btn--ghost" data-cp-names-clear>Clear</button>
      </div>
    </details>`;

  const inputs = [...panel.querySelectorAll<HTMLInputElement>('[data-cp-name-input]')];

  const apply = () => {
    const map = currentMap();
    const use = (n: string) => {
      const v = (map[n] ?? '').trim();
      return v && VALID.test(v) ? v : '';
    };
    for (const input of inputs) {
      if (document.activeElement !== input) input.value = map[input.dataset.cpNameInput as string] ?? '';
      input.classList.toggle('is-invalid', !!input.value.trim() && !VALID.test(input.value.trim()));
    }
    content.querySelectorAll<HTMLElement>('.cp-name').forEach((span) => {
      const real = use(span.dataset.cpName as string);
      span.textContent = real || (span.dataset.cpName as string);
      span.classList.toggle('is-set', !!real);
    });
    content.querySelectorAll<HTMLButtonElement>('button[data-cp-orig-code]').forEach((btn) => {
      btn.dataset.code = (btn.dataset.cpOrigCode ?? '').replace(NAME_RE, (m) => use(m) || m);
    });
    const set = examples.filter((e) => use(e.name)).length;
    const state = panel.querySelector('[data-cp-names-state]');
    if (state) state.textContent = set ? `${set} of ${examples.length} set` : 'examples';
  };

  panel.addEventListener('input', (e) => {
    const input = (e.target as HTMLElement).closest<HTMLInputElement>('[data-cp-name-input]');
    if (!input) return;
    setValue('name-map', { ...currentMap(), [input.dataset.cpNameInput as string]: input.value.trim() });
  });
  panel.querySelector('[data-cp-names-fill]')?.addEventListener('click', () => {
    setValue('name-map', null);
    if (!getValue('config-builder', null)) alert('No names saved yet. Fill in the README config builder first.');
    apply();
  });
  panel.querySelector('[data-cp-names-clear]')?.addEventListener('click', () => {
    setValue('name-map', Object.fromEntries(EXAMPLES.map((e) => [e.name, ''])));
  });

  apply();
  onProgressChange(apply);
}
