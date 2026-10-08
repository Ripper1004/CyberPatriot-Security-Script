// Client-side behaviour for docs pages: interactive checklist steps,
// progress card, "hide finished", table-of-contents counters and lessons.
import {
  getDoneSteps,
  getReadLessons,
  getValue,
  onProgressChange,
  resetSteps,
  setLessonRead,
  setStepDone,
  setStepsDone,
  setValue,
  storageAvailable,
} from './store';
import { initNames } from './names';

interface StepRef {
  id: string;
  box: HTMLInputElement;
  /** The element that gets the done styling (a step block or a list item). */
  el: HTMLElement;
  section: string;
  /** auto = done by the hardening script, review = script checks, manual = by hand */
  script?: string;
}

function initSteps(content: HTMLElement) {
  const page = content.dataset.cpPage;
  if (!page) return;
  const markers = [...content.querySelectorAll<HTMLElement>('[data-cp-step]')];
  if (!markers.length) return;

  const steps: StepRef[] = [];
  let currentSection = '';
  const sectionOf = new Map<Element, string>();
  // Map each top-level element to the h2 section it belongs to.
  for (const el of [...content.children]) {
    const h2 = el.matches('.sl-heading-wrapper.level-h2') ? el.querySelector('h2') : el.matches('h2') ? el : null;
    if (h2) currentSection = h2.id;
    sectionOf.set(el, currentSection);
  }

  for (const marker of markers) {
    const id = marker.dataset.cpStep as string;
    if (marker.classList.contains('cp-step')) {
      // Block step: group the heading and everything up to the next heading.
      const section = sectionOf.get(marker) ?? '';
      const block = wrapStepBlock(marker);
      const box = marker.querySelector<HTMLInputElement>('input');
      if (!box) continue;
      box.id = `cp-step-${id}`;
      box.setAttribute('aria-describedby', block.querySelector('h3,h4')?.id ?? '');
      block.dataset.cpScript = marker.dataset.cpScript ?? '';
      steps.push({ id, box, el: block, section, script: marker.dataset.cpScript });
    } else {
      // Inline step inside a task list item.
      const li = marker.closest('li');
      const box = li?.querySelector<HTMLInputElement>('input[type="checkbox"]');
      if (!li || !box) continue;
      box.disabled = false;
      box.removeAttribute('disabled');
      box.classList.add('cp-step__box');
      const label = (li.textContent ?? '').trim();
      box.setAttribute('aria-label', label);
      li.classList.add('cp-li-step');
      // Clicking the text toggles the box too.
      li.addEventListener('click', (e) => {
        if (e.target === box || (e.target as HTMLElement).closest('a,code')) return;
        box.click();
      });
      let top: Element | null = li;
      while (top && top.parentElement !== content) top = top.parentElement;
      steps.push({ id, box, el: li, section: (top && sectionOf.get(top)) ?? '' });
    }
  }

  const progress = document.querySelector<HTMLElement>('[data-cp-progress]');
  const hideBtn = progress?.querySelector<HTMLButtonElement>('[data-cp-action="hide"]');
  const hideKey = `hide-finished`;
  const compactKey = `compact-view`;
  markExplanations(content);

  const render = () => {
    const done = getDoneSteps(page);
    let count = 0;
    for (const s of steps) {
      const isDone = done.has(s.id);
      s.box.checked = isDone;
      s.el.classList.toggle('is-done', isDone);
      const text = s.el.querySelector('.cp-step__text');
      if (text) text.textContent = isDone ? 'Done' : 'Mark this step done';
      if (isDone) count++;
    }
    const total = steps.length;
    const pct = total ? Math.round((count / total) * 100) : 0;
    if (progress) {
      progress.querySelector('[data-cp-count]')!.textContent = String(count);
      progress.querySelector('[data-cp-pct]')!.textContent = `${pct}%`;
      const bar = progress.querySelector<HTMLElement>('[data-cp-bar]')!;
      bar.setAttribute('aria-valuenow', String(count));
      bar.querySelector<HTMLElement>('.cp-bar__fill')!.style.width = `${pct}%`;
      progress.classList.toggle('is-complete', total > 0 && count === total);
    }
    const topFill = document.querySelector<HTMLElement>('[data-cp-topbar] .cp-topbar__fill');
    if (topFill) topFill.style.width = `${pct}%`;
    renderTocCounts(steps, done);
    const compact = getValue<boolean>(compactKey, false);
    content.classList.toggle('cp-compact', compact);
    progress?.querySelector('[data-cp-action="compact"]')?.setAttribute('aria-pressed', String(compact));
    const hidden = getValue<boolean>(hideKey, false);
    content.classList.toggle('cp-hide-done', hidden);
    hideBtn?.setAttribute('aria-pressed', String(hidden));
    if (hideBtn) hideBtn.textContent = hidden ? 'Show finished steps' : 'Hide finished steps';
  };

  for (const s of steps) {
    s.box.addEventListener('change', () => {
      setStepDone(page, s.id, s.box.checked);
      if (s.box.checked && s.el.classList.contains('cp-block')) celebrate(s.el);
    });
  }

  progress?.addEventListener('click', (e) => {
    const action = (e.target as HTMLElement).closest<HTMLElement>('[data-cp-action]')?.dataset.cpAction;
    if (!action) return;
    if (action === 'next') {
      const done = getDoneSteps(page);
      const next = steps.find((s) => !done.has(s.id));
      if (!next) {
        alert('Every step on this page is done. Nice work!');
        return;
      }
      next.el.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
      next.box.focus({ preventScroll: true });
      next.el.classList.add('cp-flash');
      setTimeout(() => next.el.classList.remove('cp-flash'), 1600);
    } else if (action === 'compact') {
      setValue(compactKey, !getValue<boolean>(compactKey, false));
    } else if (action === 'hide') {
      setValue(hideKey, !getValue<boolean>(hideKey, false));
    } else if (action === 'print') {
      window.print();
    } else if (action === 'script') {
      const auto = steps.filter((s) => s.script === 'auto');
      const ok = confirm(
        `Tick the ${auto.length} steps marked ✅ (done by the script)?\n\n` +
          'Only do this after running the script in APPLY mode. If the script printed FAILED for any of them, untick that step and do it by hand.',
      );
      if (ok) setStepsDone(page, auto.map((s) => s.id), true);
    } else if (action === 'reset') {
      if (confirm('Clear every tick on this checklist? Do this when you start a fresh image.')) resetSteps(page);
    }
  });

  if (!storageAvailable()) progress?.querySelector<HTMLElement>('[data-cp-storage-warning]')?.removeAttribute('hidden');
  render();
  onProgressChange(render);
}

/**
 * Marks the beginner explanations so "Compact view" can hide them: the intro
 * before the first section, "What:" / "Why it matters:" / "Clicking:" paragraphs
 * (and the lists that follow them), and tip / note boxes. Commands ("Typing:"),
 * "Check it worked:", warnings and script tags always stay.
 */
function markExplanations(content: HTMLElement) {
  const EXPLAIN = /^(what|why|clicking)\b[^:]*:?$/i; // "What:", "Why it matters:", "Clicking (GNOME):"
  let beforeFirstSection = true;
  for (const el of [...content.children] as HTMLElement[]) {
    if (el.matches('.sl-heading-wrapper.level-h2, h2')) beforeFirstSection = false;
    if (beforeFirstSection) el.classList.add('cp-explain');
  }
  for (const block of content.querySelectorAll<HTMLElement>('.cp-block')) {
    let hiding = false;
    for (const el of [...block.children] as HTMLElement[]) {
      if (el.matches('.sl-heading-wrapper, .cp-step, .cp-script')) continue;
      if (el.matches('.starlight-aside--caution, .starlight-aside--danger')) continue;
      if (el.matches('.starlight-aside--tip, .starlight-aside--note')) {
        el.classList.add('cp-explain');
        continue;
      }
      const label = el.tagName === 'P' && el.firstElementChild?.tagName === 'STRONG' && el.firstChild === el.firstElementChild
        ? (el.firstElementChild.textContent ?? '').trim()
        : null;
      if (label !== null) hiding = EXPLAIN.test(label);
      if (hiding) el.classList.add('cp-explain');
    }
  }
}

/** Wraps a "mark done" marker, its heading and the content after it in a section. */
function wrapStepBlock(marker: HTMLElement): HTMLElement {
  const isHeading = (el: Element | null) =>
    !!el && (el.matches('.sl-heading-wrapper, h1, h2, h3, h4, h5, h6') || el.tagName === 'HR');
  let start: Element = marker;
  const prev = marker.previousElementSibling;
  if (prev && isHeading(prev) && prev.tagName !== 'HR') start = prev;
  const block = document.createElement('section');
  block.className = 'cp-block';
  start.before(block);
  let el: Element | null = start;
  while (el) {
    const next: Element | null = el.nextElementSibling;
    block.append(el);
    if (!next || (next !== marker && (isHeading(next) || next.matches('.cp-step')))) break;
    el = next;
  }
  return block;
}

function renderTocCounts(steps: StepRef[], done: Set<string>) {
  const bySection = new Map<string, { total: number; done: number }>();
  for (const s of steps) {
    const entry = bySection.get(s.section) ?? { total: 0, done: 0 };
    entry.total++;
    if (done.has(s.id)) entry.done++;
    bySection.set(s.section, entry);
  }
  document.querySelectorAll<HTMLAnchorElement>('starlight-toc a[href^="#"], mobile-starlight-toc a[href^="#"]').forEach((a) => {
    const id = decodeURIComponent(a.hash.slice(1));
    const counts = bySection.get(id);
    let badge = a.querySelector<HTMLElement>('.cp-toc-count');
    if (!counts) {
      badge?.remove();
      return;
    }
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'cp-toc-count';
      a.append(badge);
    }
    badge.textContent = ` ${counts.done}/${counts.total}`; // leading space reads well where Starlight copies the link text
    badge.classList.toggle('is-complete', counts.done === counts.total);
    badge.setAttribute('aria-label', `${counts.done} of ${counts.total} steps done`);
  });
}

function celebrate(el: HTMLElement) {
  if (prefersReducedMotion()) return;
  el.classList.remove('cp-pop');
  void el.offsetWidth;
  el.classList.add('cp-pop');
}

function prefersReducedMotion() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function initLesson() {
  const card = document.querySelector<HTMLElement>('[data-cp-lesson]');
  if (!card) return;
  const id = card.dataset.cpLesson as string;
  const btn = card.querySelector<HTMLButtonElement>('[data-cp-lesson-toggle]')!;
  const chip = document.querySelector<HTMLElement>(`[data-cp-lesson-state="${id}"]`);
  const render = () => {
    const isRead = getReadLessons().has(id);
    btn.setAttribute('aria-pressed', String(isRead));
    btn.querySelector<HTMLElement>('[data-label-off]')!.hidden = isRead;
    btn.querySelector<HTMLElement>('[data-label-on]')!.hidden = !isRead;
    btn.classList.toggle('cp-btn--primary', !isRead);
    card.classList.toggle('is-read', isRead);
    if (chip) chip.hidden = !isRead;
  };
  btn.addEventListener('click', () => setLessonRead(id, !getReadLessons().has(id)));
  render();
  onProgressChange(render);
}

const content = document.querySelector<HTMLElement>('.cp-content');
if (content) {
  initSteps(content);
  initNames(content);
}
initLesson();
