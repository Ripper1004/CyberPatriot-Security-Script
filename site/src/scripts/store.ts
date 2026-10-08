// Progress storage. Everything stays in this browser's localStorage: no
// accounts, no server. Every access is wrapped because storage can be
// blocked (private windows, strict settings) and the site must still work.

const PREFIX = 'cp:v1:';
export const CHANGE_EVENT = 'cp:progress-change';

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(PREFIX + key);
    return raw === null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown): void {
  try {
    if (value === null || value === undefined) localStorage.removeItem(PREFIX + key);
    else localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    /* storage unavailable: progress just won't be remembered */
  }
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT, { detail: { key } }));
}

export function storageAvailable(): boolean {
  try {
    const k = `${PREFIX}probe`;
    localStorage.setItem(k, '1');
    localStorage.removeItem(k);
    return true;
  } catch {
    return false;
  }
}

/** Calls fn now and whenever progress changes (this tab or another tab). */
export function onProgressChange(fn: () => void): void {
  window.addEventListener(CHANGE_EVENT, fn);
  window.addEventListener('storage', (e) => {
    if (!e.key || e.key.startsWith(PREFIX)) fn();
  });
}

// ---- Checklist steps --------------------------------------------------------

export function getDoneSteps(page: string): Set<string> {
  return new Set(read<string[]>(`steps:${page}`, []));
}

export function setStepDone(page: string, step: string, done: boolean): void {
  const set = getDoneSteps(page);
  if (done) set.add(step);
  else set.delete(step);
  write(`steps:${page}`, set.size ? [...set] : null);
  touch(page);
}

export function resetSteps(page: string): void {
  write(`steps:${page}`, null);
}

/** Remembers the last page with progress, for "continue where you left off". */
function touch(page: string): void {
  write('last', { page, at: Date.now() });
}

export function getLast(): { page: string; at: number } | null {
  return read<{ page: string; at: number } | null>('last', null);
}

// ---- Lessons ----------------------------------------------------------------

export function getReadLessons(): Set<string> {
  return new Set(read<string[]>('lessons', []));
}

export function setLessonRead(id: string, isRead: boolean): void {
  const set = getReadLessons();
  if (isRead) set.add(id);
  else set.delete(id);
  write('lessons', set.size ? [...set] : null);
}

// ---- Generic small values (preferences, tools) -------------------------------

export function getValue<T>(key: string, fallback: T): T {
  return read<T>(`val:${key}`, fallback);
}

export function setValue(key: string, value: unknown): void {
  write(`val:${key}`, value);
}

// ---- Export / import / reset everything ---------------------------------------

export function exportAll(): Record<string, unknown> {
  const data: Record<string, unknown> = {};
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(PREFIX)) data[k.slice(PREFIX.length)] = JSON.parse(localStorage.getItem(k) ?? 'null');
    }
  } catch {
    /* ignore */
  }
  return data;
}

export function importAll(data: Record<string, unknown>): number {
  let n = 0;
  for (const [k, v] of Object.entries(data)) {
    if (!/^(steps:|lessons$|last$|val:)/.test(k)) continue;
    try {
      localStorage.setItem(PREFIX + k, JSON.stringify(v));
      n++;
    } catch {
      /* ignore */
    }
  }
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT, { detail: { key: '*' } }));
  return n;
}

export function resetAll(): void {
  try {
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(PREFIX)) keys.push(k);
    }
    keys.forEach((k) => localStorage.removeItem(k));
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT, { detail: { key: '*' } }));
}
