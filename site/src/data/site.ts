// Typed helpers around catalog.mjs and the generated data files.
import { CHECKLISTS, LEARNING_PATH, SCRIPTS, SEASON } from './catalog.mjs';
import pagesJson from './generated/pages.json';
import checklistsJson from './generated/checklists.json';

export interface PageInfo {
  title: string;
  description: string;
  route: string;
  steps: number;
}
export interface Step {
  id: string;
  title: string;
  section: string;
  /** What the hardening script does for this step (checklist steps only). */
  script?: 'auto' | 'review' | 'manual';
}

export const pages = pagesJson as Record<string, PageInfo>;
export const checklistSteps = checklistsJson as Record<string, { title: string; route: string; steps: Step[] }>;

export type Checklist = (typeof CHECKLISTS)[number];
export { CHECKLISTS, LEARNING_PATH, SCRIPTS, SEASON };

export const IMAGE_NAMES: Record<string, string> = {
  windows: 'Windows 11',
  server: 'Server 2022',
  mint: 'Mint 21',
  debian: 'Debian 12',
  freebsd: 'FreeBSD',
  ubuntu: 'Ubuntu',
};

/** Rounds of this season that use the given image id. */
export function roundsFor(image: string) {
  return SEASON.rounds.filter((r) => r.images.includes(image));
}

export function checklistById(id: string) {
  return CHECKLISTS.find((c) => c.id === id);
}

/** The learning path with titles and routes filled in. */
export const lessons = LEARNING_PATH.map((l, i) => {
  const slug = l.path.replace(/\.md$/, '');
  const page = pages[slug];
  if (!page) throw new Error(`Learning path page missing: ${l.path}`);
  return { n: i + 1, slug, id: slug.split('/').pop() as string, label: l.label, minutes: l.minutes, ...page };
});
