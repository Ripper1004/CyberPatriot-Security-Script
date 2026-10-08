// Splits the site into two sections with their own sidebar:
//   Toolkit - checklists, tools, scripts, reference (for people who know the game)
//   Learn   - welcome, lessons, glossary (for beginners)
// The sidebar groups are defined in astro.config.mjs; groups whose label starts
// with "Learn" belong to the Learn section.
import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

type Entry = { type: 'link'; isCurrent: boolean } | { type: 'group'; label: string; entries: Entry[] };

const isLearnGroup = (e: Entry) => e.type === 'group' && e.label.startsWith('Learn');
const hasCurrent = (e: Entry): boolean => (e.type === 'link' ? e.isCurrent : e.entries.some(hasCurrent));
const flatten = (entries: Entry[]): Entry[] => entries.flatMap((e) => (e.type === 'group' ? flatten(e.entries) : [e]));

/** Pages outside the sidebar that still belong to Learn. */
const LEARN_PATHS = ['/', '/404/', '/404.html'];

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  const sidebar = route.sidebar as unknown as Entry[];
  const current = sidebar.find(hasCurrent);
  const learn = current ? isLearnGroup(current) : LEARN_PATHS.includes(context.url.pathname);
  const section = learn ? 'learn' : 'toolkit';
  (route as unknown as { cpSection: string }).cpSection = section;

  const kept = sidebar.filter((e) => isLearnGroup(e) === learn);
  // Show "Learn: start here" as just "Start here" etc.
  const shown = kept.map((e) => (e.type === 'group' ? { ...e, label: e.label.replace(/^Learn: /, ''), collapsed: false } : e));
  route.sidebar = shown as unknown as typeof route.sidebar;

  // Previous / next links stay inside the section.
  const links = flatten(shown) as unknown as (typeof route.pagination.prev)[];
  const i = links.findIndex((l) => l?.isCurrent);
  if (i >= 0) {
    route.pagination = {
      prev: route.pagination.prev && i > 0 ? links[i - 1] : undefined,
      next: route.pagination.next && i < links.length - 1 ? links[i + 1] : undefined,
    };
  }
});
