// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import { CHECKLISTS, LEARNING_PATH, REPO_URL } from './src/data/catalog.mjs';

// The site's public address, used for canonical links and the sitemap.
// Override with a SITE_URL environment variable (e.g. for a custom domain).
// CF_PAGES_URL is not used: it is the one-off address of each deployment.
const site = process.env.SITE_URL || 'https://cp-toolkit.pages.dev';

/** @type {Record<string, { text: string; variant: 'note' | 'default' }>} */
const checklistBadges = {
  'windows-10-11': { text: 'R1 · R2', variant: 'note' },
  'windows-server': { text: 'R2+', variant: 'note' },
  'linux-mint': { text: 'R1+', variant: 'note' },
  debian: { text: 'R2+', variant: 'note' },
  freebsd: { text: 'Semis', variant: 'default' },
  ubuntu: { text: 'Legacy', variant: 'default' },
};

export default defineConfig({
  site,
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'CyberPatriot Toolkit',
      description:
        'Beginner-friendly CyberPatriot checklists, guides, tools and hardening scripts for Windows, Windows Server, Linux Mint, Debian, Ubuntu and FreeBSD.',
      logo: { src: './src/assets/logo.svg', alt: '' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub repository', href: REPO_URL }],
      editLink: { baseUrl: `${REPO_URL}/edit/main/site/` },
      customCss: [
        '@fontsource-variable/inter',
        '@fontsource-variable/jetbrains-mono',
        './src/styles/theme.css',
        './src/styles/site.css',
        './src/styles/print.css',
      ],
      components: {
        PageTitle: './src/components/overrides/PageTitle.astro',
        SiteTitle: './src/components/overrides/SiteTitle.astro',
        Sidebar: './src/components/overrides/Sidebar.astro',
        MarkdownContent: './src/components/overrides/MarkdownContent.astro',
        Hero: './src/components/overrides/Hero.astro',
      },
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#0b1220' } },
        { tag: 'meta', attrs: { name: 'robots', content: 'noindex' } },
      ],
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      expressiveCode: {
        themes: ['github-dark-default', 'github-light-default'],
        styleOverrides: { borderRadius: '0.6rem', codeFontFamily: "'JetBrains Mono Variable', ui-monospace, monospace" },
      },
      // Two sections. src/routeData.ts shows only the current section's groups:
      // Toolkit = what experienced people use during a round, Learn = for beginners.
      // Group labels starting with "Learn" belong to the Learn section.
      sidebar: [
        {
          label: 'Toolkit',
          items: [
            { label: 'Dashboard', link: '/toolkit/' },
            { label: 'My progress', link: '/progress/' },
          ],
        },
        {
          label: 'Checklists',
          items: CHECKLISTS.map((c) => ({
            label: c.name,
            link: `/checklists/${c.id}/`,
            badge: checklistBadges[c.id],
          })),
        },
        {
          label: 'Tools',
          items: [
            { label: 'README config builder', link: '/tools/config-builder/' },
            { label: 'Round timer', link: '/tools/round-timer/' },
            { label: 'Findings to-do list', link: '/tools/findings/' },
            { label: 'Round log', link: '/tools/round-log/' },
            { label: 'Command finder', link: '/tools/commands/' },
            { label: 'Forensics helper', link: '/tools/forensics/' },
            { label: 'Download the scripts', link: '/downloads/' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Forensics questions', link: '/guides/forensics-questions/' },
            { label: 'Linux service hardening', link: '/guides/linux-service-hardening/' },
            { label: 'Cisco & Packet Tracer', link: '/guides/cisco-networking/' },
          ],
        },
        {
          label: 'Learn: Start here',
          items: [
            { label: 'Welcome', link: '/' },
            ...LEARNING_PATH.map((l, i) => ({
              label: `${i + 1}. ${l.label}`,
              link: `/${l.path.replace(/\.md$/, '')}/`,
            })),
          ],
        },
        {
          label: 'Learn: Glossary & more',
          items: [
            { label: 'Glossary', link: '/guides/glossary/' },
            { label: 'Glossary quiz', link: '/tools/glossary-quiz/' },
            { label: 'Networking quiz', link: '/tools/networking-quiz/' },
            { label: 'For mentors & teachers', link: '/guides/for-mentors-and-teachers/' },
            { label: 'About this site', link: '/about/' },
          ],
        },
      ],
      routeMiddleware: './src/routeData.ts',
      plugins: [starlightLinksValidator({ errorOnLocalLinks: true, exclude: ['/', '/#checklists', '/toolkit/', '/files/**', '/tools/**', '/progress/', '/downloads/'] })],
    }),
  ],
});
