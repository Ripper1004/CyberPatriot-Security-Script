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
      title: 'CP Practice Toolkit',
      description:
        'Beginner-friendly CyberPatriot practice checklists, guides, tools and hardening scripts for Windows, Windows Server, Linux Mint, Debian, Ubuntu and FreeBSD.',
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
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Welcome', link: '/' },
            ...LEARNING_PATH.map((l, i) => ({
              label: `${i + 1}. ${l.label}`,
              link: `/${l.path.replace(/\.md$/, '')}/`,
            })),
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
          label: 'Guides',
          items: [
            { label: 'Forensics questions', link: '/guides/forensics-questions/' },
            { label: 'Linux service hardening', link: '/guides/linux-service-hardening/' },
            { label: 'Glossary', link: '/guides/glossary/' },
            { label: 'For mentors & teachers', link: '/guides/for-mentors-and-teachers/' },
          ],
        },
        {
          label: 'Tools',
          items: [
            { label: 'README config builder', link: '/tools/config-builder/' },
            { label: 'Round timer', link: '/tools/round-timer/' },
            { label: 'Command finder', link: '/tools/commands/' },
            { label: 'Glossary quiz', link: '/tools/glossary-quiz/' },
            { label: 'Download the scripts', link: '/downloads/' },
            { label: 'My progress', link: '/progress/' },
          ],
        },
        { label: 'About this site', link: '/about/' },
      ],
      plugins: [starlightLinksValidator({ errorOnLocalLinks: true, exclude: ['/', '/#checklists', '/files/**', '/tools/**', '/progress/', '/downloads/'] })],
    }),
  ],
});
