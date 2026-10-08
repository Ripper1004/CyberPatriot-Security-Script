---
title: About this site
description: What this site is, how your data is handled, how it is built and how to change it.
cp:
  kind: page
  id: about
---

The **CyberPatriot Toolkit** gathers step-by-step checklists, beginner lessons, tools and hardening scripts for the [CyberPatriot](https://www.uscyberpatriot.org/) competition in one place, so nobody needs a GitHub account to use them.

## Your data

- There are **no accounts, no analytics and no cookies** set by this site.
- Ticks, lessons read, quiz scores and the timer are saved in **your browser's local storage**. They never leave your computer. Clearing your browser data erases them.
- The README config builder runs entirely in your browser. Names and passwords you type are not sent anywhere, and passwords are never saved.
- [My progress](/progress/) can export everything to a file and import it again on another computer.

## How it's built

- The pages come from the Markdown files in the repository's [`docs/` folder](https://github.com/Ripper1004/CyberPatriot-Security-Script/tree/main/docs), so the same checklists also read well on GitHub.
- The site is built with [Astro](https://astro.build/) and [Starlight](https://starlight.astro.build/), and hosted on Cloudflare Pages. Search runs in your browser with [Pagefind](https://pagefind.app/).
- Every change merged into the repository rebuilds the site automatically.

## Changing something

Mentors: see [Keeping the material up to date](/guides/for-mentors-and-teachers/#keeping-the-material-up-to-date).
