---
title: About this site
description: What this site is, how your data is handled, how it is built and how to change it.
cp:
  kind: page
  id: about
---

The **CyberPatriot Practice Toolkit** is a training site for students learning to secure computers in the style of the [CyberPatriot](https://www.uscyberpatriot.org/) competition. It gathers step-by-step checklists, beginner lessons, practice tools and hardening scripts in one place, so nobody needs a GitHub account to use them.

## Practice only

This toolkit is for **practice and learning** on practice virtual machines.

:::caution[Competition rules]
The CyberPatriot 19 Rules Book says:

- **3010.4:** scripts made with the help of AI may **not** be used during a competition round, and paid AI tools may not be used in connection with the competition. Parts of this toolkit were written with AI help.
- **3011.5:** publicly posting scripts or resources made for CyberPatriot is **prohibited**.

If your school competes, use this site to learn, then have your team write its own materials and keep them private.
:::

Never run the scripts on a computer you don't own or aren't allowed to change.

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

Found a mistake, or want to add a step? Use the **Edit page** link at the bottom of any checklist or lesson. It opens the page's Markdown file on GitHub. Keep the checklist format: **What · Why it matters · Clicking · Typing · Check it worked**, written for someone who has never done this before. The repository's [README](https://github.com/Ripper1004/CyberPatriot-Security-Script#readme) has the details.
