# Website

The CyberPatriot Practice Toolkit website: [Astro](https://astro.build/) + [Starlight](https://starlight.astro.build/), hosted on **Cloudflare Pages**.

**The content is not in this folder.** At build time, `scripts/sync-docs.mjs` copies `../docs/**/*.md` and `../scripts/` into the site. To change a checklist or guide, edit the file in [`docs/`](../docs). Never edit `src/content/docs/checklists|guides|start-here`: those folders are generated and git-ignored.

## Run it on your computer

You need [Node.js](https://nodejs.org/) 22 or newer.

```bash
cd site
npm install
npm run dev        # http://localhost:4321, reloads when you save a file in site/
```

After you change something in `docs/`, stop `npm run dev` and start it again so the docs are copied over.

| Command | What it does |
|---|---|
| `npm run dev` | Sync the docs and start a local preview |
| `npm run build` | Sync the docs and build the site into `dist/` |
| `npm run preview` | Serve the built `dist/` folder |
| `npm run check` | TypeScript / Astro checks |
| `npm test` | Build, then check every internal link, #anchor, checklist step and download checksum |

## Put it on Cloudflare Pages (one time)

1. Sign in to the [Cloudflare dashboard](https://dash.cloudflare.com/). A free account is enough.
2. Go to **Workers & Pages → Create → Pages → Connect to Git**. Cloudflare sometimes moves these buttons; look for the option to create a **Pages** project from a Git repository.
3. Allow Cloudflare to access GitHub and pick **`Ripper1004/CyberPatriot-Security-Script`**. Private repositories work too.
4. Use these build settings:

   | Setting | Value |
   |---|---|
   | Production branch | `main` |
   | Framework preset | `Astro` (or `None`) |
   | Build command | `npm run build` |
   | Build output directory | `dist` |
   | Root directory (under *Advanced*) | `site` |
   | Environment variable (optional) | `SITE_URL`, only if your address is not `https://cp-toolkit.pages.dev` (e.g. a custom domain) |

5. Click **Save and Deploy**. The first build takes 1–2 minutes. Your site is then at `https://<project-name>.pages.dev`.

The live site is **https://cp-toolkit.pages.dev/**.

From then on, every merge into `main` updates the site automatically, and every pull request gets its own preview link.

The Node.js version comes from `site/.node-version`. If a build ever complains about Node, add an environment variable `NODE_VERSION` = `22`.

### Optional: only let your class in

The site tells search engines not to index it (`robots.txt` and `X-Robots-Tag`), but anyone with the link can open it. To require a login:

1. In the Cloudflare dashboard, open **Zero Trust** (free for up to 50 users).
2. Go to **Access → Applications → Add an application → Self-hosted**, and enter your site's address (e.g. `cp-toolkit.pages.dev`).
3. Add a policy that **allows** your students' email addresses, or everyone with your school's email domain.

Students then get a one-time code by email before the site opens.

### Optional: a nicer address

In the Pages project, use **Custom domains** to add a domain you own, e.g. `cyber.yourschool.org`. Then set the `SITE_URL` environment variable to that address and redeploy.

## How the site is organised

```
site/
├── astro.config.mjs        # Starlight config: sidebar, theme, plugins
├── scripts/
│   ├── sync-docs.mjs       # ../docs → src/content/docs (+ data files, downloads)
│   └── verify-build.mjs    # checks dist/ after a build (npm test)
├── public/                 # favicon, robots.txt, _headers (Cloudflare headers)
└── src/
    ├── data/
    │   ├── catalog.mjs     # checklists, rounds, learning path, scripts: edit this when adding an OS
    │   ├── commands.ts     # the Command finder's commands
    │   └── site.ts         # typed helpers
    ├── components/
    │   ├── ChecklistHeader.astro
    │   └── overrides/      # Starlight components we customise (title, content, hero)
    ├── pages/              # home (Learn), toolkit dashboard, tools, downloads, progress
    ├── routeData.ts        # splits the sidebar into the Toolkit and Learn sections
    ├── scripts/            # browser code: progress storage, interactive checklists
    ├── styles/             # theme colours, components, print
    └── content/docs/about.md
```

### Adding a checklist

1. Write `docs/checklists/<name>.md` in the usual format. Every step is a `### N.N Title` heading followed by a `- [ ] Done` line, then a `**Script:** ✅/🔎/✋ ...` line saying what the hardening script does for that step (the build fails without it; a step titled "Fast path ..." is exempt).
2. Add an entry to `CHECKLISTS` in `src/data/catalog.mjs` (and to `SEASON` if a round uses it).
3. Add a sidebar badge in `astro.config.mjs` (optional).
4. Run `npm test`.

### How progress is stored

Everything is in the browser's `localStorage` under keys that start with `cp:v1:`. A checklist step's ID is its heading's anchor (for example `21-see-every-user-on-the-computer`), so **renaming a step's heading resets that one tick**. Nothing is sent to a server.
