# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Jekyll-based personal/company website for IDNTEQ, hosted on GitHub Pages at lsadehaan.github.io. It uses the "Serial Programmer" theme and includes a blog section and interactive EMV/cryptography tools.

## Build Commands

```bash
# Install dependencies
bundle install

# Run local development server
bundle exec jekyll serve

# Build for production
bundle exec jekyll build
```

## Architecture

### Content Structure
- `_config.yml` - Site configuration (title, plugins, collections)
- `_data/author.yml` - Author/company information displayed in bio
- `all_collections/_posts/` - Blog posts in markdown with YAML front matter
- `index.md` - Blog listing page (uses `blog` layout)
- `emvtools.md` - Interactive EMV tools page (uses `toolpage` layout)
- `hair/index.html` - "Hair Day" app, a standalone page (`layout: null`, permalink `/hair/`)

### Layouts (`_layouts/`)
- `blog.html` - Blog index with post listing
- `post.html` - Individual blog post
- `toolpage.html` - Full-width page for tool interfaces

### Key Files
- `emvtools.md` - Contains all EMV tool implementations as inline JavaScript:
  - RSA operations (public/private key operations)
  - Hex Manipulator (file upload, byte offset display, parity adjustment)
  - CPS Parser (EMV personalization file parsing)
  - Hash Calculator (SHA-1, SHA-256)
  - ELO Certificate Parser (.req file parsing)
  - Issuer Certificate Validator

### Hair Day app (`/hair/`)

A self-contained kids' app: it picks a hairstyle for every day of the year,
explains how to do it, and includes a salon sandbox and two games. It does not
use the site layouts — `hair/index.html` is a complete HTML document — and it
stores everything in `localStorage` under `hairday.v1`. No build step, no
dependencies; plain ES5-style browser JavaScript in load order:

- `assets/hair/hair-data.js` — `window.HairData`: hairstyle catalog (each entry
  has a `look`, tags, tools, bilingual steps), UI strings in English and
  Portuguese, colour palettes, and `specialDaysFor(year, profile)` which
  computes Brazilian holidays (Carnival and Easter are derived from the
  Gregorian Easter algorithm), season starts, birthdays and user-added days.
- `assets/hair/hair-draw.js` — `window.HairDraw.render(look)` builds a cartoon
  portrait as an inline SVG string from a `look`
  (`length`, `texture`, `updo`, `braid`, `bangs`, `accessory`, colours). Layer
  order matters: body, back hair, head, face, scalp, over-head tails, buns,
  front braids, accessories.
- `assets/hair/hair-app.js` — `window.HairApp`: state and persistence, the
  hash router, the day picker (`planYear` scores styles against the weekday,
  season and special-day tags, then avoids repeats inside a rolling window) and
  the Today / Year / How-to / Lookbook / Settings views.
- `assets/hair/hair-games.js` — `window.HairGames`: the salon sandbox, the
  copy-the-client game and the memory game.

To add a hairstyle, append one `S(...)` entry in `STYLES`; the renderer and all
the views pick it up automatically. Styles declare which hair lengths (`len`)
and textures (`tex`) they suit — keep every length/texture combination well
stocked, or the picker falls back to the whole catalog.

## Code Conventions

- Prettier config: 2-space tabs, 80 char width, double quotes
- Do not modify `assets/js/categories.js` - generates category pill links
- JavaScript for EMV tools is embedded in `emvtools.md` within `<script>` tags
- The Hair Day app keeps its JavaScript in `assets/hair/`, not inline
