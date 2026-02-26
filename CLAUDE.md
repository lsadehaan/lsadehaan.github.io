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

## Code Conventions

- Prettier config: 2-space tabs, 80 char width, double quotes
- Do not modify `assets/js/categories.js` - generates category pill links
- JavaScript for EMV tools is embedded in `emvtools.md` within `<script>` tags
