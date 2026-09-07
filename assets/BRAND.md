<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
Copyright (c) 2026 Tiberiu Balasea
-->

# The mark

Nine cells on a modular grid. Seven filled cells trace the S; the two open
cells are the sans-I/O core. One red cell, bottom right — the active call.

The name is a trademark and is not covered by either software licence. What
you may and may not do with these files is in [`../TRADEMARK.md`](../TRADEMARK.md);
this page is only about how to draw it correctly when you are allowed to.

## Geometry

Cell `C`, gutter `0.09C`, artwork box `3.18C` square. Clear space on every side
is one cell. Minimum size 16 px.

No rounding, no rotation, no outline, no shadow, no other colours, and nothing
placed inside the two open cells. They are the point.

## Colour

| Role | Value |
|---|---|
| ink | `#201e1d` |
| red | `#ec3013` — one cell, never more |
| ground | `#f3f2f2` |

## Type

Archivo 800, tracking `-0.045em`. The wordmark is always lowercase `sipral`.

## Files

| File | Use |
|---|---|
| `sipral-mark.svg` | the mark on a light ground. Pure rectangles, so it renders identically everywhere |
| `sipral-mark-dark.svg` | the same on a dark ground |
| `sipral-mark-256.png`, `sipral-mark-512.png` | where a raster is required: package icons, avatars |
| `sipral-lockup.png`, `sipral-lockup-dark.png` | mark and wordmark, horizontal |
| `sipral-lockup.svg`, `sipral-lockup-dark.svg` | the same as vectors — **but the wordmark is live text**, so a viewer without Archivo installed substitutes another face. Use the PNG anywhere the font is not guaranteed, which is most places |

The full kit — stacked lockups, the favicon set, avatars, banners, and the
brand manual — is not in this repository. It is not needed to build anything,
and a repository is a poor place to keep artwork that changes on its own
schedule.

## Before publishing any of these anywhere

Strip embedded provenance metadata first. The files in this directory have
already had it removed, and `scripts/check.sh` fails if any of it comes back;
the masters outside this repository have not. It is not a licensing matter —
it is that a signed manifest inside an image says who made it, and this project
publishes what it wrote and nothing about how.

For a PNG that means keeping only `IHDR`, `PLTE`, `tRNS`, `IDAT`, `IEND` and
`sRGB`, and dropping every other chunk. For an SVG it means removing the
`<metadata>` element and any namespace declared for it. Neither changes a pixel.
