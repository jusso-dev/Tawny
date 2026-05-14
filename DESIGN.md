# Design

## Overview

Tawny is a product UI for operational endpoint telemetry. The visual system is restrained, dense, and utilitarian: tinted neutrals, amber action color from the logo, readable tables, clear status labels, and minimal ornament.

## Theme

Primary scene: an engineer is checking endpoint telemetry on a laptop or external monitor during local development, often in a dim room, with logs and terminal windows nearby. Dark mode is the default presentation because it sits comfortably beside terminals and observability tools, while light mode remains available for documentation and daylight use.

## Color

Use OKLCH tokens only. Neutrals should be subtly warm rather than pure grayscale.

- Background: deep warm charcoal
- Foreground: warm near-white, not pure white
- Card: one step lifted from the background
- Muted: low-contrast panel and table-header surface
- Border: visible but quiet
- Accent: restrained amber for primary actions, selected controls, and chart highlights
- Success, warning, danger: semantic state only

Color strategy: restrained product palette. Accent usage should stay limited to actions, live state, chart emphasis, and focus rings.

## Typography

Use a system UI sans stack. Product surfaces should use modest type contrast:

- Page titles: 24 to 30px, semibold
- Section titles: 16 to 18px, semibold
- Body and table text: 14px
- Metadata and IDs: 12px, muted, monospace where appropriate

Do not use display fonts or decorative letter spacing in product views.

## Layout

Use a predictable app-shell rhythm:

- Main content max width around 72rem
- Page padding 24px on small screens, 40px vertical on desktop
- Tables and repeated operational panels may use bordered containers
- Avoid nested cards
- Prefer full-width tables and panels for scan-heavy content

## Components

Buttons use 8px or smaller radii, stable height, visible hover and disabled states. Icon buttons need labels or tooltips when meaning is not obvious.

Tables are first-class components: clear headers, consistent row height, visible selected row state, keyboard focus, and readable empty states.

Status badges pair color with text. Semantic colors should not be used decoratively.

Charts are supporting evidence, not the hero. Keep them compact and legible.

## Motion

Motion should be brief and state-driven, 150 to 220ms with ease-out timing. Avoid page-load choreography and decorative movement. Respect reduced motion.

## Screenshot Guidance

README screenshots should show real application state:

1. Dashboard with synthetic telemetry present
2. Agents list with the synthetic agent online
3. Agent detail with event tabs and raw telemetry
4. Enrollment flow with install commands visible

Use a desktop viewport first. Capture dark theme by default, with one optional light-theme screenshot only if it adds clarity.
