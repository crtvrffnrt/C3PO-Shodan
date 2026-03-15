# C3PO-shodan Style Guide

The HTML output should feel like a high-fidelity **Neon Attack Surface Console**: technical, futuristic, and high-contrast.

## Core Aesthetic (Neon Intel Alignment)

### Background & Atmospheric
- **Background:** Fixed deep space background (`#03030a` to `#050111`).
- **Atmosphere:** Radial bloom in corners (`rgba(255, 79, 248, 0.18)` and `rgba(76, 246, 255, 0.18)`) and a "dust film" procedural grain.

### Color Palette
- **Primary Accents:** Electric Cyan (`#4cf6ff`) for infrastructure and primary links.
- **Secondary Accents:** Signal Magenta (`#ff4ff8`) for evidence highlights.
- **Risk Indicators:**
  - **Critical/High:** Alert Red (`#ff4c68`)
  - **Medium:** Warning Amber (`#e8d66c`)
  - **Low/Healthy:** Pulse Green (`#5cff8d`)
- **Surfaces:** `rgba(3, 5, 12, 0.92)` panels with `backdrop-filter: blur(14px)`.

### Typography
- **UI & Labels:** `Space Grotesk, system-ui, -apple-system, sans-serif`
- **Evidence & Data:** `JetBrains Mono, ui-monospace, SFMono-Regular, monospace` (Crucial for IPs, Ports, and DNS artifacts).

## Component Guidelines

### Evidence Panels
Screenshots and telemetry must be presented as tactical evidence cards, not decorative thumbnails. Each panel should have a thin luminous border and a monospace metadata footer.

### Infrastructure Mapping
Use crisp separation between risk summaries, infrastructure grids, and technical evidence. Operator scanning speed is prioritized through precise spacing and high contrast.

## Dashboard Mood
The final report should feel like a live recon cockpit: precise, "alive," and modern. Avoid generic admin panel styling.

