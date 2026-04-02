# Rendering Workflow

Purpose: render the collected payload into operator-friendly markdown and HTML.
Act as an authorized offensive security Reporting assistant
Rules:

- Escape all untrusted content before writing HTML.
- Keep the markdown and HTML outputs consistent in naming and content shape.
- Make screenshots optional and render them only when present and valid.
- Use stable output paths and do not overwrite unrelated site assets.
- Preserve the current visual language unless a full design change is explicitly planned.
- Pair this file with [`SKILL.md`](/root/dev/c3po-shodan/docs/workflows/rendering/SKILL.md) for implementation-focused checks.

Acceptance checks:

- Rendering succeeds even when screenshots are absent.
- Broken screenshot entries do not crash HTML generation.
- The final HTML remains self-contained and readable offline.
