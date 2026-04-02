# Maintenance Workflow

Purpose: keep the repo coherent as the shell, Python, and docs layers evolve.

Rules:

- Update shell scripts, Python modules, and docs together when a behavior contract changes.
- Keep the root guidance file short and delegate detail to workflow-specific docs.
- Review config keys against actual usage before adding or renaming settings.
- Prefer small, explicit changes over broad rewrites in the pipeline.
- Verify new docs still match the shipped CLI behavior.
- Pair this file with [`SKILL.md`](/root/dev/c3po-shodan/docs/workflows/maintenance/SKILL.md) for implementation-focused checks.

Acceptance checks:

- Documented defaults match the implementation.
- New config knobs are referenced consistently in all relevant layers.
- The repo stays navigable for future agents without extra tribal knowledge.
