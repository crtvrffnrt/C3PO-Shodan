# Validation Workflow

Purpose: validate inputs and environment before any collection starts.

Rules:

- Check required files, commands, and Shodan credentials before invoking the pipeline.
- Treat missing screenshots tooling as non-fatal when screenshot capture is optional.
- Keep validation strict for broken inputs and permissive for optional augmentation.
- Do not replace a failed artifact by truncating it and then parsing it as if it were valid JSON.
- Keep domain validation aligned with the shell entrypoint and reject malformed comma-separated targets early.
- Pair this file with [`SKILL.md`](/root/dev/c3po-shodan/docs/workflows/validation/SKILL.md) for implementation-focused checks.

Acceptance checks:

- A missing required file or missing Shodan key fails fast with a clear message.
- Optional screenshot tooling only downgrades capabilities, not the whole run.
- Fallback artifacts are either valid JSON or clearly skipped.
