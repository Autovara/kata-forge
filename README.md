# kata-forge

Scaffolder for Kata subnet plugins. `kata-forge new --subnet <N> …` generates a `kata-sn<N>`
skeleton (templatized from `kata-sn126`); `kata-forge lane-config …` emits the `kata-bot` lane
config. It only writes a new dir + a reviewable config artifact — **never auto-commits or mutates
other repos**. Design & progress: `kata-forge-plan.md`.

## Status

- [x] **F1** — repo skeleton + CLI harness (spec validation)
- [ ] F2 — templates + generator
- [ ] F3 — validate by reproducing kata-sn126
- [ ] F4 — config artifact (KATA_LANES snippet + patch)

## Dev

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```
