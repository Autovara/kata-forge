# kata-forge

Scaffolder for Kata subnet plugins. `kata-forge new --subnet <N> …` generates a `kata-sn<N>`
skeleton (templatized from `kata-sn126`); `kata-forge lane-config …` emits the `kata-bot` lane
config. It only writes a new dir + a reviewable config artifact — **never auto-commits or mutates
other repos**. Design & progress: `kata-forge-plan.md`.

## Status

- [x] **F1** — repo skeleton + CLI harness (spec validation)
- [x] **F2** — templates + generator (`new` scaffolds a kata-sn<N> skeleton)
- [x] **F3** — validated by reproduction (generated skeleton installs + is discoverable)
- [x] **F4** — config artifact (`lane-config` emits KATA_LANES snippet + reviewable `.env` patch)

**M2 complete.** `kata-forge new` scaffolds an installable, discoverable kata-sn<N>; `kata-forge lane-config` emits the reviewable go-live config.

## Dev

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```
