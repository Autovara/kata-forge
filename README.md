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

### S5 — trusted input + three-outcome decision

`kata-forge decide` is the **production** input path (`extract` stays permissive for offline
research and is not used for a build):

```bash
kata-forge decide --repo https://github.com/<owner>/<repo> --work-dir ./work --out ./out
kata-forge decide --subnet 60 --catalog /srv/kata-subnets/subnet-catalog.json --work-dir ./work --out ./out
```

- `--repo` accepts **only** `https://github.com/<owner>/<repo>`; SSH, `file:`, local paths, other
  hosts, user-info, queries and IP literals are `REFUSE / NEEDS-HUMAN`.
- `--subnet` resolves **only** through a versioned local catalog with exactly one match — never from
  the chain, a search result, or a repository name. The two flags are mutually exclusive.
- The fetch pins a full 40-character commit SHA, refuses submodules, and disables git hooks.
- Writes `integration-decision.json` for **every** outcome, including `REFUSE`. Exit 0 for
  VENDOR/CLONE, 2 for REFUSE.

## Dev

```bash
uv venv && uv pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```
