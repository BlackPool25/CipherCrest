# Issues

## Git LFS audit — .git 346M bloat cause (2026-08-26)
- **Cause:** `.git 346M` = `.git/objects` loose 345M wheelhouse force-added via `git add -f` in 1647199 (32 wheels 345M, xgboost 191M dominant) despite `wheelhouse/` in `.gitignore:4`. Pack only 915K, loose dominates because `git gc` not yet run. `git ls-files --cached | grep wheelhouse` 34 tracked, `git check-ignore -v` shows ignored but forced. Dist 1.1M also force-added same commit despite `dashboard/dist/` ignored — 502K bundle-stats +494K recharts.
- **Not from pcaps/models:** pcaps 1KB×45=45K, models 276K, png 42K all <1M, not causing bloat. `git rev-list --objects --all | sort -nr` confirms wheelhouse top 10, pcaps absent from top 100. So user concern "commits massive due to model size" false for models/pcaps — models 124K not massive; actual bloat is wheelhouse air-gap 345M forced tracked.
- **Decision:** NO LFS for models/pcaps/png yet (<5M). Wheelhouse must stay gitignored air-gap USB NOT LFS. Dist should be ignored built in CI, not LFS. Prepare `.gitattributes` commented future LFS for MicroAE/torch >5M.
- **Mitigation (not executed):** `git filter-repo --path wheelhouse --invert-paths` or BFG then `git gc --prune=now --aggressive` would drop 345M loose → ~1M pack clone. Requires user approval history rewrite — audit only, documented in README + assessment/LEDGER.md.
- **CI/README:** Added `lfs: true` future-proof + conditional pull, README Git LFS & Large Files section with storage table + audit commands + cleanup recommendation.

