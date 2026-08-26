# Large Files & Storage Strategy — SecureMailScope

**Audit date:** 2026-08-26 · **Fixed:** `b9d18b4` `git rm --cached -r wheelhouse dashboard/dist` (HEAD clean 0 tracked, 345 M pack retains history until `filter-repo`) · **Current models:** 276 K tracked < 5 M threshold → keep in git, wheelhouse air-gap USB never LFS · **Decision matrix below**

> One-command turn-up: `bash scripts/turnup.sh` (or `--check` dry-run). See [Quick Turn-Up](#quick-turn-up-one-script-turns-up-modules--frontend) and `scripts/turnup.sh`.

---

## 1. GitHub limits — why large files need a decision

| Limit | Value | Source |
|-------|-------|--------|
| Hard block per file | **100 MB** — push rejected | [About large files on GitHub](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github) |
| Warn per file | **50 MB** — warning on push | same page |
| Recommended LFS threshold | **> 5 MB** use LFS | [Git LFS](https://git-lfs.github.com/) + GitHub docs “managing large files” |
| Git LFS free quota (GitHub) | **1 GB storage + 1 GB/month bandwidth** (paid beyond) | [About Git LFS](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-git-large-file-storage) / [Billing for Git LFS](https://docs.github.com/en/billing/managing-billing-for-git-large-file-storage) |
| Release asset per file | **2 GB** per asset, unlimited assets per release, free, versioned by tag | [About releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) |
| Git LFS pointer | Small text pointer in git, blob in LFS server, `git lfs pull` required on clone | [git-lfs.github.com](https://git-lfs.github.com/) |

**Takeaway:** Committing 345 M wheelhouse directly broke the 100 MB hard limit (push failed: `191M xgboost +57M llvmlite` in history `1647199` via `git add -f` despite `.gitignore`). Fixed forward via `b9d18b4`. Future `torch 180M` / `MicroAE 27-8-1 ~50M` would also breach 50–100 MB.

---

## 2. Research table — 4 options + wheelhouse special case

| # | Option | How it stores | Limits / cost | Pros | Cons | When to use for SecureMailScope |
|---|--------|---------------|---------------|------|------|----------------------------------|
| 1 | **Git LFS** | Commit small pointer; blob on `lfs.github.com`; `git lfs pull` on clone | Bypass 100 MB (LFS blob up to 2 GB per file, but quota 1 GB free, bandwidth 1 GB/mo, $5 /50 GB) | Versioned in git (pointer → checkout pins exact model), `actions/checkout@v4` with `lfs:true` fetches automatically, works for many small/medium models, diff is pointer | Quota & cost beyond 1 GB free; every `clone` pays bandwidth; needs `git lfs` installed; offline air-gap clone fails without internet | Future `models/*.pkl >5M` **if team has budget** (e.g. MicroAE 50 M → ~50 M of 1 GB quota). Prepare `.gitattributes` lines (commented) to uncomment. |
| 2 | **GitHub Releases assets** | File attached to a git tag (`gh release upload v0.7.0 models/*.pkl`); *not* in git clone; fetched by `scripts/download_models.sh` via `curl -L https://github.com/<org>/<repo>/releases/download/<tag>/<file>` | 2 GB per asset, unlimited per release, **free**, no clone overhead, versioned by tag | Free, no quota, no LFS install, historic versions stay as releases, fast download, works offline after first fetch | Not in `git clone` (fresh clone must run download script); tag lifecycle must be maintained; no `git blame` on model | **Recommended for future 50–180 M torch/MicroAE** (keeps repo clone <50 M, model fetched on demand). `scripts/download_models.sh` placeholder ready. |
| 3 | **DVC + S3 / MinIO** | `dvc.yaml` tracks remote `s3://...` or `minio` with content-hash `.dvc` files in git | Unlimited, infra cost (S3/MinIO), self-hosted possible | Best for large datasets + pipelines, air-gap MinIO, `dvc pull` selective, DAG of data | Infra to run (S3/MinIO), team must run `dvc pull`, heavier toolchain | Datasets at scale (100 GB) — overkill for current 45-env / 276 K. Use if lab grows to GB PCAP corpora with MinIO air-gap. |
| 4 | **Hugging Face Hub** | Model repo (`huggingface.co/<org>/<model>`) via `hf_hub_download` | Large files via LFS under the hood, generous quota, versioned | Good for public ML models, `transformers` integration | External dependency, not private by default, needs HF token | Sharing `MicroAE` with community — not air-gap default. |
| — | **Wheelhouse (special)** | **Never in git nor LFS.** Local `wheelhouse/` 345 M on USB 32 GB air-gap, `.gitignore`, `pip install --no-index --find-links wheelhouse --only-binary=:all:`; CI rebuilds via `pip download -d wheelhouse -r requirements.txt` if missing | Local disk only, no git cost | Survives air-gap, no internet needed, no 100 MB breach, `! torch` lean verified `du -m wheelhouse <350` | Fresh clone lacks wheelhouse (CI falls back to `pip install -r requirements.txt`) | **Always** for `wheelhouse/` (32 wheels). Already fixed `b9d18b4` + `git ls-files | grep wheelhouse` → 0. |

> Citations: GitHub large files hard 100 MB / warn 50 MB and LFS 1 GB quota per [About large files](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github) and [About Git LFS/billing](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-git-large-file-storage); LFS 5 MB recommended threshold via [git-lfs.github.com](https://git-lfs.github.com/) docs; Releases 2 GB per asset per [About releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

---

## 3. Decision matrix — what this repo does now vs future

| Category | Path | Current size | Tracked? | LFS? | Decision now | Future |
|----------|------|-------------|----------|------|--------------|--------|
| models | `models/risk_clf.pkl` 124 K + `anomaly.pkl` 76 K + `anomaly_honest.pkl` 76 K = **276 K** | YES `git ls-files` 3 files | NO | **KEEP IN GIT** — below 5 M threshold, no LFS overhead, fast clone, 276 K < 1 M | If MicroAE `models/microae_27-8-1.pt` ~50 M or torch 180 M: **Releases** (recommended free) OR LFS (if budget). Uncomment `.gitattributes` lines + run `scripts/download_models.sh`. |
| pcaps | `lab/pcaps/*.pcap` 1 KB ×45 = ~45 K, `lab/reassembled/*.bin` 120 B ×35 = 4 K | YES | NO | **KEEP IN GIT** — tiny, reproducible offline | If jitter expands to GB, consider DVC+MinIO air-gap |
| eval | `eval/*.png` 42 K + 17 K + `bundle-stats.html` 502 K | YES (png), NO (dist) | NO | **KEEP IN GIT** (png) — <1 M | If eval grows to large corpora, Releases |
| wheelhouse | `wheelhouse/*.whl` 32 wheels = **345 M** (xgboost 191 M, llvmlite 57 M, scipy 34 M) | **NO — untracked `b9d18b4` HEAD 0** | **NO — NEVER LFS** | **LOCAL USB air-gap only** — `.gitignore:4 wheelhouse/`, `pip install --no-index --find-links wheelhouse` air-gap, CI fallbacks to `pip install -r requirements.txt` if missing | Same — never add |
| dashboard dist | `dashboard/dist/` 1.1 M | **NO — untracked `b9d18b4` HEAD 0** | NO | **BUILD ARTIFACT** — `npm run build` in CI, `npm --prefix dashboard run build` not in git | Same |
| .git | `du -sh .git` 345 M pack (history retains `1647199` blob until `filter-repo`), `git count-objects -vH` loose 0 pack 344 M | — | — | Forward fix done (HEAD clean); true shrink to <50 M requires `git filter-repo --path wheelhouse --invert-paths --path dashboard/dist --invert-paths` + `git gc --prune=now --aggressive` **with user approval** — not executed | Execute with approval when history rewrite window allows |

**Rationale:** GitHub recommends LFS only above ~5 M (and hard-requires it above 100 M). With current 276 K models, adding LFS would *increase* friction (extra `git lfs pull`, quota, offline clone fails) for zero benefit. Future 50 M+ model crosses the 50 MB warn and would be blocked at 100 MB → at that point pay the complexity and pick **Releases** (free, no quota, versioned by tag) over LFS (quota/bandwidth cost) unless team already pays for LFS.

---

## 4. How future large models are linked (ready now)

1. **Prepare** (already in repo): `.gitattributes` has commented LFS lines:
   ```gitattributes
   # models/**/*.pkl filter=lfs diff=lfs merge=lfs -text
   # lab/pcaps/**/*.pcap filter=lfs diff=lfs merge=lfs -text
   # eval/*.png filter=lfs diff=lfs merge=lfs -text
   # lab/reassembled/**/*.bin filter=lfs diff=lfs merge=lfs -text
   # wheelhouse/**  — DO NOT ADD (stay gitignored)
   # dashboard/dist/** — DO NOT ADD (build artifact)
   ```
   To activate LFS: `git lfs install && git lfs track "models/**/*.pkl"` then uncomment those lines.

2. **Releases path (recommended):** when `models/microae_27-8-1.pt` or `torch` wheel lands, run:
   ```bash
   gh release create v0.8.0-microae --title "MicroAE 27-8-1" --notes "50M model, see docs/LARGE_FILES.md"
   gh release upload v0.8.0-microae models/microae_27-8-1.pt
   # then
   bash scripts/download_models.sh   # curl -L https://github.com/<org>/<repo>/releases/download/v0.8.0-microae/microae_27-8-1.pt -o models/microae_27-8-1.pt
   # or: pip download for wheelhouse — never Releases nor LFS
   ```
   `scripts/download_models.sh` is the single retrieval entrypoint; `scripts/turnup.sh` calls it (see below) and verifies `sha256` if `models/*.sha256` present.

3. **CI:** `.github/workflows/ci.yml` has `actions/checkout@v4` with `lfs:true` + `if grep -q "filter=lfs" .gitattributes; then git lfs pull; ...` — no-op now, automatic when LFS activated. Wheelhouse never fetched via LFS (`pip install --no-index --find-links wheelhouse` air-gap, fallback `pip install -r requirements.txt`).

4. **Audit commands** (copy-paste):
   ```bash
   # audit largest blobs in history (wheelhouse still in pack until filter-repo)
   git rev-list --objects --all | while read sha path; do [ -n "$path" ] || continue; s=$(git cat-file -s $sha); echo "$s $path"; done | sort -nr | head -10
   git verify-pack -v .git/objects/pack/*.idx | sort -k5 -n | tail -20
   # HEAD tracked large files >100K should show 0 wheelhouse
   git ls-files | xargs -I{} du -b "{}" 2>/dev/null | awk '$1>100000' | sort -nr | head -20
   git ls-files | grep -E "^wheelhouse/|^dashboard/dist" || echo "HEAD clean: wheelhouse+dist untracked"
   git check-ignore -v wheelhouse/new.whl dashboard/dist/new.js
   du -m wheelhouse | tail -1  # 345 <350 local
   du -sh .git && git count-objects -vH
   grep -q "filter=lfs" .gitattributes && git lfs ls-files || echo "No LFS blobs yet (<1M)"
   ```

---

## 5. Quick turn-up — one script turns up modules + frontend

**Command:** `bash scripts/turnup.sh` — brings up **API + validator + assessment + dashboard** and checks model files, wheelhouse, frontend.

| Flag | Effect |
|------|--------|
| `bash scripts/turnup.sh` | Full up: checks Python 3.11, Node, wheelhouse `<350M` + `! torch`, models, tshark optional, builds frontend if needed, starts `uvicorn api.app:app --port 8000 &`, `npm --prefix dashboard run dev` (or `npx vite --port 5173`), waits, curls `POST /analyze` zip + `GET /flows`, logs to `logs/turnup_*.log` |
| `bash scripts/turnup.sh --check` | **Dry-run** — same checks, no servers started, exit 0 if all pass |
| `bash scripts/turnup.sh --down` | Stops API/dashboard started by turnup |
| `bash scripts/turnup.sh --port 8000 --frontend-port 5173` | Custom ports |

**What it checks (in order):**

1. `python3 --version` (prefers 3.11, allows 3.13 with warning), `node --version` (>=18), `tshark` optional — if missing uses scapy/offline reassembler fallback (graceful, logs `tshark not found — using offline reassembler parity 4 prefs`).
2. `wheelhouse/` — `du -m wheelhouse | tail -1` `<350`, `ls wheelhouse | wc -l` 32 wheels, `! ls wheelhouse/*.whl | grep -qi torch` lean; if missing → warning + CI fallback note `pip install -r requirements.txt`.
3. `models/risk_clf.pkl` 124 K + `anomaly.pkl` 76 K + `anomaly_honest.pkl` 76 K — if missing tries `scripts/download_models.sh` (Releases) then fallback `python -m assessment.risk_model --train` / `anomaly_model` retrain notice.
4. `dashboard/` — if `node_modules` missing runs `npm --prefix dashboard install`; if `dist` missing runs `npm --prefix dashboard run build` (Vite gzip `<3670016`).
5. Starts API + dashboard, waits for `http://localhost:8000/flows` and `http://localhost:5173`, then `curl -F pcap=@lab/pcaps/family-01.pcap http://localhost:8000/analyze` + `GET /flows` + `GET /report?format=json` sanity.

On **fresh clone** (no wheelhouse, no models via Releases yet): `scripts/turnup.sh --check` passes with warnings for wheelhouse absent but fails only if models cannot be fetched/trained — never crashes on missing `tshark`.

See `scripts/turnup.sh` header for full flow and `scripts/download_models.sh` for model retrieval ( Releases 2 GB per asset, free, versioned by tag ).

---

## 6. Wheelhouse air-gap policy

- `wheelhouse/` is **gitignored** (`.gitignore:4`) and **never LFS** (`.gitattributes` commented `# DO NOT ADD`). Keep local 32 GB USB.
- Install: `pip install --no-index --find-links wheelhouse --only-binary=:all: -r requirements.txt`
- Rebuild wheelhouse (CI or air-gap bundle refresh): `pip download --only-binary=:all: -d wheelhouse -r requirements.txt` then `du -m wheelhouse | tail -1` verify `<350` and `! grep torch`.
- CI `pip install --no-index --find-links wheelhouse` air-gap; if `wheelhouse/` missing (fresh clone) falls back to `pip install -r requirements.txt`.
- History rewrite to drop pack from 345 M → <50 M: `git filter-repo --path wheelhouse --invert-paths --path dashboard/dist --invert-paths` or BFG + `git gc --prune=now --aggressive` — **requires user approval**, not executed; forward fix `b9d18b4` already stops future bloat (`git ls-files 0`).

---

## 7. Verification checklist

- [ ] `cat docs/LARGE_FILES.md` — table with 4 options + citations, decision KEEP IN GIT 276 K, wheelhouse never LFS
- [ ] `bash scripts/turnup.sh --check` — models pass (or download/retrain fallback), wheelhouse `<350` or warning, frontend build check, tshark optional pass
- [ ] `bash scripts/turnup.sh` — API `POST /analyze` zip → 200 + `GET /flows` <50 ms, dashboard on `http://localhost:5173`
- [ ] `README.md` links to `docs/LARGE_FILES.md` and `scripts/turnup.sh` Quick Turn-Up section
- [ ] `git ls-files | grep -E "^wheelhouse/|^dashboard/dist" || echo "HEAD clean"` — 0
- [ ] `grep -q "filter=lfs" .gitattributes && git lfs ls-files || echo "No LFS blobs yet"` — No LFS (commented future)
- [ ] `pytest -q` still passes (wheelhouse 345 M <350, models <5 M, Vite gzip <3670016)
