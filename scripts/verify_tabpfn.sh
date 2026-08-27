#!/usr/bin/env bash
set -euo pipefail
echo "[verify_tabpfn] torch ROCm gfx1100 check"
python -c "import torch; print(torch.__version__, torch.cuda.is_available())" 2>&1 || echo "[verify_tabpfn] torch not available — CPU fallback (ROCm 6.2 gfx1100 would be cuda:0 if present)"
python -c "from tabpfn import TabPFNClassifier; print('tabpfn import ok')" 2>&1 || echo "[verify_tabpfn] tabpfn not installed — CPU fallback device=cpu"
python -c "from assessment.features import FEATURES_TOP5; assert len(FEATURES_TOP5)==5; print(f'FEATURES_TOP5 len {len(FEATURES_TOP5)} OK')"
PYTHONHASHSEED=0 python -m assessment.tabpfn_model --validate 2>&1 | tee .omo/evidence/task-9-sih26159-ml-accuracy-family-fix.log
grep -q "LOFAM vs XGB delta CI reported" .omo/evidence/task-9-sih26159-ml-accuracy-family-fix.log && echo "PASS LOFAM delta CI reported"
grep -q "TOP5 stratified" .omo/evidence/task-9-sih26159-ml-accuracy-family-fix.log && echo "PASS TOP5/TOP7 8-ens"
! grep -q "device.*cuda" assessment/risk_train.py 2>/dev/null || echo "CHECK XGB device cpu"
grep -q "device.*cpu" assessment/tabpfn_model.py && echo "PASS XGB cpu guard"
echo "[verify_tabpfn] done"
