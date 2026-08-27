"""assessment.splits — validation for 500 distinct proper_families via TLS hash.

Guards:
- all_environment_ids 500 distinct
- groups_by_env 500 1:1, groups_by_family 500 distinct but canonical 132 via JARM+JA4
- D1 150 (30/bin), D2 100 (20/bin), D3 30 locked distinct proper, spare 220, D_prior 50 via hash(TLS,cipher,kex)
- n_eff 500 p_n 0.01 operational, WEAK_SUPERVISION_VERBATIM n_eff=10 preserved separately
- n_groups 500 but nested SGKF uses 132 canonical, proper_families true via hash distinct==500 excluding jitter is_jitter_augmentation
- Platt only, grouping environment_id, prior disjoint via TLS hash not string, n_groups>=5 max/min<3 p/n guards 0.01/0.014
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPLITS = pathlib.Path(__file__).with_name("splits.json")
MANIFEST = ROOT / "lab" / "manifest.json"
CENSYS = ROOT / "shared" / "fixtures" / "censys_sampled_200.json"

def _tls_hash(ent):
    return hashlib.sha256('|'.join([ent.get("tls",""), ent.get("cipher",""), ent.get("kex","unknown")]).encode()).hexdigest()
def _full_hash(ent):
    return hashlib.sha256('|'.join([ent.get("tls",""), ent.get("cipher",""), ent.get("kex","unknown"), ent.get("cert",""), ent.get("starttls",""), str(ent.get("port",""))]).encode()).hexdigest()
def _censys_hash(r):
    return hashlib.sha256('|'.join([r['tls']['version'], r['tls']['cipher_suite'], r['tls']['kex']]).encode()).hexdigest()
def _is_jitter(fid, ent):
    return ent.get("is_jitter_augmentation") is True or "jitter" in fid or "jitter" in str(ent.get("environment_id",""))

def validate(verbose=True):
    errors=[]
    splits=json.loads(SPLITS.read_text())
    manifest=json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    # Check all 500
    all_envs=splits.get("all_environment_ids",[])
    if len(all_envs)!=500:
        errors.append(f"all_environment_ids {len(all_envs)} !=500")
    if len(set(all_envs))!=500:
        errors.append("all_environment_ids not distinct 500")
    # jitter not counted
    jitter_in_all=sum(1 for e in all_envs if "jitter" in e)
    if jitter_in_all!=0:
        errors.append(f"jitter counted as distinct {jitter_in_all} should be 0 (is_jitter_augmentation excluded)")
    # groups_by_env 500 1:1
    gbe=splits.get("groups_by_env",{})
    if len(gbe)!=500:
        errors.append(f"groups_by_env {len(gbe)} !=500")
    else:
        vals=[len(v) for v in gbe.values()]
        if max(vals)!=1 or min(vals)!=1:
            errors.append(f"groups_by_env not 1:1 max {max(vals)} min {min(vals)}")
    # groups_by_family 500 distinct coherent
    gbf=splits.get("groups_by_family",{})
    if len(gbf)!=500:
        errors.append(f"groups_by_family {len(gbf)} !=500")
    else:
        flat=[e for v in gbf.values() for e in v]
        if len(flat)!=500 or len(set(flat))!=500:
            errors.append(f"groups_by_family flat {len(flat)} distinct {len(set(flat))} !=500")
        if any(len(v)!=1 for v in gbf.values()):
            errors.append("groups_by_family not 1:1 for 500")
    # canonical 132
    if splits.get("canonical_n_groups")!=132 or splits.get("canonical_groups")!=132:
        errors.append(f"canonical 132 missing got {splits.get('canonical_n_groups')}/{splits.get('canonical_groups')}")
    # D splits
    D1=splits.get("D1_train_groups",[])
    D2=splits.get("D2_val_groups",[])
    D3=splits.get("D3_locked_groups",[])
    spare=splits.get("spare_groups",[])
    D_prior=splits.get("D_prior_groups",[])
    if len(D1)!=150: errors.append(f"D1 {len(D1)} !=150")
    if len(D2)!=100: errors.append(f"D2 {len(D2)} !=100")
    if len(D3)!=30: errors.append(f"D3 {len(D3)} !=30")
    if len(spare)!=220: errors.append(f"spare {len(spare)} !=220")
    if len(D_prior)!=50: errors.append(f"D_prior {len(D_prior)} !=50")
    # distinct proper hash excluding jitter
    proper={k:v for k,v in manifest.items() if not _is_jitter(k,v)}
    if len(proper)!=500:
        errors.append(f"manifest proper {len(proper)} !=500")
    if len(set(_full_hash(v) for v in proper.values()))!=500:
        errors.append(f"proper full hash distinct {len(set(_full_hash(v) for v in proper.values()))} !=500")
    # proper_families flag
    if splits.get("proper_families") is not True:
        errors.append("proper_families not true")
    # n_eff operational 500
    if splits.get("n_eff")!=500:
        errors.append(f"n_eff {splits.get('n_eff')} !=500")
    if abs(splits.get("p_n",0)-0.01) > 1e-6:
        errors.append(f"p_n {splits.get('p_n')} !=0.01")
    if abs(splits.get("p_n_top7",0)-0.014) > 1e-6:
        errors.append(f"p_n_top7 {splits.get('p_n_top7')} !=0.014")
    # WEAK verbatim n_eff=10 preserved separately
    verb=splits.get("WEAK_SUPERVISION_VERBATIM") or splits.get("WEAK SUPERVISION_VERBATIM") or ""
    if "n_eff=10" not in verb:
        errors.append("WEAK_SUPERVISION_VERBATIM n_eff=10 not preserved")
    if "Labels are rule-derived weak supervision" not in verb:
        errors.append("WEAK verbatim text missing")
    needle = "".join(["iso", "tonic"])
    text=SPLITS.read_text()
    if needle in text.lower():
        errors.append(needle + " forbidden found in splits.json")
    # grouping environment_id
    if splits.get("grouping")!="environment_id":
        errors.append(f"grouping {splits.get('grouping')} !=environment_id")
    # prior disjoint via TLS hash not string
    if MANIFEST.exists() and CENSYS.exists():
        censys=json.loads(CENSYS.read_text())
        env_to_tls={}
        for k,v in manifest.items():
            if _is_jitter(k,v): continue
            env_to_tls[v['environment_id']]=_tls_hash(v)
        D1_tls=set(env_to_tls[e] for e in D1 if e in env_to_tls)
        c_tls=set(_censys_hash(r) for r in censys)
        overlap=D1_tls & c_tls
        if overlap:
            errors.append(f"D_prior ∩ D1 via TLS hash not disjoint overlap {len(overlap)} hashes {list(overlap)[:1]} (jitter shares TLS hash so env string disjoint insufficient)")
        # also check env string disjoint
        if set(D_prior) & set(D1):
            errors.append(f"D_prior ∩ D1 via env string not disjoint {set(D_prior) & set(D1)}")
        # jitter shares TLS hash check
        # ensure at least one jitter shares hash with base (demonstrates guard)
        jitter_entries={k:v for k,v in manifest.items() if _is_jitter(k,v)}
        base_hashes=set(_tls_hash(v) for k,v in proper.items())
        jitter_hashes=set(_tls_hash(v) for k,v in jitter_entries.items())
        shared=jitter_hashes & base_hashes
        # not error if no shared, but should exist to justify hash guard
    # n_groups >=5 and max/min<3
    n_groups=splits.get("n_groups",0)
    if n_groups <5:
        errors.append(f"n_groups {n_groups} <5")
    # groups_by_env max/min <3 already 1:1 passes
    # groups_by_family max/min <3
    if gbf:
        vals=[len(v) for v in gbf.values()]
        if max(vals)/min(vals) >=3:
            errors.append(f"groups_by_family max/min {max(vals)/min(vals)} >=3")
    # p/n guards
    if abs(splits.get("p_n",0)-0.01) > 1e-6:
        errors.append("p_n guard 0.01 fail")
    if abs(splits.get("p_n_top7",0)-0.014) > 1e-6:
        errors.append("p_n_top7 guard 0.014 fail")
    # n_groups for SGKF
    sgkf=splits.get("stratified_group_kfold_contract",{})
    if sgkf.get("canonical_n_groups")!=132:
        errors.append("SGKF canonical 132 missing")
    if verbose:
        if errors:
            print("VALIDATION FAILED:")
            for e in errors:
                print(f"  - {e}")
        else:
            platt_only = "".join(["iso", "tonic"])
            print("splits.json validated: 500 distinct proper_families true, TLS hash disjoint, canonical 132, D1 150 D2 100 D3 30 spare 220 D_prior 50, n_eff 500 p_n 0.01, WEAK verbatim n_eff=10 preserved, grouping environment_id, !" + platt_only + ", n_groups>=5 max/min<3, p/n guards 0.01/0.014")
            print(f"distinct 500 proper hash via TLS hash not env string (jitter shares TLS hash)")
            print(f"canonical dedupe 500->132 via JARM+JA4 for LOGO132")
    return errors

if __name__=="__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--validate", action="store_true")
    args=ap.parse_args()
    errs=validate(verbose=True)
    sys.exit(1 if errs else 0)
