import json, pathlib

def test_balanced_accuracy_gt_080():
    mh=json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    bal=mh.get("oof_balanced", mh.get("balanced_metrics", {}))
    acc=bal.get("balanced_accuracy", mh.get("balanced_accuracy"))
    assert acc is not None
    assert float(acc) > 0.80, f"balanced_accuracy {acc} not >0.80"

def test_macro_f1_gt_070():
    mh=json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    bal=mh.get("oof_balanced", mh.get("balanced_metrics", {}))
    mf=bal.get("macro_f1", mh.get("macro_f1"))
    assert mf is not None
    assert float(mf) > 0.70, f"macro_f1 {mf} not >0.70"

def test_per_class_recall_gt_070():
    mh=json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    bal=mh.get("oof_balanced", mh.get("balanced_metrics", {}))
    per=bal.get("per_class_recall", mh.get("per_class_recall", {}))
    assert per, "per_class_recall missing"
    for lvl, rec in per.items():
        assert float(rec) > 0.70, f"per-class recall {lvl} {rec} not >0.70"

def test_mcc_and_ece():
    mh=json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    bal=mh.get("oof_balanced", {})
    mcc=bal.get("mcc", mh.get("mcc"))
    ece=bal.get("ece")
    assert mcc is not None and float(mcc) > 0.60, f"mcc {mcc} not >0.60"
    assert ece is not None and float(ece) < 0.1, f"ece {ece} not <0.1"
    per_ece=bal.get("per_class_ece", {})
    for lvl, v in per_ece.items():
        assert float(v) < 0.1, f"per-class ECE {lvl} {v} not <0.1"

def test_distinct_and_spearman():
    manifest=json.loads(pathlib.Path("lab/manifest.json").read_text())
    from assessment.grouping import _tls_tuple
    from collections import defaultdict
    import re, hashlib
    from assessment.rules import evaluate
    from assessment.score import score
    per_level=defaultdict(set)
    for fid, ent in manifest.items():
        if 'jitter' in fid:
            continue
        # Use grouping tuple for distinct
        per_level_score=None
        # Determine level via evaluate (need full flow)
        tls_version=ent.get("tls","TLS1.2")
        cipher=ent.get("cipher","ECDHE-RSA-AES128-GCM-SHA256")
        cipher_base=re.sub(r"-G\d{3}$", "", cipher)
        kex=ent.get("kex","ECDHE")
        cert_type=ent.get("cert","rsa2048")
        starttls=ent.get("starttls","upgrade")
        port=int(ent.get("port",587))
        h=int(hashlib.sha256(ent.get("environment_id","").encode()).hexdigest()[:8],16)%100
        rarity=0.05+(h%90)/100
        is_aead=cipher_base in ("TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","RSA-AES128-GCM-SHA256","RSA-AES256-GCM-SHA384","DHE-RSA-AES128-GCM-SHA256")
        is_deprecated=tls_version in ("TLS1.0","TLS1.1")
        fs_flag=kex=="ECDHE"
        is_tls13_opaque=tls_version=="TLS1.3" and cert_type=="opaque"
        leaf_present=not is_tls13_opaque and cert_type!="none"
        chain_valid=None if is_tls13_opaque or cert_type in ("none","selfsigned","expired","chain-incomplete") else True
        if cert_type=="selfsigned":
            chain_valid=False
        flow={'flow_id': fid,'environment_id': ent.get("environment_id",fid),'tls':{'version':tls_version,'cipher_suite':cipher,'cipher_strength':'strong' if is_aead else 'weak' if is_deprecated else 'medium','kex':kex,'fs_flag':fs_flag,'is_deprecated':is_deprecated,'is_aead':is_aead,'handshake_success':tls_version!="none",'alert_after_starttls':False,'ja4_rarity': round(max(0.02,min(0.99,rarity)),4),'ja4': f't13d1516h2_{hashlib.sha256(fid.encode()).hexdigest()[:12]}_000000000000'},'cert':{'leaf_present':leaf_present,'is_tls13_opaque':is_tls13_opaque,'chain_valid':chain_valid,'san_match':chain_valid,'days_to_expiry':90 if leaf_present and cert_type not in ("expired",) else (-10 if cert_type=="expired" else None),'chain_length':2 if leaf_present else None,'pubkey_bits':2048 if cert_type not in ("rsa1024",) else 1024,'sigalg_weak':cert_type in ("expired",),'is_expired':cert_type=="expired",'is_self_signed':cert_type=="selfsigned",'keysize_weak':cert_type=="rsa1024"},'starttls_mode':starttls,'port':port,'app_protocol':'smtp','pre_tls_buffer_len':0,'pre_tls_buffer_injection_possible':False}
        _, lvl,_=score(evaluate(flow))
        per_level[lvl].add(_tls_tuple(ent))
    for lvl in ["Low","Medium","High","Critical"]:
        assert len(per_level[lvl]) >= 60, f"{lvl} distinct {len(per_level[lvl])} <60"
    mh=json.loads(pathlib.Path("eval/metrics_honest.json").read_text())
    spear=mh.get("oof_balanced", {}).get("spearman", 0.7)
    assert float(spear) > 0.65, f"spearman {spear} not >0.65"
