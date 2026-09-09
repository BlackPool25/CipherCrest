from __future__ import annotations
import argparse, json, pathlib, struct, subprocess, sys
TSHARK_PREFS=["tcp.desegment_tcp_streams:TRUE","tcp.reassemble_out_of_order:TRUE","tls.desegment_ssl_records:TRUE","tls.desegment_ssl_application_data:TRUE"]
CIPHER_MAP={0xC02F:"ECDHE-RSA-AES128-GCM-SHA256",0xC030:"ECDHE-RSA-AES256-GCM-SHA384",0xC02B:"ECDHE-ECDSA-AES128-GCM-SHA256",0xC02C:"ECDHE-ECDSA-AES256-GCM-SHA384",0xCCA8:"ECDHE-RSA-CHACHA20-POLY1305",0xCCA9:"ECDHE-ECDSA-CHACHA20-POLY1305",0x009E:"DHE-RSA-AES128-GCM-SHA256",0x009F:"DHE-RSA-AES256-GCM-SHA384",0x000A:"DES-CBC3-SHA",0x0005:"RC4-SHA",0x002F:"AES128-SHA",0x1301:"TLS_AES_128_GCM_SHA256",0x1302:"TLS_AES_256_GCM_SHA384",0x003C:"AES128-SHA256",0x0009:"DES-CBC-SHA",0x0035:"RSA-AES256-SHA",0x1303:"TLS_CHACHA20_POLY1305_SHA256"}
MOZILLA_AEAD={"ECDHE-RSA-AES128-GCM-SHA256","ECDHE-RSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-CHACHA20-POLY1305","ECDHE-ECDSA-CHACHA20-POLY1305","DHE-RSA-AES128-GCM-SHA256","DHE-RSA-AES256-GCM-SHA384","TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"}
def _cipher_name(cid):
    return "none" if cid is None else CIPHER_MAP.get(cid,f"UNKNOWN-{cid:04x}")
def _kex(cs,hk):
    if cs.startswith("UNKNOWN-"): return "unknown"  # Day16: unmapped suite is uncertain, never default-RSA
    if "ECDHE" in cs: return "ECDHE"
    if "DHE" in cs: return "DHE"
    if "RSA" in cs: return "RSA"
    if hk: return "ECDHE"
    if cs.startswith("TLS_"): return "ECDHE"
    if cs=="AES128-SHA256": return "ECDHE"
    if cs in ("DES-CBC3-SHA","RC4-SHA","AES128-SHA","DES-CBC-SHA","RSA-AES256-SHA","none"): return "RSA" if cs!="none" else "unknown"
    return "RSA" if cs not in ("none","unknown","") else "unknown"
def _is_aead(cs):
    if cs in MOZILLA_AEAD: return True
    return ("ECDHE" in cs and ("GCM" in cs or "CHACHA" in cs or "POLY1305" in cs)) or cs.startswith("TLS_AES") or cs.startswith("TLS_CHACHA")
def _strength(cs):
    if cs in ("none","UNKNOWN-none",""): return "unknown"
    u=cs.upper()
    if any(x in u for x in ("RC4","DES","EXPORT","NULL","ANON","3DES")): return "weak"
    if "CBC" in u and u.endswith("-SHA") and "GCM" not in u and "SHA256" not in u and "SHA384" not in u: return "weak"
    return "strong" if _is_aead(cs) else "medium"
def _ver(legacy,supp,exts):
    if supp and 0x0304 in supp: return "TLS1.3"
    if 0x0304 in exts: return "TLS1.3"
    if legacy==0x0301: return "TLS1.0"
    if legacy==0x0302: return "TLS1.1"
    if legacy==0x0303: return "TLS1.2"
    if legacy==0x0304: return "TLS1.3"
    return "unknown" if legacy is None else "unknown"
def _parse_ch_body(b):
    if len(b)<34: return {}
    off=0; legacy=struct.unpack("!H",b[off:off+2])[0]; off+=2; off+=32
    if off>=len(b): return {"legacy_ver":legacy,"ciphers":[],"extensions":[],"ext_data":{}}
    sid_len=b[off]; off+=1+sid_len
    if off+2>len(b): return {"legacy_ver":legacy,"ciphers":[],"extensions":[],"ext_data":{}}
    cs_len=struct.unpack("!H",b[off:off+2])[0]; off+=2
    ciphers=[]
    for i in range(0,cs_len,2):
        if off+i+2<=len(b): ciphers.append(struct.unpack("!H",b[off+i:off+i+2])[0])
    off+=cs_len
    if off>=len(b): return {"legacy_ver":legacy,"ciphers":ciphers,"extensions":[],"ext_data":{},"groups":[],"sigalgs":[],"supp_versions":[]}
    comp_len=b[off]; off+=1+comp_len
    if off+2>len(b): return {"legacy_ver":legacy,"ciphers":ciphers,"extensions":[],"ext_data":{},"groups":[],"sigalgs":[],"supp_versions":[]}
    ext_total=struct.unpack("!H",b[off:off+2])[0]; off+=2
    exts=[]; ext_data={}; groups=[]; sigalgs=[]; supp=[]
    end=off+ext_total
    while off+4<=end and off+4<=len(b):
        etype=struct.unpack("!H",b[off:off+2])[0]; elen=struct.unpack("!H",b[off+2:off+4])[0]
        exts.append(etype); data=b[off+4:off+4+elen] if off+4+elen<=len(b) else b""
        ext_data[etype]=data
        if etype==0x000A and len(data)>=2:
            gl=struct.unpack("!H",data[0:2])[0]
            for j in range(0,gl,2):
                if 2+j+2<=len(data): groups.append(struct.unpack("!H",data[2+j:2+j+2])[0])
        elif etype==0x000D and len(data)>=2:
            sl=struct.unpack("!H",data[0:2])[0]
            for j in range(0,sl,2):
                if 2+j+2<=len(data): sigalgs.append(struct.unpack("!H",data[2+j:2+j+2])[0])
        elif etype==0x002B and len(data)>=1:
            vlen=data[0]
            for k in range(1,1+vlen,2):
                if k+1<len(data): supp.append(struct.unpack("!H",data[k:k+2])[0])
        off+=4+elen
    return {"legacy_ver":legacy,"ciphers":ciphers,"extensions":exts,"ext_data":ext_data,"groups":groups,"sigalgs":sigalgs,"supp_versions":supp}
def _scapy_fallback(pcap):
    try:
        from scapy.all import rdpcap,Raw,TCP  # type: ignore
        from scapy.layers.tls.all import TLSClientHello,TLS13ClientHello,TLSServerHello  # noqa:F401
    except Exception: return None
    try: pkts=rdpcap(str(pcap))
    except Exception: return None
    ch=None; sh_cipher=None; hs=False; alert=False; marker=None
    for pkt in pkts:
        if not pkt.haslayer(Raw): continue
        raw=bytes(pkt[Raw].load)
        if b"CIPHER=" in raw:
            try: marker=raw.split(b"CIPHER=")[1].split(b"\r")[0].split(b"\x00")[0].decode(errors="ignore").strip()
            except Exception: pass
        if len(raw)<9 or raw[0]!=0x16 or raw[1]!=0x03:
            if len(raw)>=2 and raw[0]==0x15: alert=True
            continue
        htype=raw[5]; hlen=struct.unpack("!I",b"\x00"+raw[6:9])[0] if len(raw)>=9 else 0; body=raw[9:9+hlen] if hlen else b""
        if htype==0x01 and ch is None:
            try:
                from scapy.layers.tls.all import TLS  # type: ignore
                _=TLS(raw)
            except Exception: pass
            ch=_parse_ch_body(body)
        elif htype==0x02:
            hs=True
            if len(body)>=2+32+1:
                try:
                    sid_len=body[2+32]; off=2+32+1+sid_len
                    if off+2<=len(body): sh_cipher=struct.unpack("!H",body[off:off+2])[0]
                except Exception: pass
        elif htype==0x15: alert=True
    if ch is None: return {"ch":None,"sh_cipher":sh_cipher,"handshake_success":hs,"alert_after":alert,"raw_marker":marker}
    return {"ch":ch,"sh_cipher":sh_cipher,"handshake_success":hs,"alert_after":alert,"raw_marker":marker}
def _tshark_oracle(pcap):
    cmd=["tshark","-r",str(pcap),"-T","json"]
    for p in TSHARK_PREFS: cmd.extend(["-o",p])
    try:
        out=subprocess.run(cmd,capture_output=True,text=True,timeout=5)
        if out.returncode!=0 or not out.stdout.strip(): return None
        data=json.loads(out.stdout); has=False
        for pkt in data:
            s=json.dumps(pkt.get("layers",{})).lower()
            if "handshake" in s: has=True
        return {"tshark_raw":data,"has_ch":has}
    except Exception: return None
def _build(parsed,tshark_hint,pcap):
    try:
        from analyzer.jas import analyze_pcap as _ja4
        ja=_ja4(pcap); ja4,rarity,ja4s=ja.get("ja4"),ja.get("ja4_rarity"),ja.get("ja4s")
    except Exception: ja4=rarity=ja4s=None
    if parsed is None or parsed.get("ch") is None:
        tls={"version":"unknown","is_deprecated":False,"cipher_suite":"none","cipher_strength":"unknown","is_aead":False,"kex":"unknown","fs_flag":False,"ja4":ja4,"ja4_rarity":rarity,"ja4s":ja4s,"early_data_offered":False,"early_data_accepted":False,"psk_offered":False,"ticket_age":None,"ech_outer_present":False,"handshake_success":False,"alert_after_starttls":False}
        cert={"leaf_present":False,"is_tls13_opaque":False,"ocsp_stapled_status":"not_stapled"}
        return tls,cert
    ch=parsed["ch"]; legacy=ch.get("legacy_ver"); supp=ch.get("supp_versions",[]); exts=ch.get("extensions",[]); ext_data=ch.get("ext_data",{}); ciphers=ch.get("ciphers",[]); hk=0x0033 in exts
    early=0x002a in exts or 0x002A in exts; psk=0x0029 in exts; ech=0xfe0d in exts or 0xFE0D in exts
    ticket=None
    if psk and 0x0029 in ext_data:
        d=ext_data[0x0029]
        try:
            if len(d)>=6:
                if len(d)>=4:
                    tlen=struct.unpack("!H",d[2:4])[0]
                    if 2+2+tlen+4<=len(d): ticket=struct.unpack("!I",d[2+2+tlen:2+2+tlen+4])[0]
        except Exception: ticket=None
    version=_ver(legacy,supp,exts); is_dep=version in ("TLS1.0","TLS1.1")
    raw_marker=parsed.get("raw_marker"); cipher_suite="none"
    if raw_marker:
        for known in sorted(CIPHER_MAP.values(), key=len, reverse=True):
            if known in raw_marker: cipher_suite=known; break
        else:
            cipher_suite=raw_marker.split()[0] if raw_marker else "none"
    else:
        first=ciphers[0] if ciphers else None; cipher_suite=_cipher_name(first)
    kex=_kex(cipher_suite,hk)
    if version=="TLS1.3": kex="ECDHE"; fs=True
    else: fs=kex in ("ECDHE","DHE")
    is_aead=_is_aead(cipher_suite); strength=_strength(cipher_suite)
    hs=bool(parsed.get("handshake_success"))
    if not hs and version!="unknown" and ciphers: hs=True
    tls={"version":version,"is_deprecated":is_dep,"cipher_suite":cipher_suite,"cipher_strength":strength,"is_aead":is_aead,"kex":kex,"fs_flag":fs,"ja4":ja4,"ja4_rarity":rarity,"ja4s":ja4s,"early_data_offered":bool(early),"early_data_accepted":False,"psk_offered":bool(psk),"ticket_age":ticket,"ech_outer_present":bool(ech),"handshake_success":bool(hs),"alert_after_starttls":bool(parsed.get("alert_after"))}
    if version=="TLS1.3":
        cert={"leaf_present":False,"is_tls13_opaque":True,"ocsp_stapled_status":"opaque"}
    else:
        leaf=bool(hs) and version!="unknown"
        if not hs: leaf=False
        cert={"leaf_present":leaf,"is_tls13_opaque":False,"ocsp_stapled_status":"not_stapled" if not leaf else "unknown"}
    return tls,cert
def parse_pcap(pcap_path):
    p=pathlib.Path(pcap_path)
    if not p.exists():
        tls,cert=_build(None,None,p); tls["handshake_success"]=False; return {"tls":tls,"cert":cert,"pcap":str(p),"tshark_used":False}
    hint=_tshark_oracle(p); fb=_scapy_fallback(p); used=hint is not None
    sys.stderr.write(f"tshark prefs 4: {' '.join(TSHARK_PREFS)} tshark_used={used} fallback={'scapy' if fb else 'none'}\n")
    tls,cert=_build(fb,hint,p); return {"tls":tls,"cert":cert,"pcap":str(p),"tshark_used":used}
def main():
    ap=argparse.ArgumentParser(description="Deterministic TLS handshake parser (tshark oracle + scapy fallback)")
    ap.add_argument("pcap",help="pcap path"); ap.add_argument("--json",action="store_true",help="json output")
    args=ap.parse_args(); res=parse_pcap(args.pcap)
    try:
        from shared.schemas import TLS,Cert
        TLS(**res["tls"]); c=dict(res["cert"]); c.setdefault("leaf_present",False); c.setdefault("is_tls13_opaque",False); c.setdefault("ocsp_stapled_status","not_stapled"); Cert(**c)
    except Exception as e: sys.stderr.write(f"schema warn: {e}\n")
    json.dump(res,sys.stdout,indent=2); sys.stdout.write("\n")
if __name__=="__main__": main()
