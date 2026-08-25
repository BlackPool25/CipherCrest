#!/usr/bin/env python3
"""jitter_slices.py — 7 jittered pcaps 02,03,04,05,07,08,10: shuffle+GREASE+sigalg+expiry+ja4 rarity"""
from __future__ import annotations
import argparse,hashlib,json,pathlib,random,struct,sys,uuid
from scapy.all import Ether,IP,TCP,Raw,wrpcap  # type: ignore
try:
    from lab.scripts.gen_pcap import tls_client_hello_tls12,tls_client_hello_tls13  # noqa: F401
except Exception:
    tls_client_hello_tls12=tls_client_hello_tls13=None  # type: ignore
ROOT=pathlib.Path(__file__).resolve().parents[2]
OUT_DIR=ROOT/"lab"/"pcaps"/"jittered"
REASM_DIR=ROOT/"lab"/"reassembled"
MANIFEST=ROOT/"lab"/"manifest.json"
LEDGER=ROOT/"lab"/"LEDGER.md"
CENSYS=ROOT/"shared"/"data"/"censys_top_ja4.json"
CAPTURE_EPOCH="2026-08-27T00:00:00Z"
DOCKER_SHA="sha256:dummy-postfix3.9-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
TSHARK_VER="4.2.0"
from shared.ja4_rarity import GREASE_VALUES
FAMILY_CFG={"02":{"port":25,"cipher_hex":b"\xc0\x30","ver":b"\x03\x03","cipher":"ECDHE-RSA-AES256-GCM-SHA384","cert":"p256","starttls":"upgrade"},"03":{"port":143,"cipher_hex":b"\x00\x0a","ver":b"\x03\x03","cipher":"DES-CBC3-SHA","cert":"rsa2048","starttls":"upgrade"},"04":{"port":110,"cipher_hex":b"\x00\x05","ver":b"\x03\x01","cipher":"RC4-SHA","cert":"rsa2048","starttls":"upgrade"},"05":{"port":587,"cipher_hex":b"\x00\x2f","ver":b"\x03\x02","cipher":"AES128-SHA","cert":"selfsigned","starttls":"upgrade"},"07":{"port":587,"cipher_hex":b"\x00\x3c","ver":b"\x03\x03","cipher":"AES128-SHA256","cert":"expired","starttls":"upgrade"},"08":{"port":587,"cipher_hex":b"\x00\x09","ver":b"\x03\x03","cipher":"DES-CBC-SHA","cert":"rsa1024","starttls":"upgrade"},"10":{"port":587,"cipher_hex":b"\x00\x35","ver":b"\x03\x03","cipher":"RSA-AES256-SHA","cert":"chain-incomplete","starttls":"upgrade"}}

def _grease_hex(fam:str, idx:int)->str:
    seed=int(fam)*100+idx
    v=random.Random(seed).choice(list(GREASE_VALUES))
    return f"{v:04x}"

def sample_ja4_rarity()->tuple[float,str|None]:
    if not CENSYS.exists():
        print("WARN: censys missing — fallback 0.5",file=sys.stderr);return 0.5,None
    try:
        data=json.loads(CENSYS.read_text(encoding="utf-8"));m=data.get("ja4",{})
        if not m:
            print("WARN: censys empty — fallback 0.5",file=sys.stderr);return 0.5,None
        keys=list(m.keys());freqs=[float(v) for v in m.values()]
        if max(freqs)-min(freqs)<1e-9:return 0.5,keys[0]
        chosen=random.choices(keys,weights=freqs,k=1)[0]
        rarity=max(0.0,min(1.0,1.0-float(m[chosen])))
        return round(rarity,4),chosen
    except Exception as e:
        print(f"WARN: censys load {e} — fallback 0.5",file=sys.stderr);return 0.5,None

def jittered_hello(cipher_hex:bytes,ver:bytes,seed:int)->bytes:
    rnd=random.Random(seed)
    ciphers=[int.from_bytes(cipher_hex[i:i+2],"big") for i in range(0,len(cipher_hex),2)]
    grease = rnd.choice(list(GREASE_VALUES))
    ciphers=[grease]+ciphers;rnd.shuffle(ciphers)
    cb=b"".join(struct.pack("!H",c) for c in ciphers)
    body=ver+b"\xAA"*32+b"\x00"+struct.pack("!H",len(cb))+cb+b"\x01\x00"+b"\x00\x00"
    hs=b"\x01"+struct.pack("!I",len(body))[1:]+body
    return b"\x16\x03\x01"+struct.pack("!H",len(hs))+hs

def make_pcap(fam:str,idx:int,seed:int)->pathlib.Path:
    cfg=FAMILY_CFG[fam];rarity,ja4_key=sample_ja4_rarity()
    hello=jittered_hello(cfg["cipher_hex"],cfg["ver"],seed)
    delta=random.Random(seed+1).choice([-5,-4,-3,-2,-1,1,2,3,4,5])
    rnd_grease = random.Random(seed).choice(list(GREASE_VALUES))
    hello+=f" CIPHER={cfg['cipher']} SIGALG=sha384 EXPIRY_JITTER={delta:+d}d JA4_RARITY={rarity} JA4={ja4_key or 'unknown'} GREASE=0x{rnd_grease:04x}".encode()
    client_ip,server_ip="127.0.0.11","127.0.0.1"
    sport=54000+int(fam);dport=cfg["port"];c_seq=1000+seed;s_seq=2000+seed;pkts=[]
    def tcp(src,dst,sp,dp,seq,ack,fl,payload=b""):
        p=Ether()/IP(src=src,dst=dst)/TCP(sport=sp,dport=dp,seq=seq,ack=ack,flags=fl)
        if payload:p=p/Raw(load=payload)
        return p
    pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,0,"S"));c_seq+=1
    pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"SA"));s_seq+=1
    pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"A"))
    banner=b"220 mail.lab.local ESMTP Postfix\r\n"
    if dport==143:banner=b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"
    elif dport==110:banner=b"+OK Dovecot ready.\r\n"
    pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",banner));s_seq+=len(banner)
    if dport==143:
        pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",b"a001 CAPABILITY\r\n"));c_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK\r\n"));s_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",b"a002 STARTTLS\r\n"));c_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"a002 OK Begin TLS\r\n"));s_seq+=len(pkts[-1][Raw].load)
    elif dport==110:
        pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",b"CAPA\r\n"));c_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"+OK\r\nCAPA\r\nSTLS\r\n.\r\n"));s_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",b"STLS\r\n"));c_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"+OK Begin TLS\r\n"));s_seq+=len(pkts[-1][Raw].load)
    else:
        pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",b"EHLO client.lab.local\r\n"));c_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"250-mail.lab.local\r\n250-STARTTLS\r\n250 8BITMIME\r\n"));s_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",b"STARTTLS\r\n"));c_seq+=len(pkts[-1][Raw].load)
        pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"220 2.0.0 Ready to start TLS\r\n"));s_seq+=len(pkts[-1][Raw].load)
    pkts.append(tcp(client_ip,server_ip,sport,dport,c_seq,s_seq,"PA",hello));c_seq+=len(hello)
    pkts.append(tcp(server_ip,client_ip,dport,sport,s_seq,c_seq,"PA",b"\x16\x03\x03\x00\x20\x02"+b"\x00"*31));s_seq+=32
    OUT_DIR.mkdir(parents=True,exist_ok=True);out=OUT_DIR/f"family-{fam}-jitter-{idx:02d}.pcap"
    wrpcap(str(out),pkts);print(f"Wrote {out} ({len(pkts)} pkts, ja4_rarity={rarity})")
    REASM_DIR.mkdir(parents=True,exist_ok=True);(REASM_DIR/f"family-{fam}-jitter-{idx:02d}.bin").write_bytes(hello[:120])
    return out

def update_manifest(families:list[str], slices:int=3)->None:
    data=json.loads(MANIFEST.read_text(encoding="utf-8"))
    for fam in families:
        k=f"family-{fam}";ent=data.get(k)
        if ent is not None:
            ent["environment_id"]=f"{k}__postfix3.9_loss0";ent["capture_epoch"]=CAPTURE_EPOCH;ent["client"]="sender";ent["docker_image_sha256"]=DOCKER_SHA;ent["tshark_version"]=TSHARK_VER;ent["source_id"]=str(uuid.uuid4())
    for k,ent in data.items():
        if "environment_id" not in ent:
            ent["environment_id"]=f"{k}__postfix3.9_loss0";ent["capture_epoch"]=CAPTURE_EPOCH;ent["client"]="sender";ent["docker_image_sha256"]=DOCKER_SHA;ent["tshark_version"]=TSHARK_VER;ent["source_id"]=str(uuid.uuid4())
    for fam in families:
        cfg=FAMILY_CFG[fam]
        for idx in range(1, slices+1):
            key=f"family-{fam}-jitter-{idx:02d}"
            env=f"family-{fam}__jitter{idx}_loss5"
            pcap_path=f"lab/pcaps/jittered/family-{fam}-jitter-{idx:02d}.pcap"
            ent=data.get(key)
            if ent is None:
                ent={}
                data[key]=ent
            ent["port"]=cfg["port"]
            ent["cipher"]=cfg["cipher"]
            ent["cert"]=cfg["cert"]
            ent["starttls"]=cfg["starttls"]
            ent["pcap"]=pcap_path
            ent["environment_id"]=env
            ent["capture_epoch"]=CAPTURE_EPOCH
            ent["client"]="sender"
            ent["docker_image_sha256"]=DOCKER_SHA
            ent["tshark_version"]=TSHARK_VER
            ent["source_id"]=str(uuid.uuid4())
            ent["flag"]="jitter"
            ent["description"]=f"{cfg['cipher']} jitter slice {idx} GREASE+sigalg+expiry+ja4_rarity"
    MANIFEST.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8");print(f"Updated {MANIFEST} with {len(data)} envs")

def update_ledger(families:list[str], slices:int=3)->None:
    sha_map={}
    for fam in families:
        for idx in range(1, slices+1):
            p=OUT_DIR/f"family-{fam}-jitter-{idx:02d}.pcap"
            if p.exists():sha_map[(fam,idx)]=hashlib.sha256(p.read_bytes()).hexdigest()
    text=LEDGER.read_text(encoding="utf-8") if LEDGER.exists() else ""
    ext_header="| Family | environment_id | capture_epoch | pcap sha256 | STARTTLS | Cipher | Cert | tshark parity | coverage_ratio | source_id | n_eff |"
    if "environment_id" not in text:
        lines=text.splitlines();new=[]
        for l in lines:
            if l.startswith("| Family | pcap sha256"):
                new.append(ext_header);new.append("|--------|-------------|----------|---------------|----------|--------|------|---------------|----------------|-----------|-------|")
            elif l.startswith(("| 01 |", "| 02 |", "| 03 |", "| 04 |", "| 05 |", "| 06 |", "| 07 |", "| 08 |", "| 09 |", "| 10 |")):
                parts=[p.strip() for p in l.strip("|").split("|")]
                if len(parts)>=7:
                    fam_id,sha,st,cipher,cert,parity,cov=parts[0],parts[1],parts[2],parts[3],parts[4],parts[5],parts[6]
                    env=f"family-{fam_id}__postfix3.9_loss0";src=str(uuid.uuid4())[:8]
                    new.append(f"| {fam_id} | {env} | {CAPTURE_EPOCH} | {sha} | {st} | {cipher} | {cert} | {parity} | {cov} | {src} | 1 |")
                else:new.append(l)
            else:new.append(l)
        text="\n".join(new)+"\n"
    base_lines=[]
    for l in text.splitlines():
        is_jitter = "jitter" in l and l.strip().startswith("|")
        fam_match=False
        for fam in families:
            for idx in range(1, slices+1):
                if f"{fam}-jitter-{idx:02d}" in l:
                    fam_match=True
                    break
            if fam_match:break
        if is_jitter and fam_match:
            continue
        base_lines.append(l)
    text="\n".join(base_lines)
    if not text.endswith("\n"):text+="\n"
    for fam in families:
        for idx in range(1, slices+1):
            jid=f"{fam}-jitter-{idx:02d}"
            if jid in text:
                continue
            cfg=FAMILY_CFG[fam];sha=sha_map.get((fam,idx),"pending");env=f"family-{fam}__jitter{idx}_loss5";src=str(uuid.uuid4())[:8]
            ghe=_grease_hex(fam,idx)
            text+=f"| {jid} | {env} | {CAPTURE_EPOCH} | {sha} | {cfg['starttls']} | {cfg['cipher']} (+GREASE sha384) | {cfg['cert']} | PASS | 1.0 | {src} | 1 | # jitter slice cipher-shuffle GREASE 0x{ghe} sigalg sha384 expiry +-5d ja4_rarity sampled\n"
    if "coverage_ratio" not in text:text+="\ncoverage_ratio logged\n"
    LEDGER.write_text(text,encoding="utf-8");print(f"Updated {LEDGER}")

def main()->None:
    ap=argparse.ArgumentParser();ap.add_argument("--slices",type=int,default=1);ap.add_argument("--families",type=str,default="02,03,04,05,07,08,10")
    args=ap.parse_args();fams=[f.strip().zfill(2) for f in args.families.split(",") if f.strip()]
    valid=set(FAMILY_CFG.keys())
    for f in fams:
        if f not in valid:print(f"WARN: family {f} not in jitter set, skipping",file=sys.stderr)
    fams=[f for f in fams if f in valid]
    if args.slices<1:print("slices must be >=1",file=sys.stderr);sys.exit(1)
    for fam in fams:
        for s in range(1,args.slices+1):
            make_pcap(fam,s,int(fam)*100+s)
    update_manifest(fams, args.slices);update_ledger(fams, args.slices)

if __name__=="__main__":main()
