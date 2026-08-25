import React from 'react'
const TOK={card:'#1e293b',border:'#334155',text:'#e2e8f0',muted:'#94a3b8'}
const CHECKS=[
{id:'01',label:'01 Version',spec:'RFC 8446 §4.2',isInfo:false},
{id:'02',label:'02 Cipher strong',spec:'IANA cipher strength',isInfo:false},
{id:'03',label:'03 KEX FS',spec:'ECDHE/DHE FS_flag',isInfo:false},
{id:'04',label:'04 Cert expiry',spec:'X.509 notAfter',isInfo:false},
{id:'05',label:'05 Self-signed',spec:'chain_valid',isInfo:false},
{id:'06',label:'06 Chain valid',spec:'chain_length/valid',isInfo:false},
{id:'07',label:'07 SAN match',spec:'SAN vs CN RFC7817',isInfo:false},
{id:'08',label:'08 Pubkey algo',spec:'RSA/ECDSA bits',isInfo:false},
{id:'09',label:'09 Sigalg weak',spec:'sha1WithRSA weak',isInfo:false},
{id:'10',label:'10 Keysize weak',spec:'rsa1024 <2048',isInfo:false},
{id:'11',label:'11 OCSP staple',spec:'ocsp_stapled_status',isInfo:false},
{id:'12',label:'12 STARTTLS',spec:'Bennett 220 upgrade M03',isInfo:false},
{id:'13',label:'13 Deprecated TLS',spec:'TLS1.0/1.1 RFC8996',isInfo:false},
{id:'14',label:'14 ALPN/JA4',spec:'ja4/ja4s rarity M22',isInfo:false},
{id:'15a',label:'15a Stripping',spec:'cleartext downgrade M18',isInfo:false},
{id:'15c',label:'15c Sweet32',spec:'3DES 64-bit CVE-2016-2183',isInfo:false},
{id:'16a',label:'16a MTA-STS',spec:'RFC8461 enforce',isInfo:false},
{id:'17',label:'17 DANE TLSA',spec:'RFC7672 Mankin',isInfo:false},
{id:'18',label:'18 CRL',spec:'crl_unknown_reason',isInfo:false},
{id:'19',label:'19 Cipher AEAD',spec:'is_aead Mozilla Intermediate',isInfo:false},
{id:'15b',label:'15b Injection',spec:'pre-TLS buffer injection GHSA-9j88',isInfo:true},
{id:'16b',label:'16b MX',spec:'MX MTA-STS/DANE offline 16b',isInfo:true},
{id:'16c',label:'16c 0-RTT',spec:'TLS1.3 early_data 0-RTT RFC8446 §8',isInfo:true},
]
function severityFor(flow,check){
if(check.isInfo)return{severity:'Info',evidence:'info-only offline'}
const f=flow.assessment?.findings||[]
const hit=f.find(x=>x.check===check.id||x.check===check.label)
if(hit)return{severity:hit.severity,evidence:hit.evidence||hit.spec||check.spec}
if(check.id==='01'||check.id==='13')return{severity:flow.tls?.is_deprecated?'Critical':'Low',evidence:flow.tls?.version||'unknown'}
if(check.id==='02')return{severity:flow.tls?.cipher_strength==='weak'?'High':flow.tls?.cipher_strength==='strong'?'Low':'Medium',evidence:flow.tls?.cipher_suite||'none'}
if(check.id==='03')return{severity:flow.tls?.fs_flag===false?'High':'Low',evidence:`kex=${flow.tls?.kex} fs=${flow.tls?.fs_flag}`}
if(check.id==='04')return{severity:flow.cert?.is_expired?'Critical':flow.cert?.days_to_expiry!=null&&flow.cert.days_to_expiry<30?'High':'Low',evidence:`days_to_expiry=${flow.cert?.days_to_expiry}`}
if(check.id==='05')return{severity:flow.cert?.is_self_signed?'Critical':'Low',evidence:String(flow.cert?.is_self_signed)}
if(check.id==='06')return{severity:flow.cert?.chain_valid===false?'High':'Low',evidence:`chain_len=${flow.cert?.chain_length}`}
if(check.id==='07')return{severity:flow.cert?.san_match===false?'High':'Low',evidence:`san_match=${flow.cert?.san_match}`}
if(check.id==='08')return{severity:flow.cert?.pubkey_bits!=null&&flow.cert.pubkey_bits<2048?'High':'Low',evidence:`${flow.cert?.pubkey_algo}/${flow.cert?.pubkey_bits}`}
if(check.id==='09')return{severity:flow.cert?.sigalg_weak?'High':'Low',evidence:flow.cert?.sigalg||'—'}
if(check.id==='10')return{severity:flow.cert?.keysize_weak?'High':'Low',evidence:String(flow.cert?.keysize_weak)}
if(check.id==='11')return{severity:flow.cert?.ocsp_stapled_status==='revoked'?'Critical':flow.cert?.ocsp_stapled_status==='unknown'?'Medium':'Low',evidence:flow.cert?.ocsp_stapled_status||'—'}
if(check.id==='12'||check.id==='15a')return{severity:flow.starttls_mode==='stripped'?'Critical':flow.starttls_mode==='upgrade'?'Low':'Medium',evidence:flow.starttls_mode}
if(check.id==='19')return{severity:flow.tls?.is_aead===false?'High':'Low',evidence:`aead=${flow.tls?.is_aead}`}
return{severity:flow.assessment?.risk_level||'Low',evidence:`risk_score=${flow.assessment?.risk_score}`}
}
function sevColor(sev,isInfo){
if(isInfo)return'#475569'
if(sev==='Critical')return'#dc2626'
if(sev==='High')return'#ea580c'
if(sev==='Medium')return'#ca8a04'
if(sev==='Low')return'#16a34a'
if(sev==='Info')return'#64748b'
return'#334155'
}
export default function ThreatMatrix({flows,onSelect,selectedId}){
if(!flows||flows.length===0)return<div style={{color:TOK.muted,padding:12}}>No flows — loading fixtures… — 0/20 REAL — fetch('/api/flows') polling</div>
return(
<div style={{background:TOK.card,border:`1px solid ${TOK.border}`,borderRadius:12,padding:12,overflowX:'auto'}}>
<div style={{fontSize:12,color:TOK.muted,textTransform:'uppercase',letterSpacing:1,marginBottom:8}}>ThreatMatrix — rows=flows cols=23 (20 scored +3 info-greyed 15b/16b/16c) — 20 scored color Critical25 High15 Medium7 Low3 +3 greyed info 15b injection,16b MX/MTA-STS,16c 0-RTT</div>
<table style={{borderCollapse:'collapse',fontSize:11,width:'100%'}}>
<thead><tr>
<th style={{textAlign:'left',padding:'6px 8px',color:TOK.muted,borderBottom:`1px solid ${TOK.border}`,minWidth:110}}>Flow</th>
{CHECKS.map(c=>(
<th key={c.id} title={c.spec} style={{padding:'6px 4px',color:c.isInfo?'#94a3b8':TOK.muted,borderBottom:`1px solid ${TOK.border}`,fontWeight:c.isInfo?400:600,opacity:c.isInfo?0.7:1,fontStyle:c.isInfo?'italic':'normal',minWidth:28,textAlign:'center'}}>{c.id}</th>
))}
</tr></thead>
<tbody>
{flows.map(flow=>(
<tr key={flow.flow_id} onClick={()=>onSelect&&onSelect(flow.flow_id)} style={{cursor:'pointer',background:selectedId===flow.flow_id?'#1e3a5f':'transparent',outline:selectedId===flow.flow_id?'1px solid #0ea5e9':'none'}}>
<td style={{padding:'6px 8px',borderBottom:`1px solid #1f2a3a`,fontWeight:600,color:TOK.text,whiteSpace:'nowrap'}}>{flow.flow_id}<span style={{color:TOK.muted,fontWeight:400,marginLeft:6}}>{flow.app_protocol}/{flow.tls?.version}</span></td>
{CHECKS.map(c=>{
const {severity,evidence}=severityFor(flow,c)
const weight=c.isInfo?'Info 1pt':severity==='Critical'?'25':severity==='High'?'15':severity==='Medium'?'7':severity==='Low'?'3':'0'
const bg=sevColor(severity,c.isInfo)
return<td key={c.id} style={{padding:3,borderBottom:`1px solid #1f2a3a`,textAlign:'center'}}>
<div title={`${c.spec} — ${evidence} — weight ${weight} (${severity}) — lineage manifest vs parsed — tshark 4-prefs parity vs reassembled/${flow.flow_id}.bin`} style={{width:22,height:22,borderRadius:4,background:bg,display:'inline-block',border:c.isInfo?'1px dashed #64748b':'none',opacity:c.isInfo?0.75:1}}/>
</td>
})}
</tr>))}
</tbody>
</table>
<div style={{fontSize:10,color:TOK.muted,marginTop:8,display:'flex',gap:12,flexWrap:'wrap'}}>
<span><span style={{display:'inline-block',width:10,height:10,background:'#dc2626',borderRadius:2,verticalAlign:'middle',marginRight:4}}/>Critical25</span>
<span><span style={{display:'inline-block',width:10,height:10,background:'#ea580c',borderRadius:2,verticalAlign:'middle',marginRight:4}}/>High15</span>
<span><span style={{display:'inline-block',width:10,height:10,background:'#ca8a04',borderRadius:2,verticalAlign:'middle',marginRight:4}}/>Medium7</span>
<span><span style={{display:'inline-block',width:10,height:10,background:'#16a34a',borderRadius:2,verticalAlign:'middle',marginRight:4}}/>Low3</span>
<span><span style={{display:'inline-block',width:10,height:10,background:'#475569',borderRadius:2,border:'1px dashed #64748b',verticalAlign:'middle',marginRight:4}}/>Info greyed (15b/16b/16c)</span>
<span style={{marginLeft:'auto'}}>hover cell for spec+evidence+weight class</span>
</div>
</div>
)
}
export {CHECKS}
