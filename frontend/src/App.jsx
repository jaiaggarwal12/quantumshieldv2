import { useState, useEffect, useRef, useCallback } from "react";

// ── Design Tokens ─────────────────────────────────────────────────────────────
const RISK_COLOR = {
  QUANTUM_SAFE:  { bg:"#061a0f", border:"#00e676", text:"#00e676", badge:"QUANTUM SAFE",  glow:"#00e67640" },
  PQC_READY:     { bg:"#1a1a00", border:"#c6ff00", text:"#c6ff00", badge:"PQC READY",     glow:"#c6ff0040" },
  TRANSITIONING: { bg:"#1a0e00", border:"#ff9100", text:"#ffab40", badge:"TRANSITIONING", glow:"#ff910040" },
  VULNERABLE:    { bg:"#1a0000", border:"#ff1744", text:"#ff5252", badge:"VULNERABLE",    glow:"#ff174440" },
  UNKNOWN:       { bg:"#0a0a20", border:"#536dfe", text:"#8c9eff", badge:"UNKNOWN",       glow:"#536dfe40" },
};
const SEV_COLOR = { CRITICAL:"#ff1744", HIGH:"#ff5252", MEDIUM:"#ffab40", LOW:"#c6ff00", INFO:"#8c9eff" };

// ── Mock Data ─────────────────────────────────────────────────────────────────
const buildMock = (target,score,status,tlsVer,cipher,certType,certBits,kex,issues,positives,vulns,daysLeft) => ({
  target, port:443, status:"success", timestamp:new Date().toISOString(),
  tls_info:{ tls_version:tlsVer,cipher_suite:cipher,cipher_bits:256,cipher_grade:score>=75?"A":"B",
             key_exchange:kex,forward_secrecy:true,supported_tls_versions:["TLSv1.3","TLSv1.2"],
             cert_key_type:certType,cert_key_bits:certBits },
  certificate:{ key_type:certType,key_bits:certBits,subject:`CN=${target}`,issuer:"CN=Google Trust Services",
                not_after:new Date(Date.now()+daysLeft*86400000).toISOString(),days_until_expiry:daysLeft,
                total_validity_days:397,signature_algorithm:"SHA256",sans:[target,`www.${target}`],
                is_self_signed:false,pqc_cert:false,ct_sct_count:2,key_usage:{digital_signature:true},
                ocsp_urls:["http://ocsp.example.com"],policies:[],issues:[] },
  pqc_assessment:{ score,status,label:RISK_COLOR[status]?.badge,badge_color:RISK_COLOR[status]?.border,
                   issues,positives,parameters_checked:40 },
  cbom:{ cbom_version:"1.4",components:[
    {type:"protocol",name:"TLS",version:tlsVer,quantum_safe:false,supported_versions:["TLSv1.3","TLSv1.2"]},
    {type:"cipher-suite",name:cipher,bits:256,grade:score>=75?"A":"B",forward_secrecy:true,quantum_safe:false},
    {type:"key-exchange",name:kex,quantum_safe:kex.includes("ML-KEM")},
    {type:"certificate",name:`${certType}-${certBits}`,algorithm:"SHA256",quantum_safe:false,days_until_expiry:daysLeft,ct_sct_count:2},
  ]},
  vulnerabilities:vulns,
  dns:{ caa_present:true,dnssec_enabled:false,dns_resolves:true,
        ipv4_addresses:["142.250.80.46"],ipv6_addresses:["2607:f8b0:4004::200e"],
        issues:score<70?[{severity:"MEDIUM",issue:"No CAA DNS records",action:"Add CAA records"}]:[] },
  http_headers:{ hsts:{present:true,max_age:31536000,include_subdomains:true,preload:true},
                 csp:{present:score>60,value:"default-src 'self'"},
                 headers_found:{"Strict-Transport-Security":"max-age=31536000; includeSubDomains; preload"},
                 headers_missing:score<70?["X-Frame-Options","Permissions-Policy"]:[],
                 score:score>70?90:65,issues:[] },
});

const MOCK_DB = {
  "google.com":     buildMock("google.com",65,"PQC_READY","TLSv1.3","TLS_AES_256_GCM_SHA384","ECDSA",256,"X25519/P-256 ECDHE (Quantum-Vulnerable)",
    [{severity:"HIGH",issue:"ECDSA-256 certificate — fully broken by Shor's algorithm",action:"Migrate to ML-DSA-65 (FIPS 204)"},{severity:"MEDIUM",issue:"X25519 ECDHE key exchange — vulnerable to HNDL attacks",action:"Deploy ML-KEM-768 (FIPS 203)"}],
    ["TLS 1.3 in use","AES-256 symmetric encryption","Forward secrecy enabled"],
    [{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later threat active",action:"Deploy ML-KEM-768"}],48),
  "cloudflare.com": buildMock("cloudflare.com",72,"PQC_READY","TLSv1.3","TLS_AES_256_GCM_SHA384","ECDSA",256,"X25519+Kyber768 (Hybrid PQC)",
    [{severity:"HIGH",issue:"ECDSA-256 certificate — quantum-vulnerable signature",action:"Migrate to ML-DSA-65"}],
    ["TLS 1.3","Hybrid PQC key exchange (X25519+Kyber768)","AES-256-GCM","HSTS with preload"],
    [{name:"HNDL",cve:"N/A",severity:"HIGH",description:"Certificate still HNDL vulnerable",action:"Complete PQC migration"}],120),
  "example.com":    buildMock("example.com",32,"VULNERABLE","TLSv1.2","ECDHE-RSA-AES128-GCM-SHA256","RSA",2048,"ECDHE (Quantum-Vulnerable)",
    [{severity:"CRITICAL",issue:"RSA-2048 — fully broken by Shor's algorithm",action:"Replace with ML-DSA-65"},{severity:"HIGH",issue:"TLS 1.2 in use",action:"Enforce TLS 1.3"}],
    [],[{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Full PQC migration required"}],5),
  "rc4.badssl.com": buildMock("rc4.badssl.com",8,"VULNERABLE","TLSv1.2","RC4-SHA","RSA",2048,"RSA (Quantum-Vulnerable — no forward secrecy)",
    [{severity:"CRITICAL",issue:"RC4 cipher — broken by classical statistical attacks (RFC 7465)",action:"Disable RC4 immediately"},{severity:"CRITICAL",issue:"No forward secrecy",action:"Migrate to ECDHE or ML-KEM"}],
    [],[{name:"RC4_BIASES",cve:"CVE-2015-2808",severity:"CRITICAL",description:"RC4 statistical biases allow plaintext recovery",action:"Disable RC4"},{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Complete overhaul required"}],365),
  "3des.badssl.com":buildMock("3des.badssl.com",12,"VULNERABLE","TLSv1.2","DES-CBC3-SHA","RSA",2048,"RSA (Quantum-Vulnerable — no forward secrecy)",
    [{severity:"CRITICAL",issue:"3DES — SWEET32 birthday attack, Grover's ~40-bit quantum security",action:"Disable 3DES immediately"},{severity:"CRITICAL",issue:"No forward secrecy",action:"Switch to ECDHE or ML-KEM"}],
    [],[{name:"SWEET32",cve:"CVE-2016-2183",severity:"MEDIUM",description:"3DES birthday attack",action:"Disable 3DES"},{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Full PQC migration"}],365),
};

// ── Scan Function ─────────────────────────────────────────────────────────────
async function performScan(target, backendUrl, token) {
  const clean = target.replace(/^https?:\/\//,"").split("/")[0].trim();
  if (token && backendUrl) {
    try {
      const res = await fetch(`${backendUrl}/api/v1/scan/quick`, {
        method:"POST",
        headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body: JSON.stringify({target:clean,port:443}),
        signal: AbortSignal.timeout(25000),
      });
      if (res.ok) return await res.json();
    } catch(_) {}
  }
  // Demo fallback
  await new Promise(r=>setTimeout(r,1200+Math.random()*800));
  const mock = MOCK_DB[clean];
  if (mock) return {...mock, timestamp:new Date().toISOString()};
  const score = Math.floor(Math.random()*55)+20;
  const status = score>=65?"PQC_READY":score>=40?"TRANSITIONING":"VULNERABLE";
  return buildMock(clean,score,status,score>50?"TLSv1.3":"TLSv1.2","ECDHE-RSA-AES256-GCM-SHA384","RSA",2048,"ECDHE (Quantum-Vulnerable)",
    [{severity:"HIGH",issue:"RSA-2048 certificate — quantum-vulnerable",action:"Migrate to ML-DSA-65 (FIPS 204)"}],
    score>50?["TLS 1.3 in use"]:[],[{name:"HNDL",cve:"N/A",severity:"CRITICAL",description:"Harvest Now Decrypt Later",action:"Deploy ML-KEM-768"}],
    Math.floor(Math.random()*300)+30);
}

// ── Mini UI Components ────────────────────────────────────────────────────────
function ScoreRing({score,size=72}) {
  const r=size/2-7; const circ=2*Math.PI*r; const dash=(score/100)*circ;
  const color=score>=75?"#00e676":score>=55?"#c6ff00":score>=35?"#ff9100":"#ff1744";
  return (
    <svg width={size} height={size} style={{transform:"rotate(-90deg)"}}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1a1a2e" strokeWidth="7"/>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="7"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        style={{transition:"stroke-dasharray 1.2s ease",filter:`drop-shadow(0 0 5px ${color})`}}/>
      <text x={size/2} y={size/2} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={size>60?15:11} fontWeight="800"
        style={{transform:`rotate(90deg)`,transformOrigin:`${size/2}px ${size/2}px`,fontFamily:"monospace"}}>{score}</text>
    </svg>
  );
}
function Badge({status,small}) {
  const c=RISK_COLOR[status]||RISK_COLOR.UNKNOWN;
  return <span style={{background:c.bg,border:`1px solid ${c.border}`,color:c.text,
    padding:small?"2px 7px":"3px 10px",borderRadius:4,fontSize:small?10:11,fontWeight:700,
    letterSpacing:1,fontFamily:"monospace",boxShadow:`0 0 8px ${c.glow}`,whiteSpace:"nowrap"}}>{c.badge}</span>;
}
function SevBadge({sev}) {
  const c=SEV_COLOR[sev]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}44`,
    padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700,letterSpacing:1,whiteSpace:"nowrap"}}>{sev}</span>;
}
function GradeBadge({grade}) {
  const gc={A:"#00e676",B:"#c6ff00",C:"#ff9100",D:"#ff5252",F:"#ff1744"};
  const c=gc[grade]||"#888";
  return <span style={{background:`${c}22`,color:c,border:`1px solid ${c}`,
    padding:"2px 8px",borderRadius:4,fontSize:12,fontWeight:900,fontFamily:"monospace"}}>{grade}</span>;
}

// ── Login Screen ──────────────────────────────────────────────────────────────
function LoginScreen({backendUrl,onLogin}) {
  const [form,setForm]=useState({username:"",password:""});
  const [error,setError]=useState("");
  const [loading,setLoading]=useState(false);

  const doLogin = async () => {
    if(!form.username||!form.password){setError("Please enter username and password");return;}
    setLoading(true); setError("");
    const fd=new URLSearchParams();
    fd.append("username",form.username); fd.append("password",form.password);
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/login`,{method:"POST",body:fd,signal:AbortSignal.timeout(8000)});
      if(res.ok){
        const data=await res.json();
        localStorage.setItem("qs_token",data.access_token);
        localStorage.setItem("qs_user",JSON.stringify({username:data.username,role:data.role,email:data.email,id:data.user_id}));
        onLogin(data.access_token,{username:data.username,role:data.role,email:data.email,id:data.user_id});
      } else {
        const d=await res.json().catch(()=>({}));
        setError(d.detail||"Invalid credentials");
      }
    } catch(_) {
      // Backend offline — demo mode login
      localStorage.setItem("qs_token","demo");
      localStorage.setItem("qs_user",JSON.stringify({username:"demo",role:"Operator",email:"demo@demo.com",id:0}));
      onLogin("demo",{username:"demo",role:"Operator",email:"demo@demo.com",id:0});
    }
    setLoading(false);
  };

  const inp={width:"100%",background:"#0f0f25",border:"1px solid #2a2a4a",borderRadius:7,
    color:"#e0e0ff",fontFamily:"monospace",fontSize:13,padding:"11px 14px",outline:"none",
    boxSizing:"border-box",transition:"border-color 0.2s"};

  return (
    <div style={{background:"#05050e",minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"monospace",padding:20}}>
      <div style={{width:"100%",maxWidth:400}}>
        {/* Logo */}
        <div style={{textAlign:"center",marginBottom:36}}>
          <div style={{width:64,height:64,background:"linear-gradient(135deg,#7c3aed,#1d4ed8)",borderRadius:16,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:32,margin:"0 auto 14px",
            boxShadow:"0 0 40px #7c3aed60"}}>⚛</div>
          <div style={{color:"#e0e0ff",fontWeight:900,fontSize:22,letterSpacing:3}}>QUANTUMSHIELD</div>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginTop:4}}>PQC SCANNER v3.0 · NIST FIPS 203/204/205</div>
        </div>

        <div style={{background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:14,padding:"32px 32px 28px"}}>
          <div style={{color:"#8888aa",fontSize:11,letterSpacing:2,marginBottom:20,textAlign:"center"}}>SIGN IN TO CONTINUE</div>
          {error && (
            <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",
              padding:"10px 14px",borderRadius:7,marginBottom:16,fontSize:12}}>{error}</div>
          )}
          <div style={{marginBottom:14}}>
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:7}}>USERNAME</div>
            <input value={form.username} onChange={e=>setForm({...form,username:e.target.value})}
              onKeyDown={e=>e.key==="Enter"&&doLogin()} style={inp} placeholder="admin"/>
          </div>
          <div style={{marginBottom:22}}>
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:7}}>PASSWORD</div>
            <input type="password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}
              onKeyDown={e=>e.key==="Enter"&&doLogin()} style={inp} placeholder="••••••••••"/>
          </div>
          <button onClick={doLogin} disabled={loading} style={{
            width:"100%",padding:"13px",background:loading?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
            border:"none",borderRadius:8,color:"#fff",fontFamily:"monospace",fontSize:13,fontWeight:700,
            cursor:loading?"not-allowed":"pointer",letterSpacing:2,
            boxShadow:loading?"none":"0 0 24px #7c3aed50",transition:"all 0.3s"}}>
            {loading?"⏳ SIGNING IN...":"⚡ SIGN IN"}
          </button>
          <div style={{marginTop:20,padding:"14px",background:"#080818",borderRadius:8,border:"1px solid #1e1e3a"}}>
            <div style={{color:"#444466",fontSize:10,letterSpacing:1,marginBottom:8}}>DEMO CREDENTIALS</div>
            {[["admin","quantum2026","Admin"],["pnb","pnbsecure","Operator"],["auditor","audit2026","Checker"]].map(([u,p,r])=>(
              <div key={u} onClick={()=>{setForm({username:u,password:p});setError("");}}
                style={{display:"flex",justifyContent:"space-between",padding:"5px 8px",borderRadius:5,
                  cursor:"pointer",marginBottom:3,background:"#0a0a1e",border:"1px solid #1e1e3a"}}>
                <span style={{color:"#8888cc",fontSize:11,fontFamily:"monospace"}}>{u} / {p}</span>
                <span style={{color:r==="Admin"?"#a78bfa":r==="Operator"?"#60a5fa":"#34d399",fontSize:10,fontWeight:700}}>{r}</span>
              </div>
            ))}
            <div style={{color:"#333355",fontSize:10,marginTop:8,textAlign:"center"}}>Click a row to auto-fill · Backend offline = Demo Mode</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── History Panel ─────────────────────────────────────────────────────────────
function HistoryPanel({backendUrl,token,onLoadScan}) {
  const [history,setHistory]=useState([]);
  const [loading,setLoading]=useState(true);
  const [loadingId,setLoadingId]=useState(null);
  const [deletingId,setDeletingId]=useState(null);

  const fetchHistory=useCallback(async()=>{
    setLoading(true);
    try {
      const res=await fetch(`${backendUrl}/api/v1/history`,{headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) setHistory(await res.json());
    } catch(_){}
    setLoading(false);
  },[backendUrl,token]);

  useEffect(()=>{fetchHistory();},[fetchHistory]);

  const loadScan=async(id)=>{
    setLoadingId(id);
    try {
      const res=await fetch(`${backendUrl}/api/v1/history/${id}`,{headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok){const d=await res.json();onLoadScan(d);}
    } catch(_){}
    setLoadingId(null);
  };

  const deleteScan=async(id,e)=>{
    e.stopPropagation();
    setDeletingId(id);
    try {
      await fetch(`${backendUrl}/api/v1/history/${id}`,{method:"DELETE",headers:{"Authorization":`Bearer ${token}`}});
      setHistory(h=>h.filter(s=>s.id!==id));
    } catch(_){}
    setDeletingId(null);
  };

  if(loading) return <div style={{color:"#6666aa",padding:40,textAlign:"center",fontFamily:"monospace"}}>Loading history...</div>;

  return (
    <div style={{padding:"20px 24px",maxWidth:900,margin:"0 auto"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div>
          <div style={{color:"#e0e0ff",fontWeight:700,fontSize:16,fontFamily:"monospace"}}>📋 SCAN HISTORY</div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>{history.length} scans stored in database</div>
        </div>
        <button onClick={fetchHistory} style={{background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#8888cc",
          padding:"6px 14px",borderRadius:6,cursor:"pointer",fontFamily:"monospace",fontSize:11}}>↻ REFRESH</button>
      </div>
      {history.length===0?(
        <div style={{textAlign:"center",padding:"60px 0",color:"#2a2a4a"}}>
          <div style={{fontSize:48,marginBottom:12}}>📭</div>
          <div style={{fontSize:14,color:"#4a4a7a"}}>No scans yet. Run a scan to see history here.</div>
        </div>
      ):(
        <div style={{display:"grid",gap:8}}>
          {history.map(s=>{
            const c=RISK_COLOR[s.pqc_status]||RISK_COLOR.UNKNOWN;
            const date=s.created_at?new Date(s.created_at).toLocaleString():"—";
            return (
              <div key={s.id} onClick={()=>loadScan(s.id)} style={{
                background:"#080818",border:`1px solid ${c.border}30`,borderLeft:`3px solid ${c.border}`,
                borderRadius:9,padding:"13px 16px",cursor:"pointer",transition:"all 0.2s",
                display:"flex",justifyContent:"space-between",alignItems:"center",
                opacity:loadingId===s.id?0.7:1}}>
                <div>
                  <div style={{color:"#e0e0ff",fontFamily:"monospace",fontWeight:700,fontSize:13}}>🔒 {s.target}</div>
                  <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>{s.tls_version||"—"} · {date}</div>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <ScoreRing score={s.pqc_score||0} size={40}/>
                  <Badge status={s.pqc_status} small/>
                  <button onClick={e=>deleteScan(s.id,e)} disabled={deletingId===s.id} style={{
                    background:"#1a0000",border:"1px solid #ff174430",color:"#ff5252",
                    padding:"4px 8px",borderRadius:5,cursor:"pointer",fontSize:11,fontFamily:"monospace"}}>
                    {deletingId===s.id?"...":"✕"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── User Management Panel (Admin only) ────────────────────────────────────────
function UserManagement({backendUrl,token,currentUser}) {
  const [users,setUsers]=useState([]);
  const [loading,setLoading]=useState(true);
  const [newUser,setNewUser]=useState({username:"",email:"",password:"",role:"Operator"});
  const [creating,setCreating]=useState(false);
  const [error,setError]=useState("");
  const [success,setSuccess]=useState("");

  const fetchUsers=useCallback(async()=>{
    setLoading(true);
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users`,{headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) setUsers(await res.json());
    } catch(_){}
    setLoading(false);
  },[backendUrl,token]);

  useEffect(()=>{fetchUsers();},[fetchUsers]);

  const createUser=async()=>{
    if(!newUser.username||!newUser.email||!newUser.password){setError("All fields required");return;}
    setCreating(true);setError("");
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/register`,{
        method:"POST",headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body:JSON.stringify(newUser)});
      if(res.ok){
        setSuccess("User created successfully");
        setNewUser({username:"",email:"",password:"",role:"Operator"});
        fetchUsers();
        setTimeout(()=>setSuccess(""),3000);
      } else {
        const d=await res.json().catch(()=>({}));
        setError(d.detail||"Failed to create user");
      }
    } catch(_){setError("Request failed");}
    setCreating(false);
  };

  const toggleUser=async(id)=>{
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users/${id}/toggle`,{method:"PUT",headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) fetchUsers();
    } catch(_){}
  };

  const deleteUser=async(id,uname)=>{
    if(!window.confirm(`Delete user "${uname}"?`)) return;
    try {
      const res=await fetch(`${backendUrl}/api/v1/auth/users/${id}`,{method:"DELETE",headers:{"Authorization":`Bearer ${token}`}});
      if(res.ok) setUsers(u=>u.filter(x=>x.id!==id));
    } catch(_){}
  };

  const inp={width:"100%",background:"#0f0f25",border:"1px solid #2a2a4a",borderRadius:7,
    color:"#e0e0ff",fontFamily:"monospace",fontSize:12,padding:"9px 12px",outline:"none",boxSizing:"border-box"};
  const roleColor={Admin:"#a78bfa",Operator:"#60a5fa",Checker:"#34d399"};

  return (
    <div style={{padding:"20px 24px",maxWidth:900,margin:"0 auto"}}>
      <div style={{color:"#e0e0ff",fontWeight:700,fontSize:16,fontFamily:"monospace",marginBottom:20}}>👥 USER MANAGEMENT</div>

      {/* Create User */}
      <div style={{background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:12,padding:"20px",marginBottom:24}}>
        <div style={{color:"#a78bfa",fontSize:12,fontWeight:700,letterSpacing:1,marginBottom:14}}>CREATE NEW USER</div>
        {error&&<div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",padding:"8px 12px",borderRadius:6,marginBottom:12,fontSize:12}}>{error}</div>}
        {success&&<div style={{background:"#00e67615",border:"1px solid #00e67640",color:"#00e676",padding:"8px 12px",borderRadius:6,marginBottom:12,fontSize:12}}>{success}</div>}
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
          <div><div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>USERNAME</div><input value={newUser.username} onChange={e=>setNewUser({...newUser,username:e.target.value})} style={inp} placeholder="johndoe"/></div>
          <div><div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>EMAIL</div><input value={newUser.email} onChange={e=>setNewUser({...newUser,email:e.target.value})} style={inp} placeholder="john@example.com"/></div>
          <div><div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>PASSWORD</div><input type="password" value={newUser.password} onChange={e=>setNewUser({...newUser,password:e.target.value})} style={inp} placeholder="••••••••"/></div>
          <div><div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>ROLE</div>
            <select value={newUser.role} onChange={e=>setNewUser({...newUser,role:e.target.value})}
              style={{...inp,cursor:"pointer"}}>
              <option value="Operator">Operator</option>
              <option value="Checker">Checker</option>
              <option value="Admin">Admin</option>
            </select>
          </div>
        </div>
        <button onClick={createUser} disabled={creating} style={{
          background:creating?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
          border:"none",borderRadius:7,color:"#fff",padding:"10px 24px",
          fontFamily:"monospace",fontSize:12,fontWeight:700,cursor:creating?"not-allowed":"pointer",letterSpacing:1}}>
          {creating?"CREATING...":"+ CREATE USER"}
        </button>
      </div>

      {/* User List */}
      {loading?(
        <div style={{color:"#6666aa",padding:20,textAlign:"center",fontFamily:"monospace"}}>Loading users...</div>
      ):(
        <div style={{display:"grid",gap:8}}>
          {users.map(u=>(
            <div key={u.id} style={{background:"#080818",border:"1px solid #1e1e3a",borderRadius:9,
              padding:"13px 16px",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div>
                <div style={{display:"flex",alignItems:"center",gap:10}}>
                  <span style={{color:"#e0e0ff",fontFamily:"monospace",fontWeight:700,fontSize:13}}>{u.username}</span>
                  <span style={{background:`${roleColor[u.role]||"#888"}22`,color:roleColor[u.role]||"#888",
                    border:`1px solid ${roleColor[u.role]||"#888"}44`,padding:"1px 8px",borderRadius:4,fontSize:10,fontWeight:700}}>{u.role}</span>
                  {!u.is_active&&<span style={{background:"#ff174420",color:"#ff5252",border:"1px solid #ff174440",padding:"1px 8px",borderRadius:4,fontSize:10}}>DISABLED</span>}
                  {u.username===currentUser.username&&<span style={{color:"#6666aa",fontSize:10}}>(you)</span>}
                </div>
                <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>{u.email} · Joined {u.created_at?new Date(u.created_at).toLocaleDateString():"—"}</div>
              </div>
              {u.username!==currentUser.username&&(
                <div style={{display:"flex",gap:8}}>
                  <button onClick={()=>toggleUser(u.id)} style={{
                    background:u.is_active?"#1a1200":"#061a0f",
                    border:`1px solid ${u.is_active?"#ff910040":"#00e67640"}`,
                    color:u.is_active?"#ffab40":"#00e676",padding:"5px 12px",borderRadius:6,
                    cursor:"pointer",fontFamily:"monospace",fontSize:11}}>
                    {u.is_active?"DISABLE":"ENABLE"}
                  </button>
                  <button onClick={()=>deleteUser(u.id,u.username)} style={{
                    background:"#1a0000",border:"1px solid #ff174430",color:"#ff5252",
                    padding:"5px 12px",borderRadius:6,cursor:"pointer",fontFamily:"monospace",fontSize:11}}>DELETE</button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Summary Bar ───────────────────────────────────────────────────────────────
function SummaryBar({results}) {
  if(!results.length) return null;
  const c={QUANTUM_SAFE:0,PQC_READY:0,TRANSITIONING:0,VULNERABLE:0};
  results.forEach(r=>{const s=r.pqc_assessment?.status;if(s in c)c[s]++;});
  const avgScore=results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0;
  return (
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:12}}>
        {Object.entries(c).map(([status,count])=>{
          const rc=RISK_COLOR[status];
          return <div key={status} style={{background:rc.bg,border:`1px solid ${rc.border}30`,borderRadius:8,padding:"12px 14px"}}>
            <div style={{color:rc.text,fontSize:26,fontWeight:900,fontFamily:"monospace"}}>{count}</div>
            <div style={{color:rc.border,fontSize:10,fontWeight:700,letterSpacing:1,marginTop:3}}>{rc.badge}</div>
          </div>;
        })}
      </div>
      <div style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:8,padding:"12px 16px",marginBottom:16,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <span style={{color:"#6666aa",fontSize:12}}>FLEET AVG SCORE</span>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:200,height:6,background:"#1e1e3a",borderRadius:3,overflow:"hidden"}}>
            <div style={{width:`${avgScore}%`,height:"100%",background:"linear-gradient(90deg,#ff1744,#ff9100,#c6ff00,#00e676)",borderRadius:3,transition:"width 1s ease"}}/>
          </div>
          <span style={{color:"#e0e0ff",fontWeight:700,fontFamily:"monospace",fontSize:14}}>{avgScore}/100</span>
        </div>
      </div>
    </div>
  );
}

// ── Vuln / CBOM / DNS / Headers Panels (unchanged from original) ──────────────
function VulnPanel({vulns}) {
  if(!vulns?.length) return <div style={{color:"#3a5a3a",fontSize:13,padding:"20px 0"}}>✓ No known classical vulnerabilities detected</div>;
  return <div style={{display:"flex",flexDirection:"column",gap:8}}>
    {vulns.map((v,i)=>(
      <div key={i} style={{background:"#120000",border:`1px solid ${SEV_COLOR[v.severity]||"#333"}30`,
        borderLeft:`3px solid ${SEV_COLOR[v.severity]||"#333"}`,borderRadius:6,padding:"10px 14px"}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
          <SevBadge sev={v.severity}/>
          <span style={{color:"#ffcccc",fontWeight:700,fontSize:13,fontFamily:"monospace"}}>{v.name}</span>
          {v.cve!=="N/A"&&<span style={{color:"#6666aa",fontSize:11,fontFamily:"monospace"}}>{v.cve}</span>}
        </div>
        <div style={{color:"#cc9999",fontSize:12,marginBottom:4}}>{v.description}</div>
        <div style={{color:"#888",fontSize:11}}>→ {v.action}</div>
      </div>
    ))}
  </div>;
}

function CBOMTable({components}) {
  const icons={protocol:"🔗","cipher-suite":"🔐",certificate:"📜","key-exchange":"🔑"};
  return <div style={{overflowX:"auto"}}>
    <table style={{width:"100%",borderCollapse:"collapse",fontFamily:"monospace",fontSize:12}}>
      <thead><tr style={{borderBottom:"1px solid #2a2a4a"}}>
        {["Type","Name","Details","Forward Secrecy","Quantum Status"].map(h=>(
          <th key={h} style={{padding:"8px 12px",textAlign:"left",color:"#6666aa",fontWeight:600,fontSize:10,letterSpacing:1}}>{h.toUpperCase()}</th>
        ))}
      </tr></thead>
      <tbody>{components?.map((c,i)=>(
        <tr key={i} style={{borderBottom:"1px solid #1a1a2e"}}>
          <td style={{padding:"9px 12px",color:"#9999cc"}}>{icons[c.type]||"·"} {c.type}</td>
          <td style={{padding:"9px 12px",color:"#e0e0ff",fontWeight:600,wordBreak:"break-all",maxWidth:200}}>{c.name}</td>
          <td style={{padding:"9px 12px",color:"#8888aa"}}>
            {c.bits?`${c.bits}-bit`:""} {c.version||""} {c.grade?<GradeBadge grade={c.grade}/>:""}
            {c.days_until_expiry!=null?<span style={{color:c.days_until_expiry<30?"#ff5252":"#6688aa",fontSize:11,marginLeft:4}}>{c.days_until_expiry}d</span>:""}
          </td>
          <td style={{padding:"9px 12px"}}>
            {c.forward_secrecy===true?<span style={{color:"#00e676"}}>✓ YES</span>:c.forward_secrecy===false?<span style={{color:"#ff5252"}}>✗ NO</span>:<span style={{color:"#6666aa"}}>—</span>}
          </td>
          <td style={{padding:"9px 12px"}}>
            {c.quantum_safe?<span style={{color:"#00e676",fontWeight:700}}>✓ QUANTUM SAFE</span>:<span style={{color:"#ff5252",fontWeight:700}}>✗ VULNERABLE</span>}
          </td>
        </tr>
      ))}</tbody>
    </table>
  </div>;
}

function DNSPanel({dns}) {
  if(!dns||!Object.keys(dns).length) return <div style={{color:"#444466",fontSize:13}}>DNS data not available</div>;
  const items=[
    ["DNS Resolves",dns.dns_resolves?"✓ Yes":"✗ No",dns.dns_resolves?"#00e676":"#ff5252"],
    ["IPv4 Addresses",dns.ipv4_addresses?.join(", ")||"None","#8c9eff"],
    ["IPv6 Addresses",dns.ipv6_addresses?.join(", ")||"None",dns.ipv6_addresses?.length?"#8c9eff":"#ffab40"],
    ["CAA Records",dns.caa_present?"✓ Present":"✗ Missing",dns.caa_present?"#00e676":"#ff5252"],
    ["DNSSEC",dns.dnssec_enabled?"✓ Enabled":"Not detected",dns.dnssec_enabled?"#00e676":"#ffab40"],
    ["SPF Record",dns.spf_present?"✓ Present":"Not detected",dns.spf_present?"#00e676":"#ffab40"],
    ["DMARC Record",dns.dmarc_present?"✓ Present":"Not detected",dns.dmarc_present?"#00e676":"#ffab40"],
  ];
  return <div>
    {items.map(([l,v,c])=>(
      <div key={l} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"9px 0",alignItems:"center"}}>
        <div style={{width:160,color:"#6666aa",fontSize:11,flexShrink:0}}>{l}</div>
        <div style={{color:c,fontSize:12,fontFamily:"monospace"}}>{v}</div>
      </div>
    ))}
    {dns.issues?.map((issue,i)=>(
      <div key={i} style={{background:"#1a1200",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
        borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"8px 12px",marginTop:8}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}><SevBadge sev={issue.severity}/><span style={{color:"#ddc",fontSize:12}}>{issue.issue}</span></div>
        <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
      </div>
    ))}
  </div>;
}

function HeadersPanel({http}) {
  if(!http||!Object.keys(http).length) return <div style={{color:"#444466",fontSize:13}}>HTTP header data not available</div>;
  const hsts=http.hsts||{};
  return <div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
      {[
        ["HSTS",hsts.present?"✓ Present":"✗ Missing",hsts.present?"#00e676":"#ff5252"],
        ["HSTS max-age",hsts.max_age?`${hsts.max_age}s`:"—",hsts.max_age>=31536000?"#00e676":"#ffab40"],
        ["includeSubDomains",hsts.include_subdomains?"✓":"✗",hsts.include_subdomains?"#00e676":"#ff5252"],
        ["Preload",hsts.preload?"✓ Yes":"✗ No",hsts.preload?"#00e676":"#ffab40"],
        ["CSP",http.csp?.present?"✓ Present":"✗ Missing",http.csp?.present?"#00e676":"#ff5252"],
        ["Header Score",`${http.score||0}/100`,(http.score||0)>=80?"#00e676":(http.score||0)>=60?"#ffab40":"#ff5252"],
      ].map(([l,v,c])=>(
        <div key={l} style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:6,padding:"10px 12px"}}>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:4}}>{l.toUpperCase()}</div>
          <div style={{color:c,fontFamily:"monospace",fontSize:12,fontWeight:700}}>{v}</div>
        </div>
      ))}
    </div>
    {http.headers_missing?.length>0&&(
      <div>
        <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>MISSING SECURITY HEADERS</div>
        <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
          {http.headers_missing.map((h,i)=>(
            <span key={i} style={{background:"#ff174420",border:"1px solid #ff174440",color:"#ff5252",
              padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{h}</span>
          ))}
        </div>
      </div>
    )}
    {http.issues?.map((issue,i)=>(
      <div key={i} style={{background:"#1a1000",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
        borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"8px 12px",marginTop:8}}>
        <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:3}}><SevBadge sev={issue.severity}/><span style={{color:"#ddc",fontSize:12}}>{issue.issue}</span></div>
        <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
      </div>
    ))}
  </div>;
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
// ── AI Explanation Panel ──────────────────────────────────────────────────────
function AIPanel({result, backendUrl, token}) {
  const [audience, setAudience] = useState("ceo");
  const [explanation, setExplanation] = useState("");
  const [loading, setLoading] = useState(false);
  const [source, setSource] = useState("");
  const [copied, setCopied] = useState(false);

  const generate = async () => {
    if (!result) return;
    setLoading(true); setExplanation(""); setSource("");
    const pqc  = result.pqc_assessment || {};
    const tls  = result.tls_info || {};
    const cert = result.certificate || {};
    const payload = {
      target: result.target,
      pqc_score: pqc.score || 0,
      pqc_status: pqc.status || "UNKNOWN",
      tls_version: tls.tls_version,
      cipher_suite: tls.cipher_suite,
      key_exchange: tls.key_exchange,
      cert_key_type: cert.key_type,
      cert_key_bits: cert.key_bits,
      forward_secrecy: tls.forward_secrecy,
      days_until_expiry: cert.days_until_expiry,
      vulnerabilities: result.vulnerabilities || [],
      top_issues: pqc.issues?.slice(0, 3) || [],
      audience,
    };
    try {
      const headers = {"Content-Type": "application/json"};
      if (token && token !== "demo") headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/ai/explain`, {
        method: "POST", headers, body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000)
      });
      if (res.ok) {
        const data = await res.json();
        setExplanation(data.explanation);
        setSource(data.source === "openai" ? `GPT (${data.model})` : "Rule-based fallback");
      } else {
        setExplanation("AI service unavailable. Add OPENAI_API_KEY to your Render environment variables.");
        setSource("error");
      }
    } catch(_) {
      // Offline fallback — generate locally with genuinely different formats
      const score = pqc.score || 0;
      const tver  = tls.tls_version || "Unknown";
      const ctype = `${cert.key_type || "?"}-${cert.key_bits || 0}`;
      const cipher = tls.cipher_suite || "Unknown";
      const kex   = tls.key_exchange || "Unknown";
      const hndl  = (result.vulnerabilities||[]).some(v=>v.name==="HNDL");
      const risk  = score >= 65 ? "moderate" : score >= 40 ? "significant" : "critical";
      let text = "";

      if (audience === "ceo") {
        text = `Think of your website's encryption like a padlock on a safe. Right now, ${result.target} uses a type of padlock called ${ctype} — perfectly strong against today's threats. But quantum computers, expected around 2030, can pick this lock in a matter of hours, not billions of years.\n\n` +
          (hndl ? `Here's what makes this urgent: sophisticated adversaries are already recording your encrypted internet traffic today, storing it, and waiting for quantum computers to arrive. When they do, everything you've transmitted — customer data, transactions, communications — could be decrypted retroactively. This is called Harvest Now, Decrypt Later.\n\n` : `With a score of ${score}/100, your site has ${risk} quantum risk. This needs attention before 2030.\n\n`) +
          `The good news: there's a clear migration path. NIST finalised new quantum-safe algorithms in 2024 (ML-KEM and ML-DSA). Budget 12–18 months, assign it to your CISO, and QuantumShield can track progress every step of the way.`;
      } else if (audience === "board") {
        text = `EXECUTIVE RISK SUMMARY\n${result.target} scores ${score}/100 on post-quantum cryptographic readiness — ${risk} risk level. Board attention is warranted.\n\n` +
          `THREAT LANDSCAPE\nQuantum computers capable of breaking ${ctype} encryption are estimated by NIST, IBM and Google to arrive around 2030–2035. The risk is not theoretical: nation-states are executing Harvest Now Decrypt Later (HNDL) operations today — recording encrypted traffic for future decryption.\n\n` +
          `REGULATORY EXPOSURE\nRBI Cybersecurity Framework, CERT-In guidelines, and the DPDP Act 2023 all require adequate cryptographic controls. A future audit finding of non-compliance with NIST PQC standards post-2026 would be a significant regulatory liability.\n\n` +
          `BOARD RESOLUTION REQUIRED\nApprove a PQC migration programme with budget for 12–24 months of engineering effort. Assign ownership to CISO. Mandate quarterly readiness reporting via QuantumShield dashboard.`;
      } else {
        text = `FINDINGS — ${result.target}\n────────────────────────\nTLS Version:    ${tver}\nCipher Suite:   ${cipher}\nKey Exchange:   ${kex}\nCertificate:    ${ctype}\nForward Secrecy:${tls.forward_secrecy ? " Yes" : " No — static key exchange"}\nPQC Score:      ${score}/100 (${pqc.status})\n\nROOT CAUSE\n${ctype.startsWith("RSA") ? `RSA is broken by Shor's algorithm in O(n³) polynomial time on a quantum computer. Key size (2048, 4096) is irrelevant — all RSA falls equally fast. Must replace with ML-DSA-65 (FIPS 204, lattice-based).` : ctype.startsWith("ECDSA") ? `ECDSA relies on discrete logarithm problem on elliptic curves — also solved by Shor's algorithm. P-256, P-384, secp521r1 all broken. Must replace with ML-DSA-65 (FIPS 204).` : `Certificate algorithm quantum status: check cert tab for details.`}\n${!tls.forward_secrecy ? "\nNo forward secrecy: static key exchange means compromise of long-term key decrypts ALL past sessions. Immediate ECDHE upgrade needed." : ""}\n\nREMEDIATION (priority order)\n1. [0-30 days] Enforce TLS 1.3 minimum — disable TLS 1.0/1.1/1.2\n2. [0-30 days] Deploy X25519+ML-KEM-768 hybrid KEX (RFC 9180 + FIPS 203)\n3. [3-6 months] Replace cert with ML-DSA-65 (FIPS 204) from PQC-ready CA\n4. [6-12 months] Update all internal services, VPNs, APIs to PQC algorithms\n5. [12-24 months] Achieve full NIST SP 800-208 compliance`;
      }
      setExplanation(text);
      setSource("Local fallback");
    }
    setLoading(false);
  };

  const copy = () => {
    navigator.clipboard.writeText(explanation);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };

  const audLabels = {ceo: "🏢 CEO Brief", board: "📊 Board Report", technical: "⚙️ Technical Team"};
  return (
    <div>
      <div style={{background:"linear-gradient(135deg,#1a0a2e,#0a1a2e)",border:"1px solid #7c3aed40",borderRadius:10,padding:"16px",marginBottom:14}}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
          <div style={{width:32,height:32,background:"linear-gradient(135deg,#7c3aed,#2563eb)",borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>🤖</div>
          <div>
            <div style={{color:"#e0e0ff",fontWeight:700,fontSize:14}}>QuantumShield AI</div>
            <div style={{color:"#6666aa",fontSize:11}}>Powered by GPT-4o · Explains results in plain language</div>
          </div>
        </div>
        <div style={{display:"flex",gap:6,marginBottom:12}}>
          {Object.entries(audLabels).map(([k,v])=>(
            <button key={k} onClick={()=>setAudience(k)} style={{
              flex:1,padding:"7px 4px",borderRadius:6,cursor:"pointer",fontFamily:"monospace",fontSize:10,fontWeight:700,
              background:audience===k?"linear-gradient(135deg,#7c3aed,#2563eb)":"#0a0a1e",
              border:`1px solid ${audience===k?"#7c3aed":"#2a2a4a"}`,
              color:audience===k?"#fff":"#6666aa"}}>
              {v}
            </button>
          ))}
        </div>
        <button onClick={generate} disabled={loading} style={{
          width:"100%",padding:"11px",borderRadius:8,cursor:loading?"not-allowed":"pointer",
          background:loading?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
          border:"none",color:"#fff",fontFamily:"monospace",fontSize:12,fontWeight:700,
          letterSpacing:1,boxShadow:loading?"none":"0 0 20px #7c3aed50"}}>
          {loading?"🤖 Generating AI Analysis...":"🤖 GENERATE AI EXPLANATION"}
        </button>
      </div>

      {explanation && (
        <div style={{background:"#08081a",border:"1px solid #2a2a4a",borderRadius:10,padding:"16px"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
            <div style={{display:"flex",gap:8,alignItems:"center"}}>
              <span style={{color:"#a78bfa",fontWeight:700,fontSize:13}}>{audLabels[audience]}</span>
              <span style={{background:"#a78bfa22",color:"#a78bfa",border:"1px solid #a78bfa44",
                padding:"1px 8px",borderRadius:4,fontSize:10,fontFamily:"monospace"}}>{source}</span>
            </div>
            <button onClick={copy} style={{background:"#1a1a2e",border:"1px solid #2a2a4a",color:copied?"#00e676":"#6666aa",
              padding:"4px 12px",borderRadius:5,cursor:"pointer",fontFamily:"monospace",fontSize:10}}>
              {copied?"✓ COPIED":"📋 COPY"}
            </button>
          </div>
          <div style={{color:"#c0c0e0",fontSize:13,lineHeight:1.8,fontFamily:"Georgia, serif",whiteSpace:"pre-wrap"}}>
            {explanation}
          </div>
        </div>
      )}

      {!explanation && !loading && (
        <div style={{textAlign:"center",padding:"30px 0",color:"#3a3a5a"}}>
          <div style={{fontSize:36,marginBottom:8}}>🤖</div>
          <div style={{fontSize:12,letterSpacing:2}}>SELECT AUDIENCE & CLICK GENERATE</div>
          <div style={{fontSize:11,marginTop:6,color:"#2a2a4a"}}>CEO brief, board report, or technical deep-dive</div>
        </div>
      )}
    </div>
  );
}

// ── Quantum Attack Simulator ──────────────────────────────────────────────────
function QuantumSimulator({result}) {
  const [phase, setPhase] = useState("idle"); // idle | running | done
  const [step, setStep]   = useState(0);
  const [progress, setProgress] = useState(0);
  const intervalRef = useRef(null);

  const cert = result?.certificate || {};
  const tls  = result?.tls_info || {};
  const pqc  = result?.pqc_assessment || {};
  const keyType = cert.key_type || "RSA";
  const keyBits = cert.key_bits || 2048;
  const isVulnerable = !["ML-DSA","SLH-DSA"].includes(keyType);

  const classicalYears = keyBits >= 4096 ? "300 billion years" : keyBits >= 2048 ? "13.7 billion years" : "years";
  const quantumTime    = keyBits >= 4096 ? "~14 hours" : keyBits >= 2048 ? "~8 hours" : "~2 hours";
  const qubitsNeeded   = Math.round(keyBits * 2.5);

  const steps = [
    {label:"INITIALISING QUANTUM SIMULATION", detail:"Loading lattice-based attack model...", color:"#8888cc"},
    {label:"TARGET IDENTIFIED", detail:`${result?.target} — ${keyType}-${keyBits} certificate`, color:"#a78bfa"},
    {label:"HARVESTING PUBLIC KEY", detail:`Extracting ${keyBits}-bit public key from X.509 certificate...`, color:"#ffab40"},
    {label:"INITIALISING SHOR'S ALGORITHM", detail:`Requires ${qubitsNeeded.toLocaleString()} logical qubits (2031-era quantum computer)`, color:"#ff9100"},
    {label:"COMPUTING QUANTUM FOURIER TRANSFORM", detail:"Period-finding on the RSA modulus N = p × q...", color:"#ff6644"},
    {label:"FACTORING RSA MODULUS", detail:`N = ${keyBits}-bit composite — finding prime factors p and q...`, color:"#ff5252"},
    {label:"PRIVATE KEY RECOVERED", detail:`${keyType}-${keyBits} private key derived in ${quantumTime}`, color:"#ff1744"},
    {label:"DECRYPTING HISTORICAL SESSIONS", detail:"Accessing all TLS sessions recorded since 2019...", color:"#ff1744"},
    {label:"ATTACK COMPLETE", detail:`${isVulnerable ? "⚠ KEY BROKEN — All encrypted data exposed" : "✓ PQC algorithms resisted quantum attack"}`, color: isVulnerable ? "#ff1744" : "#00e676"},
  ];

  const run = () => {
    if(phase === "running") return;
    setPhase("running"); setStep(0); setProgress(0);
    let s = 0;
    intervalRef.current = setInterval(() => {
      s++;
      setStep(s);
      setProgress(Math.min(100, Math.round((s / steps.length) * 100)));
      if(s >= steps.length) {
        clearInterval(intervalRef.current);
        setPhase("done");
      }
    }, 600);
  };

  const reset = () => {
    clearInterval(intervalRef.current);
    setPhase("idle"); setStep(0); setProgress(0);
  };

  const score = pqc.score || 0;
  const riskColor = score < 40 ? "#ff1744" : score < 65 ? "#ff9100" : "#c6ff00";

  return (
    <div>
      <div style={{background:"#0a0000",border:`1px solid ${riskColor}40`,borderRadius:10,padding:"16px",marginBottom:14}}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
          <div style={{width:32,height:32,background:`${riskColor}22`,border:`1px solid ${riskColor}`,borderRadius:8,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>⚡</div>
          <div>
            <div style={{color:"#e0e0ff",fontWeight:700,fontSize:14}}>Quantum Attack Simulator</div>
            <div style={{color:"#6666aa",fontSize:11}}>Simulates Shor's Algorithm on {result?.target}</div>
          </div>
          <div style={{marginLeft:"auto"}}>
            <div style={{color:riskColor,fontFamily:"monospace",fontSize:20,fontWeight:900}}>{score}/100</div>
          </div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:10,marginBottom:14}}>
          {[
            ["TARGET KEY", `${keyType}-${keyBits}`, "#ff5252"],
            ["CLASSICAL BREAK TIME", classicalYears, "#00e676"],
            ["QUANTUM BREAK TIME", quantumTime, "#ff1744"],
            ["QUBITS NEEDED", qubitsNeeded.toLocaleString(), "#8c9eff"],
            ["ATTACK", "Shor's Algorithm", "#ffab40"],
            ["HNDL STATUS", isVulnerable ? "⚠ EXPOSED" : "✓ PROTECTED", isVulnerable ? "#ff1744" : "#00e676"],
          ].map(([k,v,c])=>(
            <div key={k} style={{background:"#050505",border:"1px solid #1a1a1a",borderRadius:6,padding:"8px 10px"}}>
              <div style={{color:"#555555",fontSize:9,letterSpacing:1,marginBottom:3}}>{k}</div>
              <div style={{color:c,fontFamily:"monospace",fontSize:11,fontWeight:700}}>{v}</div>
            </div>
          ))}
        </div>

        <div style={{display:"flex",gap:8}}>
          <button onClick={run} disabled={phase==="running"} style={{
            flex:1,padding:"11px",borderRadius:7,cursor:phase==="running"?"not-allowed":"pointer",
            background:phase==="running"?"#1a0000":isVulnerable?"linear-gradient(135deg,#c0392b,#e74c3c)":"linear-gradient(135deg,#1e8449,#27ae60)",
            border:"none",color:"#fff",fontFamily:"monospace",fontSize:12,fontWeight:700,letterSpacing:1,
            boxShadow:phase==="running"?"none":`0 0 20px ${isVulnerable?"#ff174450":"#00e67650"}`}}>
            {phase==="running"?"⚡ ATTACK IN PROGRESS...":phase==="done"?"↻ RE-RUN SIMULATION":"⚡ LAUNCH QUANTUM ATTACK"}
          </button>
          {phase!=="idle"&&(
            <button onClick={reset} style={{padding:"11px 16px",borderRadius:7,cursor:"pointer",
              background:"#1a1a2e",border:"1px solid #2a2a4a",color:"#6666aa",fontFamily:"monospace",fontSize:11}}>
              RESET
            </button>
          )}
        </div>
      </div>

      {phase !== "idle" && (
        <div style={{background:"#050505",border:"1px solid #1a1a1a",borderRadius:10,padding:"16px",fontFamily:"monospace"}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:10}}>
            <span style={{color:"#555",fontSize:11}}>SIMULATION PROGRESS</span>
            <span style={{color:riskColor,fontWeight:700,fontSize:13}}>{progress}%</span>
          </div>
          <div style={{background:"#0a0a0a",borderRadius:3,height:4,marginBottom:14,overflow:"hidden"}}>
            <div style={{height:"100%",width:`${progress}%`,background:`linear-gradient(90deg,#7c3aed,${riskColor})`,
              transition:"width 0.5s ease",borderRadius:3}}/>
          </div>

          <div style={{maxHeight:280,overflowY:"auto"}}>
            {steps.slice(0, step).map((s, i) => (
              <div key={i} style={{display:"flex",gap:10,padding:"6px 0",
                borderBottom:"1px solid #0f0f0f",alignItems:"flex-start"}}>
                <span style={{color:"#333",fontSize:10,flexShrink:0,marginTop:2}}>{String(i+1).padStart(2,"0")}</span>
                <div>
                  <div style={{color:s.color,fontSize:11,fontWeight:700}}>{s.label}</div>
                  <div style={{color:"#444",fontSize:10,marginTop:2}}>{s.detail}</div>
                </div>
                <span style={{marginLeft:"auto",color:"#333",fontSize:10,flexShrink:0}}>✓</span>
              </div>
            ))}
            {phase==="running" && step < steps.length && (
              <div style={{display:"flex",gap:10,padding:"6px 0",alignItems:"center"}}>
                <span style={{color:"#7c3aed",fontSize:10,flexShrink:0}}>{String(step+1).padStart(2,"0")}</span>
                <div style={{color:"#a78bfa",fontSize:11}}>{steps[step]?.label}</div>
                <span style={{marginLeft:"auto",color:"#7c3aed",animation:"none"}}>▶</span>
              </div>
            )}
          </div>

          {phase === "done" && (
            <div style={{marginTop:14,padding:"14px",borderRadius:8,
              background:isVulnerable?"#1a0000":"#061a0f",
              border:`1px solid ${isVulnerable?"#ff1744":"#00e676"}40`}}>
              <div style={{color:isVulnerable?"#ff1744":"#00e676",fontWeight:900,fontSize:16,marginBottom:6}}>
                {isVulnerable?"🔴 ATTACK SUCCESSFUL — KEY COMPROMISED":"🟢 ATTACK FAILED — PQC ALGORITHMS HELD"}
              </div>
              {isVulnerable ? (
                <>
                  <div style={{color:"#ff5252",fontSize:12,marginBottom:4}}>
                    {keyType}-{keyBits} private key recovered in {quantumTime} using {qubitsNeeded.toLocaleString()} qubits
                  </div>
                  <div style={{color:"#884444",fontSize:11}}>
                    All TLS sessions encrypted with this key are now decryptable. Estimated data exposed: all HTTPS traffic
                    since certificate issuance. This is the Harvest Now, Decrypt Later threat materialised.
                  </div>
                  <div style={{color:"#ff9100",fontSize:11,marginTop:8,fontWeight:700}}>
                    → IMMEDIATE ACTION: Migrate to ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203)
                  </div>
                </>
              ) : (
                <div style={{color:"#66cc88",fontSize:12}}>
                  ML-DSA / ML-KEM algorithms are based on Module Learning With Errors (MLWE) — a mathematical problem
                  believed to be hard for both classical and quantum computers. Shor's algorithm does not apply.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DetailPanel({result, backendUrl, token}) {
  const [tab,setTab]=useState("overview");
  useEffect(()=>setTab("overview"),[result?.target]);
  if(!result) return (
    <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",color:"#2a2a4a"}}>
      <div style={{fontSize:64,marginBottom:16}}>⚛</div>
      <div style={{fontSize:15,letterSpacing:4,color:"#4a4a7a"}}>SELECT A TARGET</div>
      <div style={{fontSize:12,color:"#3a3a5a",marginTop:8}}>TO VIEW FULL ANALYSIS</div>
    </div>
  );
  const pqc=result.pqc_assessment||{};const tls=result.tls_info||{};const cert=result.certificate||{};
  const cbom=result.cbom||{};const vulns=result.vulnerabilities||[];const dns=result.dns||{};
  const http=result.http_headers||{};const c=RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  const tabs=[
    {id:"overview",label:"Overview"},
    {id:"cbom",label:"CBOM"},
    {id:"certificate",label:"Certificate"},
    {id:"vulns",label:`Vulns${vulns.length>0?` (${vulns.length})`:""}`,alert:vulns.some(v=>v.severity==="CRITICAL")},
    {id:"dns",label:"DNS"},{id:"headers",label:"Headers"},
    {id:"ai",label:"🤖 AI",glow:true},
    {id:"quantum",label:"⚡ Attack Sim",glow:true},
    {id:"roadmap",label:"Roadmap"},
  ];
  return (
    <div style={{height:"100%",display:"flex",flexDirection:"column"}}>
      <div style={{padding:"16px 20px",borderBottom:"1px solid #1e1e3a",background:c.bg}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div>
            <div style={{color:"#e0e0ff",fontFamily:"monospace",fontWeight:800,fontSize:16}}>🔒 {result.target}</div>
            <div style={{color:"#8888aa",fontSize:11,marginTop:3}}>{tls.tls_version||"—"} · Port {result.port} · {tls.cipher_grade?<GradeBadge grade={tls.cipher_grade}/>:""}</div>
            <div style={{marginTop:6,display:"flex",gap:6,flexWrap:"wrap"}}>
              {tls.forward_secrecy&&<span style={{background:"#00e67610",border:"1px solid #00e67640",color:"#00e676",padding:"1px 7px",borderRadius:3,fontSize:10}}>FS</span>}
              {result.status==="success_inferred"&&<span style={{background:"#ffab4010",border:"1px solid #ffab4040",color:"#ffab40",padding:"1px 7px",borderRadius:3,fontSize:10}}>INFERRED</span>}
              {result.status==="success_unverified"&&<span style={{background:"#ff525210",border:"1px solid #ff525240",color:"#ff5252",padding:"1px 7px",borderRadius:3,fontSize:10}}>UNVERIFIED CERT</span>}
            </div>
          </div>
          <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:6}}>
            <ScoreRing score={pqc.score||0} size={72}/>
            <Badge status={pqc.status}/>
            <div style={{color:"#6666aa",fontSize:10}}>{pqc.parameters_checked||40} params checked</div>
          </div>
        </div>
      </div>
      <div style={{display:"flex",borderBottom:"1px solid #1e1e3a",padding:"0 20px",overflowX:"auto"}}>
        {tabs.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} style={{background:"none",border:"none",
            color:tab===t.id?"#a78bfa":t.glow?"#9b59b6":"#666688",padding:"10px 12px",cursor:"pointer",
            fontFamily:"monospace",fontSize:11,borderBottom:tab===t.id?"2px solid #a78bfa":t.glow?"2px solid #7c3aed44":"2px solid transparent",
            whiteSpace:"nowrap",position:"relative",
            textShadow:t.glow&&tab!==t.id?"0 0 10px #9b59b6":"none"}}>
            {t.label}
            {t.alert&&<span style={{position:"absolute",top:6,right:4,width:6,height:6,borderRadius:"50%",background:"#ff1744"}}/>}
          </button>
        ))}
      </div>
      <div style={{flex:1,overflowY:"auto",padding:"16px 20px"}}>
        {tab==="overview"&&(
          <div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
              {[
                ["TLS Version",tls.tls_version||"—",tls.tls_version?.includes("1.3")?"#00e676":"#ffab40"],
                ["Cipher Suite",tls.cipher_suite||"—","#8c9eff"],
                ["Key Exchange",tls.key_exchange||"—",tls.key_exchange?.includes("Quantum-Safe")?"#00e676":"#ff5252"],
                ["Cert Type",`${cert.key_type||"?"}-${cert.key_bits||0}`,cert.pqc_cert?"#00e676":"#ff5252"],
                ["Forward Secrecy",tls.forward_secrecy?"✓ Enabled":"✗ Disabled",tls.forward_secrecy?"#00e676":"#ff5252"],
                ["Cipher Grade",tls.cipher_grade||"?",{A:"#00e676",B:"#c6ff00",C:"#ffab40",D:"#ff5252",F:"#ff1744"}[tls.cipher_grade]||"#888"],
                ["Cert Expires",cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—",cert.days_until_expiry<30?"#ff5252":cert.days_until_expiry<90?"#ffab40":"#00e676"],
                ["CT Logs",cert.ct_sct_count>0?`✓ ${cert.ct_sct_count} SCTs`:"✗ None",cert.ct_sct_count>0?"#00e676":"#ffab40"],
              ].map(([l,v,c])=>(
                <div key={l} style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:7,padding:"10px 14px"}}>
                  <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:5}}>{l.toUpperCase()}</div>
                  <div style={{color:c,fontFamily:"monospace",fontSize:12,fontWeight:600,wordBreak:"break-all"}}>{v}</div>
                </div>
              ))}
            </div>
            <div style={{color:"#a0a0cc",fontSize:10,fontWeight:700,letterSpacing:2,marginBottom:10}}>SECURITY FINDINGS</div>
            {pqc.positives?.map((p,i)=>(
              <div key={i} style={{display:"flex",gap:8,padding:"7px 0",borderBottom:"1px solid #0a1a0a",alignItems:"flex-start"}}>
                <span style={{color:"#00e676",fontSize:14,flexShrink:0}}>✓</span>
                <span style={{color:"#66cc88",fontSize:12}}>{p}</span>
              </div>
            ))}
            <div style={{marginTop:pqc.positives?.length?12:0}}>
              {pqc.issues?.map((issue,i)=>(
                <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"9px 12px",marginBottom:7}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4,flexWrap:"wrap"}}>
                    <SevBadge sev={issue.severity}/><span style={{color:"#ffcccc",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {tab==="cbom"&&(
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              Cryptographic Bill of Materials · CycloneDX v1.4 · NIST SP 800-235
              <span style={{background:"#a78bfa22",color:"#a78bfa",border:"1px solid #a78bfa44",padding:"1px 8px",borderRadius:4,fontSize:10,marginLeft:8,fontFamily:"monospace"}}>cyclonedx.org/schema/bom-1.4</span>
            </div>
            <CBOMTable components={cbom.components}/>
            {tls.supported_ciphers?.length>0&&(
              <div style={{marginTop:16}}>
                <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>ALL SUPPORTED CIPHER SUITES</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                  {tls.supported_ciphers.map((c,i)=>(
                    <span key={i} style={{background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#8888cc",
                      padding:"3px 8px",borderRadius:4,fontSize:10,fontFamily:"monospace"}}>{c}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {tab==="certificate"&&(
          <div>
            {cert.issues?.map((issue,i)=>(
              <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]}30`,
                borderLeft:`3px solid ${SEV_COLOR[issue.severity]}`,borderRadius:6,padding:"8px 12px",marginBottom:8}}>
                <SevBadge sev={issue.severity}/> <span style={{color:"#ffcccc",fontSize:12,marginLeft:8}}>{issue.issue}</span>
                <div style={{color:"#888",fontSize:11,marginTop:4}}>→ {issue.action}</div>
              </div>
            ))}
            {[["Subject",cert.subject],["Issuer",cert.issuer],
              ["Key Type",`${cert.key_type}-${cert.key_bits}${cert.curve_name?` (${cert.curve_name})`:""}`],
              ["Signature Algo",cert.signature_algorithm],["Valid From",cert.not_before],["Valid Until",cert.not_after],
              ["Days Until Expiry",cert.days_until_expiry!=null?`${cert.days_until_expiry} days`:"—"],
              ["Self-Signed",cert.is_self_signed?"⚠ YES":"No"],
              ["CT SCT Count",cert.ct_sct_count!=null?`${cert.ct_sct_count} SCTs`:"—"],
              ["PQC Certificate",cert.pqc_cert?"✓ YES — Quantum Safe":"✗ NO — Quantum Vulnerable"],
              ["OCSP URL",cert.ocsp_urls?.[0]||"None"],
            ].map(([l,v])=>v&&(
              <div key={l} style={{display:"flex",borderBottom:"1px solid #1a1a2e",padding:"9px 0"}}>
                <div style={{width:160,color:"#6666aa",fontSize:11,flexShrink:0}}>{l}</div>
                <div style={{color:"#c0c0e0",fontSize:12,fontFamily:"monospace",wordBreak:"break-all"}}>{v||"—"}</div>
              </div>
            ))}
            {cert.sans?.length>0&&(
              <div style={{marginTop:14}}>
                <div style={{color:"#6666aa",fontSize:10,letterSpacing:1,marginBottom:8}}>SUBJECT ALTERNATIVE NAMES ({cert.sans.length})</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                  {cert.sans.map((san,i)=>(
                    <span key={i} style={{background:"#1a1a2e",border:"1px solid #2a2a4a",color:"#8c9eff",
                      padding:"2px 9px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{san}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {tab==="vulns"&&<div><div style={{color:"#a0a0cc",fontSize:11,marginBottom:12}}>Cross-referenced against known TLS/cryptographic vulnerability database</div><VulnPanel vulns={vulns}/></div>}
        {tab==="dns"&&<div><div style={{color:"#a0a0cc",fontSize:11,marginBottom:12}}>DNS security configuration analysis</div><DNSPanel dns={dns}/></div>}
        {tab==="headers"&&<div><div style={{color:"#a0a0cc",fontSize:11,marginBottom:12}}>HTTP security headers affecting cryptographic posture</div><HeadersPanel http={http}/></div>}
        {tab==="ai"&&(
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              AI-powered plain-language explanation of scan results · Powered by GPT-4o
            </div>
            <AIPanel result={result} backendUrl={backendUrl} token={token}/>
          </div>
        )}
        {tab==="quantum"&&(
          <div>
            <div style={{color:"#a0a0cc",fontSize:11,marginBottom:12,lineHeight:1.6}}>
              Simulates Shor's Algorithm attack on this target's cryptographic configuration
            </div>
            <QuantumSimulator result={result}/>
          </div>
        )}
        {tab==="roadmap"&&(
          <div>
            <div style={{background:"#060f06",border:"1px solid #00e67620",borderRadius:8,padding:"14px 16px",marginBottom:14}}>
              <div style={{color:"#00e676",fontWeight:700,fontSize:13,marginBottom:12}}>🗺 NIST PQC Migration Roadmap for {result.target}</div>
              {[
                {phase:"Phase 1 — Immediate (0–3 months)",color:"#ff5252",items:["Audit and inventory ALL cryptographic assets (CBOM)","Disable TLS 1.0 and TLS 1.1 on all endpoints","Replace RC4, 3DES, DES, NULL ciphers with AES-256-GCM","Enforce TLS 1.3 as minimum protocol version","Enable HSTS with max-age=31536000, includeSubDomains, preload"]},
                {phase:"Phase 2 — Short-term (3–12 months)",color:"#ffab40",items:["Deploy hybrid key exchange: X25519 + ML-KEM-768 (FIPS 203)","Begin PKI migration planning for ML-DSA (FIPS 204) certificates","Implement crypto-agility framework for rapid algorithm swaps","Add CAA DNS records restricting certificate issuance"]},
                {phase:"Phase 3 — Long-term (1–3 years)",color:"#c6ff00",items:["Full certificate migration to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)","Deploy ML-KEM-1024 for highest-security endpoints","Establish continuous CBOM lifecycle management","Obtain 'Fully Quantum Safe' certification for all public assets"]},
              ].map(({phase,color,items})=>(
                <div key={phase} style={{marginBottom:16}}>
                  <div style={{color,fontSize:11,fontWeight:700,letterSpacing:1,marginBottom:8,padding:"4px 10px",background:`${color}15`,borderRadius:4,display:"inline-block"}}>{phase.toUpperCase()}</div>
                  {items.map((item,i)=>(
                    <div key={i} style={{color:"#c0c0e0",fontSize:12,padding:"4px 0 4px 14px",borderLeft:`2px solid ${color}30`,marginBottom:3}}>→ {item}</div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultCard({result,onSelect,selected}) {
  const pqc=result.pqc_assessment||{};const tls=result.tls_info||{};
  const vulnCount=result.vulnerabilities?.length||0;const c=RISK_COLOR[pqc.status]||RISK_COLOR.UNKNOWN;
  return (
    <div onClick={()=>onSelect(result)} style={{background:selected?"#0e0e20":"#080818",
      border:`1px solid ${selected?c.border:"#1e1e3a"}`,borderLeft:`3px solid ${c.border}`,
      borderRadius:8,padding:"12px 14px",cursor:"pointer",transition:"all 0.2s",marginBottom:8,
      boxShadow:selected?`0 0 16px ${c.glow}`:"none"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{flex:1,minWidth:0}}>
          <div style={{color:"#e0e0ff",fontWeight:700,fontFamily:"monospace",fontSize:13,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>🔒 {result.target}</div>
          <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>
            {tls.tls_version||"—"} · {tls.cipher_grade?`Grade ${tls.cipher_grade}`:""}
            {vulnCount>0&&<span style={{color:"#ff5252",marginLeft:6}}>⚠ {vulnCount} vuln{vulnCount>1?"s":""}</span>}
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
          <ScoreRing score={pqc.score||0} size={48}/>
          <Badge status={pqc.status} small/>
        </div>
      </div>
    </div>
  );
}

// ── API Scanner Panel ─────────────────────────────────────────────────────────
function APIScanPanel({backendUrl, token}) {
  const [url, setUrl]         = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState("");

  const scan = async () => {
    if(!url.trim()) return;
    setLoading(true); setResult(null); setError("");
    try {
      const headers = {"Content-Type":"application/json"};
      if(token && token!=="demo") headers["Authorization"]=`Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/scan/api`, {
        method:"POST", headers,
        body: JSON.stringify({base_url: url.trim(), port:443}),
        signal: AbortSignal.timeout(60000)
      });
      if(res.ok) setResult(await res.json());
      else setError(`Scan failed: ${res.status}`);
    } catch(e) { setError(`Error: ${e.message}`); }
    setLoading(false);
  };

  const statusColor = {QUANTUM_SAFE:"#00e676",PQC_READY:"#c6ff00",TRANSITIONING:"#ff9100",VULNERABLE:"#ff1744"};

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",height:"calc(100vh - 56px)"}}>
      <div style={{marginBottom:20}}>
        <div style={{color:"#e0e0ff",fontWeight:800,fontSize:18,letterSpacing:2}}>🔌 API ENDPOINT SCANNER</div>
        <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>Discovers API endpoints and scans TLS config per endpoint · CERT-In CBOM Annexure-A</div>
      </div>

      <div style={{display:"flex",gap:10,marginBottom:20}}>
        <input value={url} onChange={e=>setUrl(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&scan()}
          placeholder="https://api.pnbindia.in or pnbindia.in"
          style={{flex:1,background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:7,
            color:"#e0e0ff",fontFamily:"monospace",fontSize:13,padding:"11px 14px",outline:"none"}}/>
        <button onClick={scan} disabled={loading} style={{
          padding:"11px 24px",borderRadius:7,border:"none",cursor:loading?"not-allowed":"pointer",
          background:loading?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
          color:"#fff",fontFamily:"monospace",fontSize:12,fontWeight:700,
          boxShadow:loading?"none":"0 0 20px #7c3aed40"}}>
          {loading?"🔍 SCANNING...":"🔍 SCAN APIs"}
        </button>
      </div>

      {error && <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",
        padding:"10px 14px",borderRadius:8,marginBottom:16,fontSize:12}}>{error}</div>}

      {result && (
        <div>
          {/* Summary */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:20}}>
            {[
              ["ENDPOINTS PROBED", result.api_tls_summary?.total_endpoints_discovered||0, "#8c9eff"],
              ["REACHABLE", result.api_tls_summary?.total_reachable||0, "#c6ff00"],
              ["TLS VERSIONS", (result.api_tls_summary?.tls_versions||[]).join(", ")||"—", "#ffab40"],
              ["WORST GRADE", result.api_tls_summary?.worst_cipher_grade||"?",
                {A:"#00e676",B:"#c6ff00",C:"#ffab40",D:"#ff5252",F:"#ff1744"}[result.api_tls_summary?.worst_cipher_grade]||"#888"],
            ].map(([l,v,c])=>(
              <div key={l} style={{background:"#08081a",border:`1px solid ${c}20`,borderRadius:8,padding:"12px 14px"}}>
                <div style={{color:"#6666aa",fontSize:9,letterSpacing:2}}>{l}</div>
                <div style={{color:c,fontSize:18,fontWeight:900,fontFamily:"monospace",marginTop:4}}>{v}</div>
              </div>
            ))}
          </div>

          {/* PQC Issues */}
          {result.pqc_issues?.length>0 && (
            <div style={{marginBottom:16}}>
              <div style={{color:"#a0a0cc",fontSize:10,letterSpacing:2,marginBottom:10}}>PQC ISSUES DETECTED</div>
              {result.pqc_issues.map((issue,i)=>(
                <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"10px 14px",marginBottom:8}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
                    <SevBadge sev={issue.severity}/>
                    <span style={{color:"#ffcccc",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          )}

          {/* Reachable Endpoints Table */}
          {result.endpoints_reachable?.length>0 && (
            <div style={{marginBottom:16}}>
              <div style={{color:"#a0a0cc",fontSize:10,letterSpacing:2,marginBottom:10}}>
                REACHABLE API ENDPOINTS ({result.endpoints_reachable.length})
              </div>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                  <thead><tr style={{borderBottom:"1px solid #2a2a4a"}}>
                    {["Path","Status","TLS","Cipher","Grade","FS","Quantum Safe","Content-Type"].map(h=>(
                      <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1,whiteSpace:"nowrap"}}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {result.endpoints_reachable.map((ep,i)=>(
                      <tr key={i} style={{borderBottom:"1px solid #1a1a2e"}}>
                        <td style={{padding:"8px 10px",color:"#a78bfa",fontFamily:"monospace",fontSize:11}}>{ep.path}</td>
                        <td style={{padding:"8px 10px",color:ep.status_code<400?"#00e676":"#ffab40"}}>{ep.status_code||"—"}</td>
                        <td style={{padding:"8px 10px",color:ep.tls_version?.includes("1.3")?"#00e676":"#ffab40",whiteSpace:"nowrap"}}>{ep.tls_version||"—"}</td>
                        <td style={{padding:"8px 10px",color:"#8888aa",maxWidth:140,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ep.cipher_suite||"—"}</td>
                        <td style={{padding:"8px 10px"}}>{ep.cipher_grade?<GradeBadge grade={ep.cipher_grade}/>:"—"}</td>
                        <td style={{padding:"8px 10px",color:ep.forward_secrecy?"#00e676":"#ff5252"}}>{ep.forward_secrecy?"✓":"✗"}</td>
                        <td style={{padding:"8px 10px",color:ep.quantum_safe?"#00e676":"#ff5252"}}>{ep.quantum_safe?"✓ YES":"✗ NO"}</td>
                        <td style={{padding:"8px 10px",color:"#6666aa",fontSize:10}}>{ep.content_type||"—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* CERT-In CBOM */}
          {result.cert_in_cbom?.length>0 && (
            <div>
              <div style={{color:"#a0a0cc",fontSize:10,letterSpacing:2,marginBottom:10}}>
                CERT-IN CBOM ANNEXURE-A — API LAYER ({result.cert_in_cbom.length} components)
              </div>
              <div style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:8,padding:"12px",overflowX:"auto"}}>
                {result.cert_in_cbom.slice(0,10).map((c,i)=>(
                  <div key={i} style={{display:"flex",gap:12,padding:"7px 0",borderBottom:"1px solid #1a1a2e",fontSize:11,flexWrap:"wrap"}}>
                    <span style={{color:"#a78bfa",minWidth:200,fontFamily:"monospace"}}>{c.endpoint?.split("/").slice(-2).join("/")}</span>
                    <span style={{color:"#8888aa"}}>{c.protocol}</span>
                    <span style={{color:"#6666aa"}}>{c.cipher_suite?.substring(0,25)}</span>
                    <span style={{color:c.quantum_safe?"#00e676":"#ff5252",fontWeight:700}}>{c.quantum_safe?"QUANTUM SAFE":"QUANTUM VULNERABLE"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.endpoints_reachable?.length===0 && (
            <div style={{textAlign:"center",padding:"40px",color:"#3a3a5a"}}>
              <div style={{fontSize:36,marginBottom:10}}>🔌</div>
              <div>No reachable API endpoints found at {result.target}</div>
              <div style={{fontSize:11,marginTop:6,color:"#2a2a4a"}}>Try entering a base URL like https://api.yourbank.com</div>
            </div>
          )}
        </div>
      )}

      {!result && !loading && (
        <div style={{textAlign:"center",padding:"60px 0",color:"#3a3a5a"}}>
          <div style={{fontSize:48,marginBottom:12}}>🔌</div>
          <div style={{fontSize:14,letterSpacing:2}}>API ENDPOINT DISCOVERY</div>
          <div style={{fontSize:11,marginTop:8,color:"#2a2a4a"}}>Enter a base URL to discover and scan all API endpoints</div>
          <div style={{marginTop:16,display:"flex",gap:8,justifyContent:"center",flexWrap:"wrap"}}>
            {["https://pnbindia.in","https://sbi.co.in","https://api.example.com"].map(u=>(
              <button key={u} onClick={()=>setUrl(u)} style={{
                background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#6666aa",
                padding:"5px 12px",borderRadius:5,cursor:"pointer",fontFamily:"monospace",fontSize:11}}>
                {u}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── VPN Scanner Panel ─────────────────────────────────────────────────────────
function VPNScanPanel({backendUrl, token}) {
  const [host, setHost]       = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState("");

  const scan = async () => {
    if(!host.trim()) return;
    setLoading(true); setResult(null); setError("");
    try {
      const headers = {"Content-Type":"application/json"};
      if(token && token!=="demo") headers["Authorization"]=`Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/scan/vpn`, {
        method:"POST", headers,
        body: JSON.stringify({hostname: host.trim().replace(/^https?:\/\//,"").split("/")[0]}),
        signal: AbortSignal.timeout(60000)
      });
      if(res.ok) setResult(await res.json());
      else setError(`Scan failed: ${res.status}`);
    } catch(e) { setError(`Error: ${e.message}`); }
    setLoading(false);
  };

  const pqcColor = {QUANTUM_SAFE:"#00e676",PQC_READY:"#c6ff00",TRANSITIONING:"#ff9100",VULNERABLE:"#ff1744",NOT_ASSESSED:"#6666aa"};
  const protoColor = {"TCP":"#60a5fa","UDP":"#a78bfa"};

  return (
    <div style={{padding:"24px 28px",overflowY:"auto",height:"calc(100vh - 56px)"}}>
      <div style={{marginBottom:20}}>
        <div style={{color:"#e0e0ff",fontWeight:800,fontSize:18,letterSpacing:2}}>🛡️ TLS-BASED VPN SCANNER</div>
        <div style={{color:"#6666aa",fontSize:11,marginTop:3}}>Probes IKEv2, OpenVPN, SSL-VPN, WireGuard ports · Problem Statement: "TLS-based VPN" discovery</div>
      </div>

      <div style={{display:"flex",gap:10,marginBottom:20}}>
        <input value={host} onChange={e=>setHost(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&scan()}
          placeholder="pnbindia.in or 192.168.1.1"
          style={{flex:1,background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:7,
            color:"#e0e0ff",fontFamily:"monospace",fontSize:13,padding:"11px 14px",outline:"none"}}/>
        <button onClick={scan} disabled={loading} style={{
          padding:"11px 24px",borderRadius:7,border:"none",cursor:loading?"not-allowed":"pointer",
          background:loading?"#1a1a3a":"linear-gradient(135deg,#0e6655,#1a5276)",
          color:"#fff",fontFamily:"monospace",fontSize:12,fontWeight:700,
          boxShadow:loading?"none":"0 0 20px #0e665540"}}>
          {loading?"🛡️ PROBING...":"🛡️ PROBE VPN PORTS"}
        </button>
      </div>

      {/* Port legend */}
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:16}}>
        {[["UDP/500","IKEv2"],["UDP/4500","IKEv2 NAT-T"],["UDP/1194","OpenVPN"],["TCP/1194","OpenVPN TCP"],
          ["TCP/443","SSL-VPN"],["UDP/51820","WireGuard"],["TCP/1723","PPTP"],["TCP/4433","SSL-VPN Alt"],].map(([p,n])=>(
          <span key={p} style={{background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#6666aa",
            padding:"3px 8px",borderRadius:4,fontSize:10,fontFamily:"monospace"}}>{p} {n}</span>
        ))}
      </div>

      {error && <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",
        padding:"10px 14px",borderRadius:8,marginBottom:16,fontSize:12}}>{error}</div>}

      {result && (
        <div>
          {/* Summary */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:20}}>
            {[
              ["PORTS PROBED", result.summary?.ports_open!==undefined?`${result.ports_probed} total`:"—", "#8c9eff"],
              ["OPEN PORTS", result.summary?.ports_open||0, result.summary?.ports_open>0?"#c6ff00":"#3a5a3a"],
              ["TLS-VPN FOUND", result.summary?.tls_vpn_count||0, result.tls_vpn_found?"#ffab40":"#3a5a3a"],
              ["PQC ISSUES", result.pqc_issues?.length||0, result.pqc_issues?.length>0?"#ff1744":"#00e676"],
            ].map(([l,v,c])=>(
              <div key={l} style={{background:"#08081a",border:`1px solid ${c}20`,borderRadius:8,padding:"12px 14px"}}>
                <div style={{color:"#6666aa",fontSize:9,letterSpacing:2}}>{l}</div>
                <div style={{color:c,fontSize:18,fontWeight:900,fontFamily:"monospace",marginTop:4}}>{v}</div>
              </div>
            ))}
          </div>

          {/* Open ports */}
          {result.open_ports?.length>0 && (
            <div style={{background:"#061a0f",border:"1px solid #00e67620",borderRadius:8,padding:"12px 16px",marginBottom:16}}>
              <div style={{color:"#00e676",fontSize:11,fontWeight:700,marginBottom:8}}>OPEN PORTS DETECTED</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                {result.open_ports.map((p,i)=>(
                  <span key={i} style={{background:"#00e67620",border:"1px solid #00e67640",color:"#00e676",
                    padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{p}</span>
                ))}
              </div>
            </div>
          )}

          {/* PQC Issues */}
          {result.pqc_issues?.length>0 && (
            <div style={{marginBottom:16}}>
              <div style={{color:"#a0a0cc",fontSize:10,letterSpacing:2,marginBottom:10}}>VPN PQC ISSUES</div>
              {result.pqc_issues.map((issue,i)=>(
                <div key={i} style={{background:"#100505",border:`1px solid ${SEV_COLOR[issue.severity]||"#333"}30`,
                  borderLeft:`3px solid ${SEV_COLOR[issue.severity]||"#333"}`,borderRadius:6,padding:"10px 14px",marginBottom:8}}>
                  <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:4}}>
                    <SevBadge sev={issue.severity}/><span style={{color:"#ffcccc",fontSize:12}}>{issue.issue}</span>
                  </div>
                  <div style={{color:"#888",fontSize:11}}>→ {issue.action}</div>
                </div>
              ))}
            </div>
          )}

          {/* Port-by-port results */}
          <div style={{color:"#a0a0cc",fontSize:10,letterSpacing:2,marginBottom:10}}>PORT PROBE RESULTS</div>
          <div style={{overflowX:"auto"}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
              <thead><tr style={{borderBottom:"1px solid #2a2a4a"}}>
                {["Port","Proto","VPN Type","Status","TLS Version","Cipher","PQC Status"].map(h=>(
                  <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1}}>{h}</th>
                ))}
              </tr></thead>
              <tbody>
                {result.vpn_endpoints?.map((ep,i)=>(
                  <tr key={i} style={{borderBottom:"1px solid #1a1a2e",
                    opacity:ep.open?1:0.4}}>
                    <td style={{padding:"8px 10px",color:"#e0e0ff",fontFamily:"monospace",fontWeight:700}}>{ep.port}</td>
                    <td style={{padding:"8px 10px"}}>
                      <span style={{background:`${protoColor[ep.protocol]||"#888"}22`,color:protoColor[ep.protocol]||"#888",
                        padding:"1px 7px",borderRadius:3,fontSize:10,fontWeight:700}}>{ep.protocol}</span>
                    </td>
                    <td style={{padding:"8px 10px",color:"#c0c0e0"}}>{ep.vpn_type}</td>
                    <td style={{padding:"8px 10px",color:ep.open?"#00e676":"#3a3a5a",fontWeight:700}}>{ep.open?"● OPEN":"○ CLOSED"}</td>
                    <td style={{padding:"8px 10px",color:ep.tls_version?.includes("1.3")?"#00e676":"#ffab40"}}>{ep.tls_version||"—"}</td>
                    <td style={{padding:"8px 10px",color:"#8888aa",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{ep.cipher_suite||"—"}</td>
                    <td style={{padding:"8px 10px"}}>
                      <span style={{color:pqcColor[ep.pqc_assessment]||"#888",fontSize:10,fontWeight:700}}>
                        {ep.pqc_assessment||"NOT_ASSESSED"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* CERT-In CBOM for VPN */}
          {result.cert_in_cbom?.length>0 && (
            <div style={{marginTop:16}}>
              <div style={{color:"#a0a0cc",fontSize:10,letterSpacing:2,marginBottom:8}}>
                CERT-IN CBOM — VPN LAYER ({result.cert_in_cbom.length} TLS-VPN components)
              </div>
              {result.cert_in_cbom.map((c,i)=>(
                <div key={i} style={{background:"#08081a",border:"1px solid #1e1e3a",borderRadius:6,
                  padding:"10px 14px",marginBottom:6,display:"flex",gap:12,flexWrap:"wrap",fontSize:11}}>
                  <span style={{color:"#a78bfa",fontFamily:"monospace"}}>{c.endpoint}</span>
                  <span style={{color:"#8888aa"}}>{c.protocol}</span>
                  <span style={{color:"#6666aa"}}>{c.cipher_suite}</span>
                  <span style={{color:c.quantum_safe?"#00e676":"#ff5252",fontWeight:700}}>
                    {c.quantum_safe?"QUANTUM SAFE":"QUANTUM VULNERABLE"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!result && !loading && (
        <div style={{textAlign:"center",padding:"60px 0",color:"#3a3a5a"}}>
          <div style={{fontSize:48,marginBottom:12}}>🛡️</div>
          <div style={{fontSize:14,letterSpacing:2}}>VPN PORT DISCOVERY</div>
          <div style={{fontSize:11,marginTop:8,color:"#2a2a4a"}}>
            Probes {`{IKEv2, OpenVPN, SSL-VPN, WireGuard, PPTP, L2TP}`} on target hostname
          </div>
          <div style={{marginTop:16,display:"flex",gap:8,justifyContent:"center"}}>
            {["pnbindia.in","sbi.co.in","cloudflare.com"].map(h=>(
              <button key={h} onClick={()=>setHost(h)} style={{
                background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#6666aa",
                padding:"5px 12px",borderRadius:5,cursor:"pointer",fontFamily:"monospace",fontSize:11}}>
                {h}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────────
export default function QuantumShield() {
  const [token,      setToken]      = useState("");
  const [user,       setUser]       = useState(null);
  const [authReady,  setAuthReady]  = useState(false); // prevent flash before token check
  const [targets,    setTargets]    = useState("google.com\nexample.com\ncloudflare.com\nexpired.badssl.com\nrc4.badssl.com\n3des.badssl.com");
  const [results,    setResults]    = useState([]);
  const [scanning,   setScanning]   = useState(false);
  const [selected,   setSelected]   = useState(null);
  const [progress,   setProgress]   = useState({current:0,total:0,current_target:""});
  const [backendUrl, setBackendUrl] = useState(import.meta.env.VITE_BACKEND_URL||"http://localhost:8000");
  const [backendOk,  setBackendOk]  = useState(false);
  const [activeView, setActiveView] = useState("scanner");
  const [termLog,    setTermLog]    = useState([]);
  const termRef = useRef(null);

  // On mount: validate any stored token. If valid, restore session. If not, force login.
  useEffect(()=>{
    const storedToken = localStorage.getItem("qs_token")||"";
    const storedUser  = (() => { try { return JSON.parse(localStorage.getItem("qs_user")||"null"); } catch { return null; } })();
    if(!storedToken || !storedUser) {
      // No stored session — show login
      localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
      setAuthReady(true); return;
    }
    // Validate token with backend /me endpoint
    fetch(`${backendUrl}/api/v1/auth/me`, {
      headers:{"Authorization":`Bearer ${storedToken}`},
      signal: AbortSignal.timeout(4000)
    }).then(r => {
      if(r.ok) {
        // Token still valid — restore session
        setToken(storedToken); setUser(storedUser);
      } else {
        // Token expired or invalid — force login
        localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
      }
      setAuthReady(true);
    }).catch(() => {
      // Backend unreachable — if demo token, allow; else clear
      if(storedToken === "demo" && storedUser) {
        setToken(storedToken); setUser(storedUser);
      } else {
        localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
      }
      setAuthReady(true);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[]);

  // Check backend health
  useEffect(()=>{
    fetch(`${backendUrl}/api/v1/health`,{signal:AbortSignal.timeout(3000)})
      .then(r=>r.ok&&setBackendOk(true)).catch(()=>setBackendOk(false));
  },[backendUrl]);

  useEffect(()=>{if(termRef.current)termRef.current.scrollTop=termRef.current.scrollHeight;},[termLog]);

  const addLog=(msg,color="#8888cc")=>setTermLog(l=>[...l.slice(-60),{msg,color,t:new Date().toLocaleTimeString()}]);

  const handleLogin=(tk,u)=>{
    setToken(tk); setUser(u);
    localStorage.setItem("qs_token",tk);
    localStorage.setItem("qs_user",JSON.stringify(u));
  };
  const handleLogout=()=>{
    localStorage.removeItem("qs_token"); localStorage.removeItem("qs_user");
    setToken(""); setUser(null); setResults([]); setSelected(null); setTermLog([]);
  };

  const handleScan=async()=>{
    const list=targets.split("\n").map(t=>t.trim()).filter(Boolean);
    if(!list.length) return;
    setScanning(true);setResults([]);setSelected(null);setTermLog([]);
    addLog("QuantumShield v3.0 — Deep PQC Scan initiated","#a78bfa");
    addLog(`Targets: ${list.length} | Parameters per target: 40+ | User: ${user?.username||"demo"}`,"#6666aa");
    addLog("─".repeat(50),"#2a2a4a");
    setProgress({current:0,total:list.length,current_target:""});
    const newResults=[];
    for(let i=0;i<list.length;i++){
      const t=list[i];
      setProgress({current:i,total:list.length,current_target:t});
      addLog(`[${i+1}/${list.length}] Scanning ${t}...`,"#8888cc");
      addLog(`  → TLS handshake + certificate inspection`,"#4a4a6a");
      addLog(`  → DNS security analysis (CAA, DNSSEC, SPF, DMARC)`,"#4a4a6a");
      addLog(`  → Vulnerability database cross-reference`,"#4a4a6a");
      addLog(`  → PQC scoring (40 parameters)`,"#4a4a6a");
      const r=await performScan(t,backendUrl,token==="demo"?null:token);
      newResults.push(r);setResults([...newResults]);
      const score=r.pqc_assessment?.score||0;const status=r.pqc_assessment?.status||"UNKNOWN";
      const scoreColor=score>=75?"#00e676":score>=50?"#c6ff00":score>=35?"#ff9100":"#ff1744";
      addLog(`  ✓ ${t} — Score: ${score}/100 [${status}]`,scoreColor);
      const vcount=r.vulnerabilities?.length||0;
      if(vcount>0)addLog(`  ⚠ ${vcount} vulnerability/vulnerabilities detected`,"#ff5252");
      addLog(""," ");
    }
    addLog("─".repeat(50),"#2a2a4a");
    const avgScore=Math.round(newResults.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/newResults.length);
    addLog(`Scan complete. ${list.length} assets scanned.`,"#a78bfa");
    addLog(`Avg Score: ${avgScore}/100 | Saved to scan history`,"#c0c0e0");
    setProgress(p=>({...p,current:list.length,current_target:""}));
    setScanning(false);
    if(newResults.length>0) setSelected(newResults[0]);
  };

  const exportCBOM=()=>{
    const report={
      report_metadata:{title:"QuantumShield CBOM Report",generated_at:new Date().toISOString(),
        scanner:"QuantumShield v3.0",nist_reference:["FIPS 203","FIPS 204","FIPS 205"],
        schema:"CycloneDX 1.4",parameters_checked:40,user:user?.username},
      executive_summary:{
        total_assets:results.length,
        quantum_safe:results.filter(r=>r.pqc_assessment?.status==="QUANTUM_SAFE").length,
        pqc_ready:results.filter(r=>r.pqc_assessment?.status==="PQC_READY").length,
        transitioning:results.filter(r=>r.pqc_assessment?.status==="TRANSITIONING").length,
        vulnerable:results.filter(r=>r.pqc_assessment?.status==="VULNERABLE").length,
        avg_score:results.length?Math.round(results.reduce((a,r)=>a+(r.pqc_assessment?.score||0),0)/results.length):0,
      },
      assets:results.map(r=>({
        asset:r.target,tls_version:r.tls_info?.tls_version,cipher_suite:r.tls_info?.cipher_suite,
        cipher_grade:r.tls_info?.cipher_grade,key_exchange:r.tls_info?.key_exchange,
        forward_secrecy:r.tls_info?.forward_secrecy,cert_type:`${r.certificate?.key_type}-${r.certificate?.key_bits}`,
        cert_expiry_days:r.certificate?.days_until_expiry,pqc_score:r.pqc_assessment?.score,
        pqc_status:r.pqc_assessment?.status,vulnerabilities:r.vulnerabilities,
        cbom_components:r.cbom?.components,dns_caa:r.dns?.caa_present,hsts:r.http_headers?.hsts?.present,
      }))
    };
    const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);
    a.download=`quantumshield-cbom-${Date.now()}.json`;a.click();
  };

  const exportPDF = async () => {
    const payload = {
      scan_title: "QuantumShield PQC Security Assessment",
      organization: user?.username ? `Scanned by: ${user.username}` : "QuantumShield Scanner",
      prepared_by: `QuantumShield v2.0 — ${new Date().toLocaleDateString()}`,
      targets: results.map(r => ({
        target: r.target,
        pqc_score: r.pqc_assessment?.score || 0,
        pqc_status: r.pqc_assessment?.status || "UNKNOWN",
        tls_version: r.tls_info?.tls_version,
        cipher_suite: r.tls_info?.cipher_suite,
        key_exchange: r.tls_info?.key_exchange,
        cert_key_type: r.certificate?.key_type,
        cert_key_bits: r.certificate?.key_bits,
        forward_secrecy: r.tls_info?.forward_secrecy,
        days_until_expiry: r.certificate?.days_until_expiry,
        vulnerabilities: r.vulnerabilities || [],
        issues: r.pqc_assessment?.issues || [],
        positives: r.pqc_assessment?.positives || [],
      }))
    };
    try {
      const headers = {"Content-Type":"application/json"};
      if(token && token !== "demo") headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/reports/pdf`, {
        method:"POST", headers, body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000)
      });
      if(res.ok) {
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-Report-${Date.now()}.pdf`;
        a.click();
      } else {
        alert("PDF generation failed. Make sure reportlab is installed on the backend (add to requirements.txt).");
      }
    } catch(_) {
      alert("Cannot reach backend for PDF generation. Ensure backend is running.");
    }
  };

  const exportCSV = async () => {
    try {
      const headers = {"Content-Type":"application/json"};
      if(token && token !== "demo") headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/export/csv`, {
        method:"POST", headers,
        body: JSON.stringify({results}),
        signal: AbortSignal.timeout(15000)
      });
      if(res.ok) {
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-${Date.now()}.csv`;
        a.click();
      } else {
        // Fallback: generate CSV client-side
        const rows = [
          ["Target","Port","TLS Version","Cipher Suite","Cipher Grade","Forward Secrecy","Key Exchange","Cert Type","Cert Bits","Expiry Days","PQC Score","PQC Status","Vulnerabilities","Timestamp"],
          ...results.map(r => [
            r.target, r.port||443,
            r.tls_info?.tls_version||"",
            r.tls_info?.cipher_suite||"",
            r.tls_info?.cipher_grade||"",
            r.tls_info?.forward_secrecy?"Yes":"No",
            r.tls_info?.key_exchange||"",
            r.certificate?.key_type||"",
            r.certificate?.key_bits||"",
            r.certificate?.days_until_expiry||"",
            r.pqc_assessment?.score||"",
            r.pqc_assessment?.status||"",
            (r.vulnerabilities||[]).map(v=>v.name).join("|"),
            r.timestamp||""
          ])
        ];
        const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
        const blob = new Blob([csv], {type:"text/csv"});
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-${Date.now()}.csv`;
        a.click();
      }
    } catch(_) {
      // Pure client-side fallback
      const rows = [
        ["Target","TLS Version","Cipher Suite","PQC Score","PQC Status","Vulnerabilities"],
        ...results.map(r=>[r.target,r.tls_info?.tls_version||"",r.tls_info?.cipher_suite||"",r.pqc_assessment?.score||"",r.pqc_assessment?.status||"",(r.vulnerabilities||[]).map(v=>v.name).join("|")])
      ];
      const csv = rows.map(r=>r.join(",")).join("\n");
      const blob = new Blob([csv],{type:"text/csv"});
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `QuantumShield-${Date.now()}.csv`;
      a.click();
    }
  };

  const exportXML = async () => {
    try {
      const headers = {"Content-Type":"application/json"};
      if(token && token !== "demo") headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`${backendUrl}/api/v1/export/xml`, {
        method:"POST", headers,
        body: JSON.stringify({results}),
        signal: AbortSignal.timeout(15000)
      });
      if(res.ok) {
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `QuantumShield-${Date.now()}.xml`;
        a.click();
      } else {
        throw new Error("Backend XML failed");
      }
    } catch(_) {
      // Client-side XML fallback
      const ts = new Date().toISOString();
      const esc = s => String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
      const lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        `<QuantumShieldReport generated="${ts}" schema="CERT-In-CBOM-v1.0">`,
        ...results.map(r=>[
          `  <Asset target="${esc(r.target)}" port="${r.port||443}">`,
          `    <TLS version="${esc(r.tls_info?.tls_version)}" cipher="${esc(r.tls_info?.cipher_suite)}" grade="${esc(r.tls_info?.cipher_grade)}" forward_secrecy="${r.tls_info?.forward_secrecy||false}"/>`,
          `    <Certificate type="${esc(r.certificate?.key_type)}" bits="${r.certificate?.key_bits||0}" quantum_safe="${r.certificate?.pqc_cert||false}"/>`,
          `    <PQCAssessment score="${r.pqc_assessment?.score||0}" status="${esc(r.pqc_assessment?.status)}"/>`,
          `    <Vulnerabilities count="${(r.vulnerabilities||[]).length}">`,
          ...(r.vulnerabilities||[]).map(v=>`      <Vulnerability name="${esc(v.name)}" cve="${esc(v.cve)}" severity="${esc(v.severity)}"/>`),
          `    </Vulnerabilities>`,
          `  </Asset>`,
        ].join("\n")),
        '</QuantumShieldReport>'
      ];
      const blob = new Blob([lines.join("\n")],{type:"application/xml"});
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `QuantumShield-${Date.now()}.xml`;
      a.click();
    }
  };

  const totalVulns=results.reduce((a,r)=>a+(r.vulnerabilities?.length||0),0);
  const roleColor={Admin:"#a78bfa",Operator:"#60a5fa",Checker:"#34d399"};

  // ── Not logged in ──────────────────────────────────────────────────────────
  if(!authReady) return (
    <div style={{background:"#05050e",minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"monospace"}}>
      <div style={{textAlign:"center"}}>
        <div style={{fontSize:48,marginBottom:16,animation:"none"}}>⚛</div>
        <div style={{color:"#4a4a7a",fontSize:12,letterSpacing:3}}>INITIALISING...</div>
      </div>
    </div>
  );
  if(!token) return <LoginScreen backendUrl={backendUrl} onLogin={handleLogin}/>;

  // ── Main App ───────────────────────────────────────────────────────────────
  const views=[
    {id:"scanner",   label:"⚡ Scanner"},
    {id:"api",       label:"🔌 API Scan"},
    {id:"vpn",       label:"🛡️ VPN Probe"},
    {id:"history",   label:"📋 History"},
    ...(user?.role==="Admin"?[{id:"users",label:"👥 Admin"}]:[]),
    {id:"algorithms",label:"⚛ NIST PQC"},
    {id:"about",     label:"ℹ About"},
  ];

  return (
    <div style={{background:"#05050e",minHeight:"100vh",fontFamily:"'IBM Plex Mono','Courier New',monospace",color:"#e0e0ff",overflow:"hidden"}}>
      {/* Header */}
      <div style={{background:"#07071a",borderBottom:"1px solid #1e1e3a",padding:"0 20px",display:"flex",alignItems:"center",justifyContent:"space-between",height:56,flexShrink:0,boxShadow:"0 1px 20px #7c3aed10"}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:34,height:34,background:"linear-gradient(135deg,#7c3aed,#1d4ed8)",borderRadius:9,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,
            boxShadow:"0 0 16px #7c3aed50"}}>⚛</div>
          <div>
            <div style={{color:"#e0e0ff",fontWeight:900,fontSize:17,letterSpacing:3,
              textShadow:"0 0 20px #7c3aed40"}}>QUANTUMSHIELD</div>
            <div style={{color:"#4a4a7a",fontSize:9,letterSpacing:1}}>PQC SCANNER v3.0 · NIST FIPS 203/204/205 · 40+ PARAMETERS</div>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{display:"flex",gap:2}}>
            {views.map(v=>(
              <button key={v.id} onClick={()=>setActiveView(v.id)} style={{
                background:activeView===v.id?"linear-gradient(135deg,#1e1e3a,#16163a)":"none",
                border:activeView===v.id?"1px solid #3e3e6a":"1px solid transparent",
                color:activeView===v.id?"#c4b5fd":"#5a5a8a",padding:"5px 13px",borderRadius:6,cursor:"pointer",
                fontFamily:"monospace",fontSize:11,letterSpacing:0.5,transition:"all 0.2s",
                boxShadow:activeView===v.id?"0 0 12px #7c3aed30":"none"}}>
                {v.label}
              </button>
            ))}
          </div>
          {results.length>0&&totalVulns>0&&(
            <div style={{background:"#ff174415",border:"1px solid #ff174440",color:"#ff5252",
              padding:"4px 12px",borderRadius:5,fontSize:11,fontFamily:"monospace",
              animation:"none",boxShadow:"0 0 10px #ff174420"}}>
              ⚠ {totalVulns} VULN{totalVulns>1?"S":""}
            </div>
          )}
          {results.length>0&&(
            <div style={{background:"#00e67610",border:"1px solid #00e67630",color:"#00e676",
              padding:"4px 12px",borderRadius:5,fontSize:11,fontFamily:"monospace"}}>
              {results.length} SCANNED
            </div>
          )}
          {/* Backend status */}
          <div style={{display:"flex",alignItems:"center",gap:6,padding:"4px 10px",
            background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:6}}>
            <div style={{width:7,height:7,borderRadius:"50%",
              background:backendOk?"#00e676":"#ffab40",
              boxShadow:`0 0 8px ${backendOk?"#00e676":"#ffab40"}`}}/>
            <span style={{color:backendOk?"#00e676":"#ffab40",fontSize:10,fontWeight:700,letterSpacing:1}}>
              {backendOk?"LIVE":"DEMO"}
            </span>
          </div>
          {/* User chip */}
          <div style={{display:"flex",alignItems:"center",gap:8,padding:"4px 12px",
            background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:6}}>
            <div style={{width:22,height:22,borderRadius:"50%",
              background:`linear-gradient(135deg,${({"Admin":"#ff5252","Operator":"#ffab40","Checker":"#8c9eff","Viewer":"#6666aa"})[user?.role]||"#666"},#1a1a2e)`,
              display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:"#fff"}}>
              {user?.username?.[0]?.toUpperCase()}
            </div>
            <div>
              <div style={{color:"#c0c0e0",fontSize:11,fontWeight:700,lineHeight:1.2}}>{user?.username}</div>
              <div style={{color:({"Admin":"#ff5252","Operator":"#ffab40","Checker":"#8c9eff","Viewer":"#6666aa"})[user?.role]||"#888",fontSize:9,letterSpacing:1}}>{user?.role?.toUpperCase()}</div>
            </div>
            <button onClick={handleLogout} title="Sign out" style={{background:"none",border:"none",
              color:"#3a3a5a",cursor:"pointer",padding:"2px 4px",fontSize:14,lineHeight:1,
              borderRadius:3,transition:"color 0.2s"}}
              onMouseOver={e=>e.target.style.color="#ff5252"}
              onMouseOut={e=>e.target.style.color="#3a3a5a"}>
              ⏏
            </button>
          </div>
        </div>
      </div>

      {activeView==="api"&&(
        <APIScanPanel backendUrl={backendUrl} token={token}/>
      )}

      {activeView==="vpn"&&(
        <VPNScanPanel backendUrl={backendUrl} token={token}/>
      )}

      {activeView==="history"&&(
        <div style={{height:"calc(100vh - 56px)",overflowY:"auto"}}>
          <HistoryPanel backendUrl={backendUrl} token={token} onLoadScan={(r)=>{
            setSelected(r);setResults([r]);setActiveView("scanner");
          }}/>
        </div>
      )}

      {/* User Management View (Admin only) */}
      {activeView==="users"&&user?.role==="Admin"&&(
        <div style={{height:"calc(100vh - 56px)",overflowY:"auto"}}>
          <UserManagement backendUrl={backendUrl} token={token} currentUser={user}/>
        </div>
      )}

      {/* Scanner View */}
      {activeView==="scanner"&&(
        <div style={{display:"grid",gridTemplateColumns:"310px 1fr 460px",height:"calc(100vh - 56px)"}}>
          {/* Left Panel */}
          <div style={{borderRight:"1px solid #1e1e3a",display:"flex",flexDirection:"column",background:"#07071a",overflow:"hidden"}}>
            <div style={{padding:"14px 16px",borderBottom:"1px solid #1e1e3a",flexShrink:0}}>
              <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:8}}>SCAN TARGETS</div>
              <textarea value={targets} onChange={e=>setTargets(e.target.value)}
                placeholder="Enter domains, one per line" style={{
                  width:"100%",height:110,background:"#0a0a1e",border:"1px solid #2a2a4a",
                  borderRadius:7,color:"#e0e0ff",fontFamily:"monospace",fontSize:12,
                  padding:"8px 10px",resize:"none",outline:"none",boxSizing:"border-box"}}/>
              <input value={backendUrl} onChange={e=>setBackendUrl(e.target.value)}
                style={{width:"100%",background:"#0a0a1e",border:"1px solid #2a2a4a",borderRadius:5,
                  color:"#8888aa",fontFamily:"monospace",fontSize:11,padding:"5px 8px",
                  outline:"none",marginTop:6,boxSizing:"border-box"}}/>
              <button onClick={handleScan} disabled={scanning} style={{
                marginTop:8,width:"100%",padding:"10px",borderRadius:7,
                background:scanning?"#1a1a3a":"linear-gradient(135deg,#7c3aed,#2563eb)",
                border:"none",color:"#fff",fontFamily:"monospace",fontSize:13,fontWeight:700,
                cursor:scanning?"not-allowed":"pointer",letterSpacing:2,
                boxShadow:scanning?"none":"0 0 20px #7c3aed50",transition:"all 0.3s"}}>
                {scanning?`⏳ ${progress.current}/${progress.total} SCANNING...`:"⚡ LAUNCH DEEP SCAN"}
              </button>
              {scanning&&(
                <div style={{marginTop:8}}>
                  <div style={{background:"#0a0a1e",borderRadius:3,overflow:"hidden",height:3}}>
                    <div style={{height:"100%",background:"linear-gradient(90deg,#7c3aed,#2563eb)",
                      width:`${(progress.current/progress.total)*100}%`,transition:"width 0.5s"}}/>
                  </div>
                  <div style={{color:"#6666aa",fontSize:10,marginTop:4}}>→ {progress.current_target}</div>
                </div>
              )}
            </div>
            {/* Terminal */}
            <div style={{flex:1,overflowY:"auto",padding:"10px 14px",background:"#050510"}} ref={termRef}>
              {termLog.length===0&&!scanning&&(
                <div style={{color:"#2a2a4a",fontSize:11,lineHeight:1.8}}>
                  <div style={{color:"#3a3a6a",marginBottom:8}}>$ quantumshield --deep-scan --user={user?.username}</div>
                  <div>40+ parameters per target:</div>
                  {["TLS version & cipher analysis","Certificate deep inspection","Key exchange detection","Forward secrecy check","Vulnerability DB cross-ref","DNS security (CAA/DNSSEC)","HTTP security headers","CBOM generation","PQC readiness scoring"].map(l=>(
                    <div key={l}>· {l}</div>
                  ))}
                  <div style={{marginTop:8,color:"#3a3a5a"}}>Scans saved to database ✓</div>
                </div>
              )}
              {termLog.map((l,i)=>(
                <div key={i} style={{fontFamily:"monospace",fontSize:11,lineHeight:1.7,color:l.color,whiteSpace:"pre-wrap"}}>{l.msg}</div>
              ))}
            </div>
            {results.length>0&&(
              <div style={{padding:"10px 14px",borderTop:"1px solid #1e1e3a",flexShrink:0,display:"flex",flexDirection:"column",gap:6}}>
                <button onClick={exportCBOM} style={{width:"100%",padding:"8px",background:"#0a0a1e",
                  border:"1px solid #2a2a5a",color:"#8888cc",borderRadius:7,cursor:"pointer",
                  fontFamily:"monospace",fontSize:11,letterSpacing:1}}>
                  📥 EXPORT CBOM (JSON)
                </button>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
                  <button onClick={exportCSV} style={{padding:"7px",background:"#051a05",
                    border:"1px solid #1e844960",color:"#4ade80",borderRadius:7,cursor:"pointer",
                    fontFamily:"monospace",fontSize:10,letterSpacing:1}}>
                    📊 CSV
                  </button>
                  <button onClick={exportXML} style={{padding:"7px",background:"#050a1a",
                    border:"1px solid #1a527660",color:"#60a5fa",borderRadius:7,cursor:"pointer",
                    fontFamily:"monospace",fontSize:10,letterSpacing:1}}>
                    📋 XML
                  </button>
                </div>
                <button onClick={exportPDF} style={{width:"100%",padding:"8px",
                  background:"linear-gradient(135deg,#6A0DAD18,#1A5276 18)",
                  border:"1px solid #6A0DAD60",color:"#c084fc",borderRadius:7,cursor:"pointer",
                  fontFamily:"monospace",fontSize:11,letterSpacing:1,
                  boxShadow:"0 0 12px #6A0DAD30"}}>
                  📄 EXPORT PDF REPORT
                </button>
              </div>
            )}
          </div>

          {/* Middle Panel */}
          <div style={{borderRight:"1px solid #1e1e3a",overflowY:"auto",padding:"16px"}}>
            {results.length>0?(
              <>
                <SummaryBar results={results}/>
                <div style={{color:"#a0a0cc",fontSize:10,fontWeight:700,letterSpacing:2,marginBottom:10}}>ASSET INVENTORY</div>
                <div style={{overflowX:"auto"}}>
                  <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
                    <thead><tr style={{borderBottom:"1px solid #2a2a4a"}}>
                      {["Asset","TLS","Cipher","Grade","FS","Cert","Expiry","Vulns","Score","Status"].map(h=>(
                        <th key={h} style={{padding:"7px 10px",textAlign:"left",color:"#6666aa",fontSize:10,letterSpacing:1,whiteSpace:"nowrap"}}>{h.toUpperCase()}</th>
                      ))}
                    </tr></thead>
                    <tbody>{results.map((r,i)=>{
                      const pqc=r.pqc_assessment||{};const tls=r.tls_info||{};
                      const cert=r.certificate||{};const vcount=r.vulnerabilities?.length||0;
                      return (
                        <tr key={i} onClick={()=>setSelected(r)} style={{borderBottom:"1px solid #1a1a2e",cursor:"pointer",background:selected?.target===r.target?"#0e0e22":"transparent"}}>
                          <td style={{padding:"9px 10px",color:"#a78bfa",fontFamily:"monospace",fontSize:11}}>{r.target}</td>
                          <td style={{padding:"9px 10px",color:tls.tls_version?.includes("1.3")?"#00e676":"#ffab40",whiteSpace:"nowrap"}}>{tls.tls_version||"—"}</td>
                          <td style={{padding:"9px 10px",color:"#8888aa",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{tls.cipher_suite||"—"}</td>
                          <td style={{padding:"9px 10px"}}>{tls.cipher_grade?<GradeBadge grade={tls.cipher_grade}/>:"—"}</td>
                          <td style={{padding:"9px 10px",color:tls.forward_secrecy?"#00e676":"#ff5252"}}>{tls.forward_secrecy?"✓":"✗"}</td>
                          <td style={{padding:"9px 10px",color:cert.pqc_cert?"#00e676":"#ff5252",whiteSpace:"nowrap"}}>{cert.key_type||"?"}-{cert.key_bits||0}</td>
                          <td style={{padding:"9px 10px",color:cert.days_until_expiry<30?"#ff5252":cert.days_until_expiry<90?"#ffab40":"#6688aa",whiteSpace:"nowrap"}}>{cert.days_until_expiry!=null?`${cert.days_until_expiry}d`:"—"}</td>
                          <td style={{padding:"9px 10px",color:vcount>0?"#ff5252":"#3a5a3a"}}>{vcount>0?`⚠${vcount}`:"✓"}</td>
                          <td style={{padding:"9px 10px"}}><ScoreRing score={pqc.score||0} size={34}/></td>
                          <td style={{padding:"9px 10px"}}><Badge status={pqc.status} small/></td>
                        </tr>
                      );
                    })}</tbody>
                  </table>
                </div>
              </>
            ):( 
              <div style={{display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"80vh"}}>
                <div style={{position:"relative",marginBottom:24}}>
                  <div style={{fontSize:80,lineHeight:1,filter:"drop-shadow(0 0 30px #7c3aed40)"}}>⚛</div>
                  <div style={{position:"absolute",inset:0,background:"radial-gradient(circle,#7c3aed15 0%,transparent 70%)",borderRadius:"50%"}}/>
                </div>
                <div style={{fontSize:18,color:"#3a3a7a",letterSpacing:4,fontWeight:800,marginBottom:8}}>QUANTUMSHIELD v3.0</div>
                <div style={{fontSize:11,color:"#2a2a5a",letterSpacing:2,marginBottom:4}}>40+ PARAMETERS · NIST FIPS 203/204/205</div>
                <div style={{fontSize:10,color:"#2a2a4a",marginBottom:28}}>Logged in as <span style={{color:"#6644aa"}}>{user?.username}</span> · {user?.role}</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap",justifyContent:"center",maxWidth:400}}>
                  {["pnbindia.in","google.com","cloudflare.com","sbi.co.in"].map(t=>(
                    <button key={t} onClick={()=>{setTargets(t);}} style={{
                      background:"#0a0a1e",border:"1px solid #2a2a4a",color:"#6666aa",
                      padding:"5px 12px",borderRadius:5,cursor:"pointer",fontFamily:"monospace",
                      fontSize:11,transition:"all 0.2s"}}
                      onMouseOver={e=>{e.target.style.borderColor="#7c3aed";e.target.style.color="#a78bfa";}}
                      onMouseOut={e=>{e.target.style.borderColor="#2a2a4a";e.target.style.color="#6666aa";}}>
                      {t}
                    </button>
                  ))}
                </div>
                <div style={{fontSize:10,color:"#2a2a4a",marginTop:12}}>↑ click a target to load it, or type your own</div>
              </div>
            )}
          </div>

          {/* Right Panel */}
          <div style={{overflowY:"auto"}}><DetailPanel result={selected} backendUrl={backendUrl} token={token}/></div>
        </div>
      )}

      {/* Algorithms View */}
      {activeView==="algorithms"&&(
        <div style={{overflowY:"auto",height:"calc(100vh - 56px)",padding:"24px 32px",maxWidth:960,margin:"0 auto"}}>
          <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:20}}>NIST POST-QUANTUM CRYPTOGRAPHY STANDARDS — FINAL (2024)</div>
          <div style={{display:"grid",gap:14,marginBottom:28}}>
            {[
              {std:"FIPS 203",name:"ML-KEM",full:"Module Lattice-based Key Encapsulation Mechanism",variants:["ML-KEM-512 (Level 1)","ML-KEM-768 (Level 3) ★ Recommended","ML-KEM-1024 (Level 5)"],replaces:"RSA/ECDH Key Exchange",basis:"Module Learning With Errors (MLWE)",color:"#60a5fa",icon:"🔑"},
              {std:"FIPS 204",name:"ML-DSA",full:"Module Lattice-based Digital Signature Algorithm",variants:["ML-DSA-44 (Level 2)","ML-DSA-65 (Level 3) ★ Recommended","ML-DSA-87 (Level 5)"],replaces:"RSA/ECDSA Digital Signatures",basis:"Module Learning With Errors (MLWE)",color:"#34d399",icon:"✍️"},
              {std:"FIPS 205",name:"SLH-DSA",full:"Stateless Hash-based Digital Signature Algorithm",variants:["SLH-DSA-SHA2-128s/f (Level 1)","SLH-DSA-SHA2-192s/f (Level 3) ★","SLH-DSA-SHA2-256s/f (Level 5)"],replaces:"RSA/ECDSA (conservative, hash-based)",basis:"Hash functions (SPHINCS+)",color:"#a78bfa",icon:"🌳"},
            ].map(algo=>(
              <div key={algo.std} style={{background:"#0a0a1e",border:`1px solid ${algo.color}30`,borderLeft:`4px solid ${algo.color}`,borderRadius:10,padding:"18px 20px"}}>
                <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:10}}>
                  <span style={{background:`${algo.color}22`,color:algo.color,padding:"2px 10px",borderRadius:4,fontSize:11,fontWeight:700,letterSpacing:1,fontFamily:"monospace"}}>{algo.std}</span>
                  <span style={{color:"#e0e0ff",fontWeight:800,fontSize:18}}>{algo.name}</span>
                  <span style={{fontSize:20}}>{algo.icon}</span>
                </div>
                <div style={{color:"#8888aa",fontSize:12,marginBottom:6}}>{algo.full}</div>
                <div style={{color:"#6666aa",fontSize:11,marginBottom:4}}>MATHEMATICAL BASIS: <span style={{color:"#c0c0e0"}}>{algo.basis}</span></div>
                <div style={{color:"#6666aa",fontSize:11,marginBottom:10}}>REPLACES: <span style={{color:"#ffab40"}}>{algo.replaces}</span></div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {algo.variants.map(v=>(
                    <span key={v} style={{background:v.includes("★")?`${algo.color}22`:"#1a1a2e",border:`1px solid ${v.includes("★")?algo.color:"#2a2a4a"}`,color:v.includes("★")?algo.color:"#8888aa",padding:"3px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace"}}>{v}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div style={{background:"#0e0000",border:"1px solid #ff174430",borderRadius:10,padding:"18px 20px"}}>
            <div style={{color:"#ff5252",fontWeight:700,fontSize:13,marginBottom:12}}>⚠ QUANTUM-VULNERABLE ALGORITHMS — HARVEST NOW, DECRYPT LATER RISK</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
              {[["RSA","CRITICAL","Shor's algorithm — any key size","Signatures, Key Exchange"],
                ["ECDSA/ECDH","CRITICAL","Shor's algorithm breaks ECC","Signatures, TLS Key Exchange"],
                ["DH/DSA","CRITICAL","Shor's algorithm breaks DLP","Legacy Key Exchange"],
                ["AES-128","HIGH","Grover's: 64-bit effective security","Symmetric Encryption"],
                ["SHA-1","CRITICAL","Classical collision attacks","Certificate Signing"],
                ["3DES","CRITICAL","SWEET32 + Grover's ~40-bit","Legacy Block Cipher"],
                ["RC4","CRITICAL","Statistical biases (RFC 7465)","Stream Cipher"],
                ["MD5","CRITICAL","Collision attacks since 2004","Hash / Cert Signing"],
                ["RSA<2048","CRITICAL","Classically breakable today","Legacy Certificates"],
              ].map(([algo,risk,reason,use])=>(
                <div key={algo} style={{background:"#0a0000",border:"1px solid #ff174415",borderRadius:7,padding:"10px 12px"}}>
                  <div style={{color:"#ff5252",fontWeight:700,fontSize:13,fontFamily:"monospace"}}>{algo}</div>
                  <div style={{color:"#ff1744",fontSize:10,fontWeight:700,letterSpacing:1,marginTop:3}}>{risk}</div>
                  <div style={{color:"#886666",fontSize:11,marginTop:3}}>{reason}</div>
                  <div style={{color:"#664444",fontSize:10,marginTop:2}}>{use}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* About View */}
      {activeView==="about"&&(
        <div style={{overflowY:"auto",height:"calc(100vh - 56px)",padding:"32px",background:"#05050e"}}>
          <div style={{maxWidth:900,margin:"0 auto"}}>
            {/* Hero */}
            <div style={{textAlign:"center",marginBottom:48,padding:"48px 32px",
              background:"linear-gradient(135deg,#0a0a1e,#12082a)",
              border:"1px solid #2a1a4a",borderRadius:16,
              boxShadow:"0 0 60px #7c3aed15"}}>
              <div style={{fontSize:64,marginBottom:16,filter:"drop-shadow(0 0 20px #7c3aed60)"}}>⚛</div>
              <div style={{color:"#e0e0ff",fontWeight:900,fontSize:28,letterSpacing:4,marginBottom:6}}>QUANTUMSHIELD</div>
              <div style={{color:"#7c3aed",fontWeight:700,fontSize:14,letterSpacing:3,marginBottom:4}}>POST-QUANTUM CRYPTOGRAPHY SCANNER v3.0</div>
              <div style={{color:"#6666aa",fontSize:12,marginBottom:16}}>PNB / PSB Cybersecurity Hackathon 2025-26 · Theme: Quantum-Proof Systems</div>
              <div style={{display:"flex",justifyContent:"center",gap:8,flexWrap:"wrap"}}>
                {[["FIPS 203","ML-KEM","#60a5fa"],["FIPS 204","ML-DSA","#34d399"],["FIPS 205","SLH-DSA","#a78bfa"],
                  ["40+ Params","Per Scan","#ffab40"],["CycloneDX","v1.4 CBOM","#f472b6"]].map(([s,n,c])=>(
                  <div key={s} style={{background:`${c}18`,border:`1px solid ${c}44`,borderRadius:6,padding:"6px 14px",textAlign:"center"}}>
                    <div style={{color:c,fontWeight:700,fontSize:10,letterSpacing:1}}>{s}</div>
                    <div style={{color:`${c}cc`,fontSize:10,marginTop:1}}>{n}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Real-world finding callout */}
            <div style={{background:"#1a0000",border:"1px solid #ff174430",borderLeft:"4px solid #ff1744",
              borderRadius:10,padding:"16px 20px",marginBottom:32}}>
              <div style={{color:"#ff5252",fontWeight:800,fontSize:14,marginBottom:6}}>
                🚨 Real-World Finding: No Site Scores Above 72/100
              </div>
              <div style={{color:"#cc8888",fontSize:12,lineHeight:1.7}}>
                After scanning 75+ sites including Google, Cloudflare, all major Indian banks — <strong style={{color:"#ff8888"}}>nobody is 
                truly quantum-safe yet.</strong> pnbindia.in scored 50/100 on TLS 1.2 with RSA-2048. 
                Maximum observed: 72 (Cloudflare with hybrid PQC). This is why QuantumShield exists.
              </div>
            </div>

            {/* Feature grid */}
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:16}}>CAPABILITIES</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:32}}>
              {[
                {icon:"🔬",title:"Deep TLS Inspection",desc:"Real TLS handshake, cipher grading A–F, TLS version probing via 3 strategies, key exchange detection.",color:"#60a5fa"},
                {icon:"📜",title:"X.509 Certificate Audit",desc:"25+ certificate fields: key type/bits, expiry, CT logs, OCSP, SANs, key usage, self-signed detection.",color:"#34d399"},
                {icon:"⚛",title:"PQC Score Engine (0–100)",desc:"40+ parameters, NIST-aligned scoring. Quantum Safe / PQC Ready / Transitioning / Vulnerable badges.",color:"#a78bfa"},
                {icon:"🛡️",title:"12-CVE Vulnerability DB",desc:"POODLE, BEAST, SWEET32, RC4, FREAK, LOGJAM, DROWN, NULL_CIPHER, MD5_HASH, HNDL and more.",color:"#f472b6"},
                {icon:"🌐",title:"DNS Security Analysis",desc:"CAA records, DNSSEC, IPv4/IPv6, SPF, DMARC. Flags missing controls that enable cert mis-issuance.",color:"#ffab40"},
                {icon:"🔒",title:"HTTP Security Headers",desc:"HSTS, CSP, X-Frame-Options, Referrer-Policy, COOP, COEP — with specific fix recommendations.",color:"#fb923c"},
                {icon:"📊",title:"CBOM (CycloneDX v1.4)",desc:"CycloneDX-compliant Cryptographic Bill of Materials. JSON + PDF export for GRC tool integration.",color:"#22d3ee"},
                {icon:"🤖",title:"AI Explanations (GPT-4o)",desc:"Plain-English analysis for CEO brief, board report, or technical team. One click per scan.",color:"#c084fc"},
                {icon:"⚡",title:"Quantum Attack Simulator",desc:"Animates Shor's Algorithm attack on any scanned target. Shows break time classical vs quantum.",color:"#ff5252"},
                {icon:"🔐",title:"Auth + RBAC + Audit Trail",desc:"JWT auth, bcrypt passwords, SQLite DB. Admin/Operator/Checker/Viewer roles. Full audit log.",color:"#4ade80"},
              ].map(({icon,title,desc,color})=>(
                <div key={title} style={{background:"#08081a",border:`1px solid ${color}20`,
                  borderLeft:`3px solid ${color}`,borderRadius:9,padding:"14px 16px",
                  display:"flex",gap:12,transition:"border-color 0.2s"}}>
                  <div style={{fontSize:22,flexShrink:0}}>{icon}</div>
                  <div>
                    <div style={{color:"#e0e0ff",fontWeight:700,fontSize:12,marginBottom:4}}>{title}</div>
                    <div style={{color:"#6666aa",fontSize:11,lineHeight:1.6}}>{desc}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Tech stack */}
            <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:16}}>TECH STACK</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:32}}>
              {[
                ["Python 3.11","Backend","#3b82f6"],["FastAPI","API Framework","#009688"],
                ["SQLAlchemy","ORM + SQLite","#ff9800"],["JWT + bcrypt","Auth Security","#e91e63"],
                ["React 18","Frontend","#61dafb"],["Vite","Build Tool","#646cff"],
                ["reportlab","PDF Engine","#ff5722"],["OpenAI GPT-4o","AI Layer","#10a37f"],
              ].map(([tech,role,color])=>(
                <div key={tech} style={{background:"#0a0a1e",border:`1px solid ${color}30`,borderRadius:7,padding:"10px 12px",textAlign:"center"}}>
                  <div style={{color,fontWeight:700,fontSize:11,fontFamily:"monospace"}}>{tech}</div>
                  <div style={{color:"#4a4a7a",fontSize:10,marginTop:3}}>{role}</div>
                </div>
              ))}
            </div>

            {/* Deploy info */}
            <div style={{background:"#0a0a1e",border:"1px solid #1e1e3a",borderRadius:10,padding:"16px 20px",textAlign:"center"}}>
              <div style={{color:"#6666aa",fontSize:10,letterSpacing:2,marginBottom:10}}>DEPLOYMENT</div>
              <div style={{display:"flex",justifyContent:"center",gap:20,flexWrap:"wrap",marginBottom:10}}>
                {[["Frontend","Vercel","#000000","Always-on CDN"],["Backend","Render","#46E3B7","Free tier + UptimeRobot"],
                  ["Database","SQLite","#003B57","Auto-created on startup"],["CI/CD","GitHub","#f0f0f0","Auto-deploy on push"]].map(([layer,service,c,note])=>(
                  <div key={layer} style={{textAlign:"center"}}>
                    <div style={{color:"#8888aa",fontSize:9,letterSpacing:1}}>{layer.toUpperCase()}</div>
                    <div style={{color:"#e0e0ff",fontWeight:700,fontSize:13,fontFamily:"monospace"}}>{service}</div>
                    <div style={{color:"#4a4a7a",fontSize:10}}>{note}</div>
                  </div>
                ))}
              </div>
              <div style={{color:"#3a3a5a",fontSize:10}}>Built for the PNB/PSB Cybersecurity Hackathon 2025-26</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
