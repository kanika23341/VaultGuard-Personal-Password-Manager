import { useEffect, useMemo, useState } from "react";
import {ShieldCheck, LayoutDashboard, KeyRound, Settings, Search, Plus, LockKeyhole, Eye, EyeOff, Copy, Pencil, Trash2, Globe, LogOut, X, ArrowUpRight, Shield, Check, LoaderCircle,} from "lucide-react";
import "./App.css";
const API="http://127.0.0.1:8000"

async function request(path, options={}, token="") {
    const response=await fetch(`${API}${path}`,{
        ...options,
        headers:{
            ...(options.body?{"Content-Type":"application/json"}:{}),
            ...(token?{Authorization: `Bearer ${token}`}:{}),
            ...options.headers,
        },
    });
    if(!response.ok){
        const body=await response.json().catch(()=>({}));
        throw new Error(body.detail || `Request failed ($(response.status})`);
    }
    if(response.status===204) return null;
    return response.json();
}

const emptyForm={
    site: "",
    username:"",
    password:"",
    url:"",
    notes:"",
};

export default function App(){
    const[screen, setScreen]=useState("loading");
    const[mode, setMode]=useState("unlock");
    const [masterPassword, setMasterPassword] = useState("");
    const [token, setToken] = useState("");
    const [credentials, setCredentials] = useState([]);
    const [query, setQuery] = useState("");
    const [modal, setModal] = useState(false);
    const [editing, setEditing] = useState(null);
    const [form, setForm] = useState(emptyForm);
    const [revealed, setRevealed] = useState({});
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [notice, setNotice] = useState("");
    const [activePage, setActivePage] = useState("dashboard");

    async function loadCredentials(sessionToken=token){
        const data=await request("/credentials",{},sessionToken);
        setCredentials(data);
    }
    async function checkVault() {
        try{
            await request("/health");
            const response=await fetch(`${API}/vault/status`);
            if(response.ok){
                const data=await response.json();
                setMode(data.exists?"unlock":"setup");
            }
            else if(response.status==404){
                setMode("unlock");
            }
            else{
                setMode("unlock");
            }
            setScreen("auth");
        }
        catch(err){
            console.error(err);
            setError("Can't reach backend");
            setMode("unlock");
            setScreen("auth");
        }
    }
    useEffect(()=>{
        checkVault();
    },[]);
    async function authenticate(event) {
        event.preventDefault();
        setError("");
        setBusy(true);
        try{
            if(mode==="setup"){
                await request("/vault/setup",{
                    method:"POST",
                    body: JSON.stringify({master_password: masterPassword}),
                });
                setNotice("Vault created unlock with master password");
                setMode("unlock");
                setMasterPassword("");
            }
            else{
                const result= await request("/vault/unlock",{
                    method:"POST",
                    body: JSON.stringify({master_password: masterPassword}),
                });
                setToken(result.access_token);
                await loadCredentials(result.access_token);
                setMasterPassword("");
                setScreen("dashboard");
                setNotice("Vault unlocked");
            }
        }
        catch(err){
            setError(err.message);
        }
        finally{
            setBusy(false);
        }
    }
    async function lockVault() {
        try{
            if(token){
                await request("/vault/lock", {method:"POST"}, token);
            }
        }
        catch{

        }
        setToken("");
        setCredentials([]);
        setRevealed({});
        setScreen("auth");
        setMode("unlock");
        setNotice("Vault locked.");
        setError("");
    }

    function openNewCredential(){
        setEditing(null);
        setForm(emptyForm);
        setError("");
        setModal(true);
    }

    function openEditCredential(item){
        setEditing(item);
        setForm({
            site: item.site||"",
            username: item.username || "",
            password: item.password || "",
            url: item.url || "",
            notes: item.notes || "",
        });
        setError("");
        setModal(true);
    }

    async function saveCredential(event) {
        event.preventDefault();
        setBusy(true);
        setError("");
        try{
            if(editing){
                await request(`/credentials/${editing.id}`,{
                    method:"PUT",
                    body:JSON.stringify(form),
                }, token);
                setNotice("Credential updated");
            }
            else{
                await request("/credentials",{
                    method:"POST",
                    body: JSON.stringify(form),
                },token);
                setNotice("Credential saved");
            }
            await loadCredentials();
            setModal(false);
            setEditing(null);
            setForm(emptyForm);
        }
        catch(err){
            setError(err.message);
        }
        finally{
            setBusy(false);
        }
    }

    async function deleteCredential(item) {
        if(!window.confirm(`Delete the saved login for ${item.site}?`)) return;
        setError("");
        try{
            await request(`/credentials/${item.id}`, {method:"DELETE"}, token);
            setCredentials((current)=>current.filter((entry)>entry.id!==item.id));
            setNotice("Credential deleted");
        }
        catch(err){
            setError(err.message);
        }
    }

    async function copyText(value, label) {
        try {
            await navigator.clipboard.writeText(value || "");
            setNotice(`${label} copied to clipboard.`);
        } 
        catch {
            setError("Clipboard access failed. Check your browser permissions.");
        } 
    }

    const filtered = useMemo(() => {
        const term = query.trim().toLowerCase();
        if (!term) return credentials;
        return credentials.filter((item) => [item.site, item.username, item.url, item.notes].some((value) => (value || "").toLowerCase().includes(term)));
    }, [credentials, query]);

    if(screen==="loading"){
        return <div className="loading-screen"><LoaderCircle className="spin" /> Loading VaultGuard...</div>;
    }
    if(screen==="auth"){
        return(
            <main className="auth-screen">
                <div className="auth-brand">
                    <div className="brand-icon"><ShieldCheck size={25} /></div>
                    <span>Vault<span className="brand-accent">Guard</span></span>
                </div>
                <section className="auth-card">
                    <div className="auth-symbol"><LockKeyhole size={27} /></div>
                    <p className="eyebrow">YOUR PERSONAL VAULT</p>
                    <h1>{mode === "setup" ? "Create your vault" : "Welcome back"}</h1>
                    <p className="muted">
                        {mode === "setup" ? "Choose a strong master password to protect your saved credentials." : "Unlock your encrypted vault to access your saved logins."}
                    </p>
                    <form onSubmit={authenticate}>
                        <label htmlFor="master-password">Master password</label>
                        <input id="master-password" type="password" autoComplete={mode === "setup" ? "new-password" : "current-password"} minLength={mode === "setup" ? 12 : undefined} required value={masterPassword} onChange={(e) => setMasterPassword(e.target.value)} placeholder={mode === "setup" ? "At least 12 characters" : "Enter master password"}/>
                        {error && <p className="error-message">{error}</p>}
                        {notice && <p className="success-message">{notice}</p>}
                        <button className="primary-button full-button" disabled={busy}>
                            {busy ? <LoaderCircle className="spin" size={17} /> : <LockKeyhole size={17} />}
                            {busy ? "Please wait..." : mode === "setup" ? "Create vault" : "Unlock vault"}
                        </button>
                    </form>
                    <div className="auth-foot"><Shield size={15} /> Your vault is protected with encryption.</div>
                </section>
                <p className="auth-caption">VAULTGUARD · PERSONAL CREDENTIAL MANAGER</p>
            </main>
        );
    }

    return(
        <div className="app-shell">
            <aside className="sidebar">
                <div className="sidebar-brand">
                    <div className="brand-icon"><ShieldCheck size={23} /></div>
                    <span>Vault<span className="brand-accent">Guard</span></span>
                </div>
                <p className="nav-label">WORKSPACE</p>
                <button className={`nav-item ${activePage === "dashboard" ? "active" : ""}`} onClick={() => setActivePage("dashboard")}>
                    <LayoutDashboard size={18} /> Dashboard
                </button>
                <button className={`nav-item ${activePage === "credentials" ? "active" : ""}`} onClick={() => setActivePage("credentials")}>
                    <KeyRound size={18} /> All credentials <span className="nav-count">{credentials.length}</span>
                </button>
                <div className="sidebar-bottom">
                    <div className="vault-status"><span className="status-dot" /><div><strong>Vault unlocked</strong><small>Encrypted storage</small></div></div>
                    <button className="nav-item lock-button" onClick={lockVault}><LogOut size={18} /> Lock vault</button>
                    <p className="sidebar-version">VAULTGUARD</p>
                </div>
            </aside>
            <main className="main-area">
                <header className="topbar">
                    <div className="breadcrumbs">VaultGuard <span>/</span> {activePage === "dashboard" ? "Dashboard" : "Credentials"}</div>
                    <div className="topbar-right"><span className="secure-indicator"><ShieldCheck size={15} /> Session active</span><button className="avatar" title="Lock vault" onClick={lockVault}>V</button></div>
                </header>
                <div className="page-content">
                    <div className="welcome-row">
                        <div>
                            <p className="eyebrow">PERSONAL WORKSPACE</p>
                            <h1>{activePage === "dashboard" ? "Your vault" : "All credentials"}</h1>
                            <p className="muted">Manage your saved logins in one secure place.</p>
                        </div>
                        <button className="primary-button" onClick={openNewCredential}><Plus size={18} /> Add credential</button>
                    </div>
                    {notice && <div className="notice"><Check size={16} /> {notice}<button onClick={() => setNotice("")}><X size={15} /></button></div>}
                    {error && <div className="error-banner">{error}<button onClick={() => setError("")}><X size={15} /></button></div>}
                    
                    <section className="stats-grid">
                        <div className="stat-card"><div className="stat-icon purple"><KeyRound size={19} /></div><p>Total credentials</p><strong>{credentials.length}</strong><small>Saved in your vault</small></div>
                        <div className="stat-card"><div className="stat-icon green"><ShieldCheck size={19} /></div><p>Vault status</p><strong className="status-text">Protected</strong><small>Session authenticated</small></div>
                        <div className="stat-card"><div className="stat-icon blue"><Globe size={19} /></div><p>Websites</p><strong>{new Set(credentials.map((item) => item.site)).size}</strong><small>Unique accounts</small></div>
                    </section>
                    <section className="credentials-section">
                        <div className="section-heading">
                            <div><h2>{activePage === "dashboard" ? "Your credentials" : "All saved logins"}</h2><p className="muted">Access and manage your saved accounts.</p></div>
                            <div className="search-box"><Search size={17} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search credentials..." /></div>
                        </div>
                        {filtered.length === 0 ? (
                            <div className="empty-state">
                                <div className="empty-icon"><KeyRound size={25} /></div>
                                <h3>{query ? "No matching credentials" : "Your vault is ready"}</h3>
                                <p>{query ? "Try another search term." : "Add your first login to get started. Your credentials will be encrypted before being stored."}</p>
                                {!query && <button className="primary-button" onClick={openNewCredential}><Plus size={17} /> Add your first credential</button>}
                            </div>
                        ) : (
                        <div className="credential-grid">
                            {filtered.map((item) => (
                                <article className="credential-card" key={item.id}>
                                    <div className="credential-card-top">
                                        <div className="site-icon">{(item.site || "?").slice(0, 1).toUpperCase()}</div>
                                        <div className="site-info"><h3>{item.site}</h3><p>{item.url || "No website URL"}</p></div>
                                        <button className="icon-button" title="Edit credential" onClick={() => openEditCredential(item)}><Pencil size={16} /></button>
                                    </div>
                                    <div className="credential-field"><span>USERNAME</span><div><p>{item.username}</p><button className="icon-button small" title="Copy username" onClick={() => copyText(item.username, "Username")}><Copy size={15} /></button></div></div>
                                    <div className="credential-field"><span>PASSWORD</span><div><p className="password-value">{revealed[item.id] ? item.password : "••••••••••••"}</p><button className="icon-button small" title={revealed[item.id] ? "Hide password" : "Reveal password"} onClick={() => setRevealed((old) => ({ ...old, [item.id]: !old[item.id] }))}>{revealed[item.id] ? <EyeOff size={15} /> : <Eye size={15} />}</button><button className="icon-button small" title="Copy password" onClick={() => copyText(item.password, "Password")}><Copy size={15} /></button></div></div>
                                    {item.notes && <p className="credential-notes">{item.notes}</p>}
                                    <div className="credential-card-footer"><span><LockKeyhole size={13} /> Encrypted at rest</span><button className="delete-button" onClick={() => deleteCredential(item)}><Trash2 size={14} /> Delete</button></div>
                                    </article>
                        )
                        )
                    }
                </div>
            )}
        </section>
        </div>
        </main>
        {modal && (
            <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setModal(false); }}>
                <section className="credential-modal">
                    <div className="modal-heading"><div><p className="eyebrow">{editing ? "UPDATE DETAILS" : "NEW LOGIN"}</p><h2>{editing ? "Edit credential" : "Add a credential"}</h2></div><button className="icon-button" onClick={() => setModal(false)}><X size={20} /></button></div>
                    <p className="muted">Enter the account details you want to keep in your vault.</p>
                    <form onSubmit={saveCredential}>
                        <label htmlFor="site">Website or service *</label>
                        <input id="site" required maxLength={200} value={form.site} onChange={(e) => setForm({ ...form, site: e.target.value })} placeholder="e.g. GitHub" />
                        <label htmlFor="username">Username or email *</label>
                        <input id="username" required maxLength={500} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="you@example.com" />
                        <label htmlFor="password">Password *</label>
                        <input id="password" type="password" required maxLength={5000} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} placeholder="Enter password" />
                        <label htmlFor="url">Website URL</label>
                        <input id="url" type="url" maxLength={2000} value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://example.com" />
                        <label htmlFor="notes">Notes</label>
                        <textarea id="notes" rows="3" maxLength={5000} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} placeholder="Optional notes" />
                            {error && <p className="error-message">{error}</p>}
                            <div className="modal-actions"><button type="button" className="secondary-button" onClick={() => setModal(false)}>Cancel</button><button className="primary-button" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <Check size={16} />}{busy ? "Saving..." : editing ? "Save changes" : "Save credential"}</button></div>
                    </form>
                </section>
            </div>
        )}
    </div>
    );
}