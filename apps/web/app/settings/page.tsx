"use client";

export const dynamic = "force-dynamic";

import { useState, useEffect } from "react";
import { useSession } from "next-auth/react";
import { Key, Plus, Trash2, Shield, Lock, AlertCircle, Cpu, Check } from "lucide-react";
import Link from "next/link";

interface Provider {
  id: string;
  name: string;
}

interface UserKey {
  id: string;
  provider: string;
  is_active: boolean;
}

export default function SettingsPage() {
  const sessionData = useSession() || {};
  const { data: session, status } = sessionData as any;
  const [providers, setProviders] = useState<Provider[]>([]);
  const [userKeys, setUserKeys] = useState<UserKey[]>([]);
  const [selectedProvider, setSelectedProvider] = useState("");
  const [keyValue, setKeyValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    fetch(process.env.NEXT_PUBLIC_API_URL + "/api/v1/ai/providers")
      .then(res => res.json())
      .then(data => setProviders(data))
      .catch(() => setError("Failed to load providers."));
  }, []);

  useEffect(() => {
    if (session?.user) {
      loadKeys();
    }
  }, [session]);

  const loadKeys = () => {
    fetch(process.env.NEXT_PUBLIC_API_URL + "/api/v1/user/api-keys")
      .then(res => {
        if (!res.ok) throw new Error("Failed to load keys");
        return res.json();
      })
      .then(data => setUserKeys(data))
      .catch(err => console.error(err));
  };

  const handleAddKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProvider || !keyValue) return;
    
    setLoading(true);
    setError(null);
    setSuccess(null);
    
    try {
      const res = await fetch(process.env.NEXT_PUBLIC_API_URL + "/api/v1/user/api-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: selectedProvider, plain_key: keyValue })
      });
      
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || "Failed to add key");
      }
      
      setSuccess("Key securely added and encrypted.");
      setKeyValue("");
      loadKeys();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteKey = async (id: string) => {
    try {
      const res = await fetch(process.env.NEXT_PUBLIC_API_URL + `/api/v1/user/api-keys/${id}`, {
        method: "DELETE"
      });
      if (!res.ok) throw new Error("Failed to delete key");
      setSuccess("Key successfully deleted.");
      loadKeys();
    } catch (err: any) {
      setError(err.message);
    }
  };

  if (status === "loading") {
    return <div style={{ minHeight: "100vh", background: "#0A0A0F", display: "flex", alignItems: "center", justifyContent: "center" }}><div style={{ width: 40, height: 40, border: "3px solid #C9A84C22", borderTopColor: "#C9A84C", borderRadius: "50%", animation: "spin 1s linear infinite" }} /></div>;
  }

  if (status === "unauthenticated") {
    return (
      <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <Shield size={64} color="#E74C3C" style={{ marginBottom: 20 }} />
        <h1 style={{ fontSize: 24, fontWeight: 800, marginBottom: 8 }}>Authentication Required</h1>
        <p style={{ color: "#A8A8C4", marginBottom: 24 }}>You must be signed in to manage your API keys.</p>
        <Link href="/" style={{ background: "#1E1E2E", padding: "10px 24px", borderRadius: 8, color: "#fff", textDecoration: "none" }}>Go Home</Link>
      </div>
    );
  }

  const cardStyle = { background: "#12121E", border: "1px solid #1E1E2E", borderRadius: 12, padding: 24 };

  return (
    <div style={{ minHeight: "100vh", background: "#0A0A0F", color: "#F0F0F8", fontFamily: "system-ui, sans-serif" }}>
      <style>{`@keyframes spin { 100% { transform: rotate(360deg); } }`}</style>
      
      <nav style={{ padding: "18px 40px", borderBottom: "1px solid #1A1A2E", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(10,10,15,0.9)" }}>
        <Link href="/" style={{ color: "#C9A84C", fontWeight: 900, fontSize: 20, letterSpacing: 1, textDecoration: "none" }}>◆ AegisML</Link>
      </nav>

      <main style={{ maxWidth: 800, margin: "0 auto", padding: "60px 24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 40 }}>
          <div style={{ background: "#C9A84C22", padding: 12, borderRadius: 12 }}><Key size={28} color="#C9A84C" /></div>
          <div>
            <h1 style={{ fontSize: 28, fontWeight: 800, margin: 0 }}>API Key Management</h1>
            <p style={{ color: "#A8A8C4", margin: "4px 0 0 0", fontSize: 14 }}>Manage your personal AI provider keys for custom scanning limits.</p>
          </div>
        </div>

        {error && <div style={{ background: "#E74C3C15", border: "1px solid #E74C3C40", color: "#E74C3C", padding: 16, borderRadius: 8, display: "flex", alignItems: "center", gap: 8, marginBottom: 24 }}><AlertCircle size={18} /> {error}</div>}
        {success && <div style={{ background: "#2ECC7115", border: "1px solid #2ECC7140", color: "#2ECC71", padding: 16, borderRadius: 8, display: "flex", alignItems: "center", gap: 8, marginBottom: 24 }}><Check size={18} /> {success}</div>}

        <div style={{ display: "grid", gap: 24 }}>
          {/* Add Key Section */}
          <div style={cardStyle}>
            <h2 style={{ fontSize: 18, fontWeight: 700, margin: "0 0 16px 0", display: "flex", alignItems: "center", gap: 8 }}><Plus size={18} color="#C9A84C" /> Add New Key</h2>
            <form onSubmit={handleAddKey} style={{ display: "grid", gap: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 13, color: "#8888AA", marginBottom: 6 }}>Provider</label>
                <select 
                  value={selectedProvider} 
                  onChange={e => setSelectedProvider(e.target.value)}
                  style={{ width: "100%", padding: "12px", background: "#0D0D18", border: "1px solid #2A2A3E", borderRadius: 8, color: "#fff", outline: "none" }}
                  required
                >
                  <option value="" disabled>Select AI Provider</option>
                  {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
              
              <div>
                <label style={{ display: "block", fontSize: 13, color: "#8888AA", marginBottom: 6 }}>API Key</label>
                <div style={{ position: "relative" }}>
                  <Lock size={16} color="#555577" style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)" }} />
                  <input 
                    type="password" 
                    placeholder="sk-..." 
                    value={keyValue}
                    onChange={e => setKeyValue(e.target.value)}
                    style={{ width: "100%", padding: "12px 12px 12px 40px", background: "#0D0D18", border: "1px solid #2A2A3E", borderRadius: 8, color: "#fff", outline: "none" }}
                    required
                  />
                </div>
                <p style={{ fontSize: 12, color: "#555577", marginTop: 8 }}>Keys are encrypted using AES-256 before being stored in the database.</p>
              </div>

              <button 
                type="submit" 
                disabled={loading}
                style={{ background: "linear-gradient(135deg, #C9A84C, #E4C46B)", color: "#000", padding: "12px", borderRadius: 8, fontWeight: 700, border: "none", cursor: loading ? "not-allowed" : "pointer" }}
              >
                {loading ? "Encrypting & Saving..." : "Save API Key"}
              </button>
            </form>
          </div>

          {/* Stored Keys */}
          <div style={cardStyle}>
            <h2 style={{ fontSize: 18, fontWeight: 700, margin: "0 0 16px 0", display: "flex", alignItems: "center", gap: 8 }}><Shield size={18} color="#C9A84C" /> Your Encrypted Keys</h2>
            
            {userKeys.length === 0 ? (
              <p style={{ color: "#555577", fontSize: 14, margin: 0, textAlign: "center", padding: 32, background: "#0D0D18", borderRadius: 8 }}>No custom API keys stored.</p>
            ) : (
              <div style={{ display: "grid", gap: 12 }}>
                {userKeys.map(key => {
                  const providerName = providers.find(p => p.id === key.provider)?.name || key.provider;
                  return (
                    <div key={key.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px", background: "#0D0D18", border: "1px solid #2A2A3E", borderRadius: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <Cpu size={20} color="#8888AA" />
                        <div>
                          <p style={{ margin: 0, fontWeight: 600, fontSize: 15 }}>{providerName}</p>
                          <p style={{ margin: 0, color: "#2ECC71", fontSize: 12 }}>Active & Encrypted</p>
                        </div>
                      </div>
                      <button 
                        onClick={() => handleDeleteKey(key.id)}
                        style={{ background: "#E74C3C15", border: "none", color: "#E74C3C", padding: "8px 12px", borderRadius: 6, cursor: "pointer", display: "flex", alignItems: "center", gap: 6, fontSize: 13, fontWeight: 600 }}
                      >
                        <Trash2 size={14} /> Remove
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
