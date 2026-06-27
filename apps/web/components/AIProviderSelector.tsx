"use client";

import React, { useState, useEffect } from "react";
import { Check, ChevronDown, Lock, ShieldAlert, Cpu } from "lucide-react";

interface Provider {
  id: string;
  name: string;
  models: string[];
}

interface UserKey {
  id: string;
  provider: string;
  is_active: boolean;
}

interface AIProviderSelectorProps {
  onSelect: (provider: string, model: string, key: string | null) => void;
  disabled?: boolean;
}

export function AIProviderSelector({ onSelect, disabled }: AIProviderSelectorProps) {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [userKeys, setUserKeys] = useState<UserKey[]>([]);
  
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [selectedModel, setSelectedModel] = useState<string>("");
  const [customKey, setCustomKey] = useState<string>("");
  const [useStoredKey, setUseStoredKey] = useState<boolean>(true);

  useEffect(() => {
    // Fetch providers
    fetch((process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000") + "/api/v1/ai/providers")
      .then(res => res.json())
      .then(data => {
        setProviders(data);
        if (data.length > 0) {
          setSelectedProvider(data[0].id);
          setSelectedModel(data[0].models[0]);
        }
      })
      .catch(err => console.error("Failed to load providers:", err));

    // Fetch user keys (Requires authentication context if implemented)
    // If not authenticated, userKeys will be empty
    fetch("/api/auth/session")
      .then(res => res.json())
      .then(session => {
        if (session?.user?.id) {
            // we should have a way to fetch the user keys from backend
            fetch((process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000") + "/api/v1/user/api-keys")
              .then(res => {
                  if (res.ok) return res.json();
                  return [];
              })
              .then(data => setUserKeys(data))
              .catch(() => {});
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    onSelect(
      selectedProvider, 
      selectedModel, 
      useStoredKey ? null : (customKey || null)
    );
  }, [selectedProvider, selectedModel, customKey, useStoredKey]);

  if (providers.length === 0) return null;

  const currentProviderObj = providers.find(p => p.id === selectedProvider);
  const hasStoredKey = userKeys.some(k => k.provider === selectedProvider && k.is_active);

  return (
    <div style={{ marginTop: 24, padding: "16px", background: "rgba(201,168,76,0.03)", border: "1px solid rgba(201,168,76,0.15)", borderRadius: 12, textAlign: "left", direction: "ltr" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <Cpu size={16} color="#C9A84C" />
        <span style={{ fontSize: 13, fontWeight: 600, color: "#C9A84C", textTransform: "uppercase", letterSpacing: 1 }}>AI Judge Engine</span>
      </div>
      
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {/* Provider Select */}
        <div>
          <label style={{ display: "block", fontSize: 12, color: "#8888AA", marginBottom: 6 }}>Provider</label>
          <select 
            disabled={disabled}
            value={selectedProvider} 
            onChange={e => {
              setSelectedProvider(e.target.value);
              const prov = providers.find(p => p.id === e.target.value);
              if (prov && prov.models.length > 0) setSelectedModel(prov.models[0]);
            }}
            style={{ width: "100%", padding: "10px 12px", background: "#0D0D18", border: "1px solid #232326", borderRadius: 8, color: "#E0E0E8", fontSize: 14, outline: "none" }}
          >
            {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>

        {/* Model Select */}
        <div>
          <label style={{ display: "block", fontSize: 12, color: "#8888AA", marginBottom: 6 }}>Model</label>
          <select 
            disabled={disabled}
            value={selectedModel} 
            onChange={e => setSelectedModel(e.target.value)}
            style={{ width: "100%", padding: "10px 12px", background: "#0D0D18", border: "1px solid #232326", borderRadius: 8, color: "#E0E0E8", fontSize: 14, outline: "none" }}
          >
            {currentProviderObj?.models.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
      </div>

      <div style={{ marginTop: 16 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "#A0A0C0", cursor: "pointer" }}>
          <input 
            type="checkbox" 
            checked={useStoredKey} 
            onChange={(e) => setUseStoredKey(e.target.checked)}
            disabled={disabled}
            style={{ accentColor: "#C9A84C" }}
          />
          Use system/stored API Key {hasStoredKey && <span style={{ background: "#C9A84C22", color: "#C9A84C", padding: "2px 6px", borderRadius: 4, fontSize: 10 }}>Personal Key Found</span>}
        </label>

        {!useStoredKey && (
          <div style={{ marginTop: 10, position: "relative" }}>
            <Lock size={14} color="#71717A" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
            <input 
              disabled={disabled}
              type="password" 
              placeholder={`Enter ${currentProviderObj?.name || "API"} Key`}
              value={customKey}
              onChange={e => setCustomKey(e.target.value)}
              style={{ width: "100%", padding: "10px 12px 10px 34px", background: "#0B0B0C", border: "1px solid #2A2A3E", borderRadius: 8, color: "#E0E0E8", fontSize: 13, outline: "none" }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
