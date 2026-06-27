"use client";

import { useState, useEffect } from "react";

export function DeveloperConsoleClient() {
  const [activeTab, setActiveTab] = useState<"webhooks" | "logs" | "graphql">("webhooks");
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [logs, setLogs] = useState<any[]>([]);
  const [urlInput, setUrlInput] = useState("");
  const [eventInput, setEventInput] = useState<string>("scan.completed");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    fetchWebhooks();
    fetchLogs();
  }, []);

  const fetchWebhooks = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/v1/developer/webhooks", {
        headers: { "Authorization": `Bearer ${localStorage.getItem("token")}` }
      });
      if (res.ok) setWebhooks(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/v1/developer/webhooks/logs", {
        headers: { "Authorization": `Bearer ${localStorage.getItem("token")}` }
      });
      if (res.ok) setLogs(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const createWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMsg("");
    try {
      const res = await fetch("http://localhost:8000/api/v1/developer/webhooks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${localStorage.getItem("token")}`
        },
        body: JSON.stringify({ url: urlInput, events: [eventInput] })
      });
      if (res.ok) {
        const data = await res.json();
        setWebhooks([data, ...webhooks]);
        setUrlInput("");
        alert(`Webhook created! Your secret HMAC token is:\n\n${data.secret_token}\n\nSave this now, it won't be shown again!`);
      } else {
        setErrorMsg("Failed to create webhook. Ensure URL is valid.");
      }
    } catch (error) {
      setErrorMsg("Network error.");
    }
    setIsSubmitting(false);
  };

  return (
    <main className="flex-1 max-w-6xl w-full mx-auto p-6 md:p-12 space-y-8 mt-16">
        <div>
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-[#D4AF37] to-[#C5A880] mb-2">Developer Console</h1>
          <p className="text-gray-400">Integrate AegisML with your CI/CD pipelines using GraphQL and Webhooks.</p>
        </div>

        <div className="flex space-x-4 border-b border-[#232326] pb-2">
          <button 
            onClick={() => setActiveTab("webhooks")}
            className={`px-4 py-2 font-medium transition-colors ${activeTab === "webhooks" ? "text-[#D4AF37] border-b-2 border-[#D4AF37]" : "text-gray-400 hover:text-gray-100"}`}
          >
            Webhooks
          </button>
          <button 
            onClick={() => setActiveTab("logs")}
            className={`px-4 py-2 font-medium transition-colors ${activeTab === "logs" ? "text-[#D4AF37] border-b-2 border-[#D4AF37]" : "text-gray-400 hover:text-gray-100"}`}
          >
            Delivery Logs
          </button>
          <button 
            onClick={() => setActiveTab("graphql")}
            className={`px-4 py-2 font-medium transition-colors ${activeTab === "graphql" ? "text-[#D4AF37] border-b-2 border-[#D4AF37]" : "text-gray-400 hover:text-gray-100"}`}
          >
            GraphQL API
          </button>
        </div>

        {activeTab === "webhooks" && (
          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4">
            <div className="bg-[#121214] border border-[#232326] p-6 rounded-xl">
              <h2 className="text-xl font-semibold mb-4 text-slate-100">Add New Webhook</h2>
              <form onSubmit={createWebhook} className="space-y-4">
                {errorMsg && <div className="text-red-400 text-sm bg-red-950/30 p-3 rounded-lg border border-red-900/50">{errorMsg}</div>}
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Target Payload URL</label>
                  <input
                    type="url"
                    required
                    placeholder="https://your-server.com/api/webhook"
                    value={urlInput}
                    onChange={e => setUrlInput(e.target.value)}
                    className="w-full bg-[#0B0B0C] border border-[#232326] rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-[#D4AF37] transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Event Type</label>
                  <select
                    value={eventInput}
                    onChange={e => setEventInput(e.target.value)}
                    className="w-full bg-[#0B0B0C] border border-[#232326] rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-[#D4AF37] transition-colors"
                  >
                    <option value="scan.completed">scan.completed</option>
                    <option value="threat.critical">threat.critical</option>
                    <option value="all">All Events</option>
                  </select>
                </div>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="bg-[#D4AF37] hover:bg-[#B39126] text-slate-950 font-semibold px-6 py-2 rounded-lg transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? "Creating..." : "Create Webhook"}
                </button>
              </form>
            </div>

            <div>
              <h2 className="text-xl font-semibold mb-4 text-slate-100">Your Webhooks</h2>
              {webhooks.length === 0 ? (
                <p className="text-gray-500 text-sm">No webhooks configured.</p>
              ) : (
                <div className="bg-[#121214] border border-[#232326] rounded-xl overflow-hidden">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-[#0B0B0C] text-gray-400">
                      <tr>
                        <th className="px-4 py-3 font-medium">URL</th>
                        <th className="px-4 py-3 font-medium">Events</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">Created</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#232326]">
                      {webhooks.map((w: any) => (
                        <tr key={w.id} className="hover:bg-[#161618]/50 transition-colors">
                          <td className="px-4 py-3 text-gray-300 font-mono truncate max-w-[200px]">{w.url}</td>
                          <td className="px-4 py-3 text-[#D4AF37]/80">{w.events.join(", ")}</td>
                          <td className="px-4 py-3">
                            <span className="px-2 py-1 bg-green-500/10 text-green-400 rounded text-xs border border-green-500/20">Active</span>
                          </td>
                          <td className="px-4 py-3 text-gray-500">{new Date(w.created_at).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "logs" && (
          <div className="animate-in fade-in slide-in-from-bottom-4">
             {logs.length === 0 ? (
                <p className="text-gray-500 text-sm">No recent webhook deliveries.</p>
              ) : (
                <div className="bg-[#121214] border border-[#232326] rounded-xl overflow-hidden">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-[#0B0B0C] text-gray-400">
                      <tr>
                        <th className="px-4 py-3 font-medium">Date</th>
                        <th className="px-4 py-3 font-medium">Event</th>
                        <th className="px-4 py-3 font-medium">URL</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#232326]">
                      {logs.map((log: any) => (
                        <tr key={log.id} className="hover:bg-[#161618]/50 transition-colors">
                          <td className="px-4 py-3 text-gray-500">{new Date(log.triggered_at).toLocaleString()}</td>
                          <td className="px-4 py-3 text-gray-300">{log.event_type}</td>
                          <td className="px-4 py-3 text-gray-400 font-mono truncate max-w-[200px]">{log.url}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-1 rounded text-xs border ${
                              log.response_status >= 200 && log.response_status < 300
                              ? 'bg-green-500/10 text-green-400 border-green-500/20'
                              : 'bg-red-500/10 text-red-400 border-red-500/20'
                            }`}>
                              {log.response_status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
          </div>
        )}

        {activeTab === "graphql" && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4">
            <p className="text-gray-300">
              Our GraphQL Gateway allows you to query scans, threat patterns, and CVEs in a single request. 
              The endpoint is located at <code className="bg-[#161618] px-1 py-0.5 rounded text-[#C5A880]">/graphql</code>.
            </p>
            <div className="bg-[#121214] border border-[#232326] rounded-xl overflow-hidden">
              <div className="bg-[#0B0B0C] px-4 py-2 border-b border-[#232326] flex justify-between items-center">
                <span className="text-sm font-medium text-gray-400">Example: Fetching Recent Scans</span>
              </div>
              <pre className="p-4 overflow-x-auto text-sm text-sky-300">
{`query GetRecentScans {
  recentScans(limit: 5) {
    scanId
    filename
    riskLevel
    riskScore
    createdAt
  }
}`}
              </pre>
            </div>

            <div className="bg-[#121214] border border-[#232326] rounded-xl overflow-hidden">
              <div className="bg-[#0B0B0C] px-4 py-2 border-b border-[#232326] flex justify-between items-center">
                <span className="text-sm font-medium text-gray-400">cURL Example</span>
              </div>
              <pre className="p-4 overflow-x-auto text-sm text-green-300">
{`curl -X POST http://localhost:8000/graphql \\
  -H "Content-Type: application/json" \\
  -d '{"query": "query { recentScans(limit: 2) { scanId riskLevel } }"}'`}
              </pre>
            </div>
          </div>
        )}
      </main>
  );
}
