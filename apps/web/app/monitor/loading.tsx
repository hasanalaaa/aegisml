export default function MonitorLoading() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div style={{ maxWidth: "1000px", margin: "0 auto", padding: "0 24px" }}>
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "48px", width: "300px", marginBottom: "16px" }} />
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "24px", width: "200px", marginBottom: "32px" }} />
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {[1, 2, 3, 4, 5].map(i => <div key={i} className="animate-pulse bg-white/5 rounded" style={{ height: "80px" }} />)}
        </div>
      </div>
    </main>
  )
}
