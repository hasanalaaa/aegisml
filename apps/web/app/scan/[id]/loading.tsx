export default function ScanLoading() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "40px", width: "400px", marginBottom: "24px" }} />
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "150px", marginBottom: "48px" }} />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
          <div className="animate-pulse bg-white/5 rounded" style={{ height: "200px" }} />
          <div className="animate-pulse bg-white/5 rounded" style={{ height: "200px" }} />
        </div>
      </div>
    </main>
  )
}
