export default function DashboardLoading() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "48px", width: "250px", marginBottom: "32px" }} />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "24px", marginBottom: "48px" }}>
          {[1, 2, 3].map(i => <div key={i} className="animate-pulse bg-white/5 rounded" style={{ height: "120px" }} />)}
        </div>
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "300px" }} />
      </div>
    </main>
  )
}
