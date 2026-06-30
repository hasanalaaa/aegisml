export default function ResearchLoading() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "60px", width: "400px", marginBottom: "24px" }} />
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "150px", marginBottom: "48px" }} />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "24px" }}>
          {[1, 2, 3, 4].map(i => <div key={i} className="animate-pulse bg-white/5 rounded" style={{ height: "250px" }} />)}
        </div>
      </div>
    </main>
  )
}
