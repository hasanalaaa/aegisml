export default function CommunityLoading() {
  return (
    <main style={{ minHeight: "100vh", background: "var(--bg-void)", paddingTop: "120px", paddingBottom: "80px" }}>
      <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px" }}>
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "60px", width: "350px", marginBottom: "16px", margin: "0 auto" }} />
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "24px", width: "400px", marginBottom: "48px", margin: "0 auto 48px" }} />
        <div className="animate-pulse bg-white/5 rounded" style={{ height: "400px" }} />
      </div>
    </main>
  )
}
