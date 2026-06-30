import { getBlogPosts } from "@/lib/blog"
import Link from "next/link"
import { GlassCard } from "@/components/GlassCard"

export const metadata = {
  title: "Blog | AegisML",
  description: "News, research, and updates on AI model security from the AegisML team."
}

export default function BlogIndexPage() {
  const posts = getBlogPosts()
  
  return (
    <div className="container" style={{ paddingTop: "120px", paddingBottom: "60px", maxWidth: "800px", margin: "0 auto" }}>
      <h1 style={{ fontSize: "3rem", marginBottom: "1rem" }}>AegisML Blog</h1>
      <p style={{ color: "var(--text-secondary)", marginBottom: "3rem", fontSize: "1.2rem" }}>
        Research, updates, and deep dives into AI model security.
      </p>
      
      <div style={{ display: "flex", flexDirection: "column", gap: "2rem" }}>
        {posts.map(post => (
          <Link href={`/blog/${post.slug}`} key={post.slug} style={{ textDecoration: "none", color: "inherit" }}>
            <GlassCard style={{ padding: "2rem", transition: "transform 0.2s" }} className="hover-lift">
              <h2 style={{ fontSize: "1.8rem", margin: "0 0 0.5rem 0", color: "var(--primary)" }}>{post.title}</h2>
              <div style={{ display: "flex", gap: "1rem", color: "var(--text-secondary)", fontSize: "0.9rem", marginBottom: "1rem" }}>
                <span>{post.date}</span>
                <span>•</span>
                <span>{post.readTime}</span>
              </div>
              <p style={{ margin: 0, lineHeight: 1.6 }}>{post.excerpt}</p>
            </GlassCard>
          </Link>
        ))}
      </div>
    </div>
  )
}
