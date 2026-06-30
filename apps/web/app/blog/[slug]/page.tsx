import { getBlogPost, getBlogPosts } from "@/lib/blog"
import { notFound } from "next/navigation"
import { MDXRemote } from "next-mdx-remote/rsc"
import fs from "fs"
import path from "path"

export async function generateStaticParams() {
  return getBlogPosts().map(post => ({ slug: post.slug }))
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const post = getBlogPost(slug)
  if (!post) return {}
  return {
    title: `${post.title} | AegisML Blog`,
    description: post.excerpt
  }
}

export default async function BlogPostPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const post = getBlogPost(slug)
  
  if (!post) notFound()
  
  let source;
  try {
    const filePath = path.join(process.cwd(), "content/blog", `${slug}.mdx`)
    source = await fs.promises.readFile(filePath, "utf-8")
    source = source.replace(/export const metadata = {[\s\S]*?}/, '')
  } catch (e) {
    notFound()
  }
  
  return (
    <div className="container" style={{ paddingTop: "120px", paddingBottom: "80px", maxWidth: "800px", margin: "0 auto" }}>
      <div style={{ marginBottom: "3rem", borderBottom: "1px solid rgba(255,255,255,0.1)", paddingBottom: "2rem" }}>
        <h1 style={{ fontSize: "3rem", marginBottom: "1rem", lineHeight: 1.2 }}>{post.title}</h1>
        <div style={{ display: "flex", gap: "1rem", color: "var(--text-secondary)" }}>
          <span>{post.date}</span>
          <span>•</span>
          <span>{post.readTime}</span>
        </div>
      </div>
      
      <div className="prose prose-invert max-w-none" style={{ fontSize: "1.1rem", lineHeight: 1.8 }}>
        <MDXRemote source={source} />
      </div>
    </div>
  )
}
