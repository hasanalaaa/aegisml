import fs from "fs"
import path from "path"

export interface BlogPost {
  slug: string
  title: string
  excerpt: string
  date: string
  readTime: string
}

export function getBlogPosts(): BlogPost[] {
  const postsDir = path.join(process.cwd(), "content", "blog")
  if (!fs.existsSync(postsDir)) return []
  
  const files = fs.readdirSync(postsDir)
  const posts = files.filter(f => f.endsWith(".mdx")).map(file => {
    const slug = file.replace(/\.mdx$/, "")
    const fullPath = path.join(postsDir, file)
    const fileContents = fs.readFileSync(fullPath, "utf8")
    
    // extract metadata export
    const titleMatch = fileContents.match(/title:\s*"([^"]+)"/)
    const excerptMatch = fileContents.match(/excerpt:\s*"([^"]+)"/)
    const dateMatch = fileContents.match(/date:\s*"([^"]+)"/)
    const readTimeMatch = fileContents.match(/readTime:\s*"([^"]+)"/)
    
    return {
      slug,
      title: titleMatch ? titleMatch[1] : slug,
      excerpt: excerptMatch ? excerptMatch[1] : "",
      date: dateMatch ? dateMatch[1] : "",
      readTime: readTimeMatch ? readTimeMatch[1] : ""
    }
  })
  
  return posts.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
}

export function getBlogPost(slug: string): BlogPost | null {
  const posts = getBlogPosts()
  return posts.find(p => p.slug === slug) || null
}
