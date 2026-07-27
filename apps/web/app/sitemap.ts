import { MetadataRoute } from 'next'

// Only canonical, live routes are advertised. The legacy multi-page site
// (/threats, /compare, /dashboard, ...) was purged — the AegisApp SPA at "/"
// and the per-scan report at /scan/[id] are the entire public surface.
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: 'https://aegisml.vercel.app',
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 1,
    },
  ]
}
