import { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: '/',
      disallow: ['/api/', '/auth/', '/scan/'],
    },
    sitemap: 'https://aegisml.vercel.app/sitemap.xml',
  }
}
