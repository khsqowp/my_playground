import { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  // 실제 URL은 환경변수 NEXT_PUBLIC_SITE_URL에 설정되어야 합니다.
  const baseUrl = process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000';
  
  return {
    rules: {
      userAgent: '*',
      allow: ['/', '/p/blog/'],
      disallow: ['/api/', '/manage/', '/dashboard/'],
    },
    sitemap: `${baseUrl}/sitemap.xml`,
  }
}
