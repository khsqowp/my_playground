import { MetadataRoute } from 'next'
import prisma from '@/lib/prisma'

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  // 실제 URL은 환경변수 NEXT_PUBLIC_SITE_URL에 설정되어야 합니다.
  const baseUrl = process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000';

  const posts = await prisma.post.findMany({
    where: {
      visibility: 'PUBLIC',
      published: true,
    },
    select: {
      slug: true,
      updatedAt: true,
    },
  })

  const blogEntries: MetadataRoute.Sitemap = posts.map((post) => ({
    url: `${baseUrl}/p/blog/${post.slug}`,
    lastModified: post.updatedAt,
    changeFrequency: 'weekly',
    priority: 0.8,
  }))

  return [
    {
      url: baseUrl,
      lastModified: new Date(),
      changeFrequency: 'daily',
      priority: 1.0,
    },
    ...blogEntries,
  ]
}
