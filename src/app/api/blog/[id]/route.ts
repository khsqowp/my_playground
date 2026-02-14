import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { PostUpdateInput } from "@/types/blog";

// Helper function to generate slug from title
function generateSlug(title: string): string {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^\w\s가-힣-]/g, "")
    .replace(/[\s_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// Helper function to ensure unique slug
async function ensureUniqueSlug(baseSlug: string, excludeId?: string): Promise<string> {
  let slug = baseSlug;
  let counter = 1;

  while (true) {
    const existing = await prisma.post.findUnique({
      where: { slug },
      select: { id: true },
    });

    if (!existing || existing.id === excludeId) {
      return slug;
    }

    slug = `${baseSlug}-${counter}`;
    counter++;
  }
}

// GET /api/blog/[id] - Get single post by ID
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    const post = await prisma.post.findUnique({
      where: { id },
      include: {
        author: {
          select: {
            id: true,
            name: true,
          },
        },
        category: {
          select: {
            id: true,
            name: true,
            slug: true,
            color: true,
          },
        },
        tags: {
          include: {
            tag: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        },
        series: {
          select: {
            id: true,
            name: true,
            posts: {
              select: {
                id: true,
                title: true,
                slug: true,
                seriesOrder: true,
              },
              orderBy: {
                seriesOrder: "asc",
              },
            },
          },
        },
      },
    });

    if (!post) {
      return NextResponse.json({ error: "Post not found" }, { status: 404 });
    }

    return NextResponse.json(post);
  } catch (error) {
    console.error("Error fetching post:", error);
    return NextResponse.json({ error: "Failed to fetch post" }, { status: 500 });
  }
}

// PUT /api/blog/[id] - Update post
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = await params;
    const body: PostUpdateInput = await request.json();

    // Check if post exists and user is authorized
    const existingPost = await prisma.post.findUnique({
      where: { id },
      select: {
        authorId: true,
        author: {
          select: {
            role: true,
          },
        },
      },
    });

    if (!existingPost) {
      return NextResponse.json({ error: "Post not found" }, { status: 404 });
    }

    // Check authorization - author or OWNER role
    const userRole = (session.user as any).role;
    const isAuthor = existingPost.authorId === session.user.id;
    const isOwner = userRole === "OWNER";

    if (!isAuthor && !isOwner) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    // Prepare update data
    const updateData: any = {};

    if (body.title !== undefined) {
      updateData.title = body.title;
      // Regenerate slug if title changed
      const baseSlug = generateSlug(body.title);
      updateData.slug = await ensureUniqueSlug(baseSlug, id);
    }

    if (body.content !== undefined) updateData.content = body.content;
    if (body.excerpt !== undefined) updateData.excerpt = body.excerpt;
    if (body.coverImage !== undefined) updateData.coverImage = body.coverImage;
    if (body.published !== undefined) updateData.published = body.published;
    if (body.visibility !== undefined) updateData.visibility = body.visibility;
    if (body.categoryId !== undefined) updateData.categoryId = body.categoryId;
    if (body.seriesId !== undefined) updateData.seriesId = body.seriesId;
    if (body.seriesOrder !== undefined) updateData.seriesOrder = body.seriesOrder;
    if (body.createdAt !== undefined) updateData.createdAt = new Date(body.createdAt);

    // Handle tags update
    if (body.tags !== undefined) {
      // Create tags that don't exist
      const tagPromises = body.tags.map(async (tagName) => {
        const tag = await prisma.tag.upsert({
          where: { name: tagName },
          update: {},
          create: { name: tagName },
        });
        return tag.id;
      });

      const tagIds = await Promise.all(tagPromises);

      // Delete existing tag connections and create new ones
      updateData.tags = {
        deleteMany: {},
        create: tagIds.map((tagId) => ({
          tag: {
            connect: { id: tagId },
          },
        })),
      };
    }

    // Update post
    const post = await prisma.post.update({
      where: { id },
      data: updateData,
      include: {
        author: {
          select: {
            id: true,
            name: true,
          },
        },
        category: {
          select: {
            id: true,
            name: true,
            slug: true,
            color: true,
          },
        },
        tags: {
          include: {
            tag: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        },
        series: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    return NextResponse.json(post);
  } catch (error) {
    console.error("Error updating post:", error);
    return NextResponse.json({ error: "Failed to update post" }, { status: 500 });
  }
}

// DELETE /api/blog/[id] - Delete post
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const session = await auth();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = await params;

    // Check if post exists and user is authorized
    const existingPost = await prisma.post.findUnique({
      where: { id },
      select: {
        authorId: true,
        author: {
          select: {
            role: true,
          },
        },
      },
    });

    if (!existingPost) {
      return NextResponse.json({ error: "Post not found" }, { status: 404 });
    }

    // Check authorization - author or OWNER role
    const userRole = (session.user as any).role;
    const isAuthor = existingPost.authorId === session.user.id;
    const isOwner = userRole === "OWNER";

    if (!isAuthor && !isOwner) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    // Delete post (tags will be cascade deleted)
    await prisma.post.delete({
      where: { id },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error deleting post:", error);
    return NextResponse.json({ error: "Failed to delete post" }, { status: 500 });
  }
}
