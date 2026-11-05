import express from 'express'
import jwt from 'jsonwebtoken'
import { ObjectId } from 'mongodb'
import sanitizeHtml from 'sanitize-html'
import { getDB } from '../lib/db.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')

const BLOG_CONTENT_SANITIZE_OPTIONS = {
  allowedTags: [
    'p', 'br', 'strong', 'b', 'em', 'i', 'u',
    'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'span',
  ],
  allowedAttributes: {
    p: ['class'],
    ul: ['style'],
    ol: ['style'],
    span: ['style'],
  },
  allowedStyles: {
    '*': {
      color: [/^#[0-9a-fA-F]{3,8}$/, /^rgb\([\d\s,]+\)$/],
      'font-size': [/^\d{1,2}px$/],
      'list-style-type': [
        /^(disc|circle|square|decimal|lower-alpha|upper-alpha|lower-roman|upper-roman)$/,
      ],
    },
  },
  allowedClasses: {
    p: ['no-spacing'],
  },
}

function sanitizeBlogContent(value) {
  return sanitizeHtml(String(value || ''), BLOG_CONTENT_SANITIZE_OPTIONS)
}

function hasBlogContent(value) {
  return sanitizeHtml(String(value || ''), { allowedTags: [] }).trim().length > 0
}

function requireAdmin(req, res, next) {
  const token = req.cookies?.adminToken
  if (!token) return res.status(401).json({ ok: false, message: 'Not authenticated' })
  try {
    req.admin = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ ok: false, message: 'Session expired' })
  }
}

function convertGoogleDriveUrl(url) {
  if (!url) return url
  const trimmed = String(url).trim()
  if (!trimmed.includes('drive.google.com')) return trimmed
  const match =
    trimmed.match(/\/file\/d\/([a-zA-Z0-9_-]+)/) ||
    trimmed.match(/[?&]id=([a-zA-Z0-9_-]+)/)
  if (!match) return trimmed
  return `https://drive.google.com/thumbnail?id=${match[1]}&sz=w1200`
}

function normalizeBlog(blog) {
  return {
    ...blog,
    title: blog.blogTitle ?? blog.title ?? '',
    featuredImageUrl: convertGoogleDriveUrl(
      blog.featuredImageUrl ?? blog.blogImageUrl ?? blog.blogImage ?? blog.image
    ),
    contentImageUrl: convertGoogleDriveUrl(
      blog.contentImageUrl ?? blog.contentImage
    ),
    imageAlt: blog.altText ?? blog.imageAlt ?? '',
    content: blog.blogContent ?? blog.content ?? '',
  }
}

router.get('/', async (_req, res) => {
  try {
    const db = await getDB()
    const blogs = await db.collection('blogs')
      .find({})
      .sort({ date: -1, createdAt: -1 })
      .toArray()
    res.json({ ok: true, blogs: blogs.map(normalizeBlog) })
  } catch (error) {
    console.error('[BLOGS] GET error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load blogs' })
  }
})

router.get('/:id', async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid blog ID' })
  }
  try {
    const db = await getDB()
    const blog = await db.collection('blogs')
      .findOne({ _id: new ObjectId(req.params.id) })
    if (!blog) {
      return res.status(404).json({ ok: false, message: 'Blog not found' })
    }
    res.json({ ok: true, blog: normalizeBlog(blog) })
  } catch (error) {
    console.error('[BLOGS] GET /:id error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load blog' })
  }
})

router.post('/', requireAdmin, async (req, res) => {
  try {
    const {
      blogTitle,
      date,
      featuredImageUrl,
      contentImageUrl,
      altText,
      blogContent,
    } = req.body || {}
    const sanitizedBlogContent = sanitizeBlogContent(blogContent)

    if (!blogTitle?.trim() || !date || !hasBlogContent(sanitizedBlogContent)) {
      return res.status(400).json({
        ok: false,
        message: 'Title, date and content are required',
      })
    }

    const db = await getDB()
    await db.collection('blogs').insertOne({
      blogTitle: blogTitle.trim(),
      date,
      featuredImageUrl: convertGoogleDriveUrl(featuredImageUrl),
      contentImageUrl: convertGoogleDriveUrl(contentImageUrl),
      altText: altText?.trim() || '',
      blogContent: sanitizedBlogContent,
      createdAt: new Date(),
    })
    res.status(201).json({ ok: true, message: 'Blog created' })
  } catch (error) {
    console.error('[BLOGS] POST error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to create blog' })
  }
})

router.put('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid blog ID' })
  }

  try {
    const {
      blogTitle,
      date,
      featuredImageUrl,
      contentImageUrl,
      altText,
      blogContent,
    } = req.body || {}
    const sanitizedBlogContent = sanitizeBlogContent(blogContent)

    if (!blogTitle?.trim() || !date || !hasBlogContent(sanitizedBlogContent)) {
      return res.status(400).json({
        ok: false,
        message: 'Title, date and content are required',
      })
    }

    const db = await getDB()
    const result = await db.collection('blogs').updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          blogTitle: blogTitle.trim(),
          date,
          featuredImageUrl: convertGoogleDriveUrl(featuredImageUrl),
          contentImageUrl: convertGoogleDriveUrl(contentImageUrl),
          altText: altText?.trim() || '',
          blogContent: sanitizedBlogContent,
          updatedAt: new Date(),
        },
      },
    )

    if (!result.matchedCount) {
      return res.status(404).json({ ok: false, message: 'Blog not found' })
    }
    res.json({ ok: true, message: 'Blog updated' })
  } catch (error) {
    console.error('[BLOGS] PUT error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to update blog' })
  }
})

router.delete('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid blog ID' })
  }

  try {
    const db = await getDB()
    const result = await db.collection('blogs').deleteOne({
      _id: new ObjectId(req.params.id),
    })
    if (!result.deletedCount) {
      return res.status(404).json({ ok: false, message: 'Blog not found' })
    }
    res.json({ ok: true, message: 'Blog deleted' })
  } catch (error) {
    console.error('[BLOGS] DELETE error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to delete blog' })
  }
})

export default router
