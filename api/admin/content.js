import express from 'express'
import jwt from 'jsonwebtoken'
import multer from 'multer'
import { randomUUID } from 'node:crypto'
import { mkdir, unlink, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { ObjectId } from 'mongodb'
import { getDB } from '../../lib/db.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')

const uploadDir = fileURLToPath(new URL('../../../public/uploads/', import.meta.url))
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 2, fields: 20, parts: 24 },
})

const collections = {
  posts: 'posts',
  blogs: 'blogs',
  reports: 'reports',
  updates: 'community_updates',
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

function imageExtension(file) {
  const buffer = file.buffer
  const isPng = buffer.length >= 8
    && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
  if (file.mimetype === 'image/png' && isPng) return '.png'

  const isJpeg = buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff
  if (file.mimetype === 'image/jpeg' && isJpeg) return '.jpg'

  const signature = buffer.subarray(0, 6).toString('ascii')
  if (file.mimetype === 'image/gif' && (signature === 'GIF87a' || signature === 'GIF89a')) return '.gif'

  const isWebp = buffer.length >= 12
    && buffer.subarray(0, 4).toString('ascii') === 'RIFF'
    && buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  if (file.mimetype === 'image/webp' && isWebp) return '.webp'
  return null
}

function validateImages(files) {
  return files.every((file) => imageExtension(file) !== null)
}

async function saveImage(file) {
  const filename = `${randomUUID()}${imageExtension(file)}`
  await mkdir(uploadDir, { recursive: true })
  await writeFile(path.join(uploadDir, filename), file.buffer, { flag: 'wx' })
  return { url: `/uploads/${filename}`, path: path.join(uploadDir, filename) }
}

async function removeSavedImages(savedImages) {
  await Promise.all(savedImages.map(async (image) => {
    try {
      await unlink(image.path)
    } catch (error) {
      if (error.code !== 'ENOENT') console.error('[admin content] Upload cleanup error:', error.message)
    }
  }))
}

function logFailure(label, error) {
  console.error(`[${label}] Error:`, error.message)
}

router.post('/posts', requireAdmin, upload.single('featuredImage'), async (req, res) => {
  const { date, topic, altText, caption, paragraph } = req.body || {}
  if (!date || !topic?.trim() || !paragraph?.trim()) {
    return res.status(400).json({ ok: false, message: 'Date, topic and paragraph required' })
  }
  if (req.file && !validateImages([req.file])) {
    return res.status(400).json({ ok: false, message: 'Upload a valid JPG, PNG, GIF, or WEBP image' })
  }

  const savedImages = []
  try {
    const db = await getDB()
    const image = req.file ? await saveImage(req.file) : null
    if (image) savedImages.push(image)
    await db.collection(collections.posts).insertOne({
      date,
      topic: topic.trim(),
      imageUrl: image?.url || null,
      altText: altText || '',
      caption: caption || '',
      paragraph: paragraph.trim(),
      createdAt: new Date(),
      createdBy: req.admin.username,
    })
    res.status(201).json({ ok: true, message: 'Post saved' })
  } catch (error) {
    await removeSavedImages(savedImages)
    logFailure('posts', error)
    res.status(500).json({ ok: false, message: 'Unable to save post' })
  }
})

router.get('/posts', requireAdmin, async (_req, res) => {
  try {
    const db = await getDB()
    const posts = await db.collection(collections.posts).find({}).sort({ createdAt: -1 }).toArray()
    res.json({ ok: true, posts })
  } catch (error) {
    logFailure('posts', error)
    res.status(500).json({ ok: false, message: 'Unable to load posts' })
  }
})

router.delete('/posts/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ ok: false, message: 'Invalid post ID' })
  try {
    const db = await getDB()
    const result = await db.collection(collections.posts).deleteOne({ _id: new ObjectId(req.params.id) })
    if (!result.deletedCount) return res.status(404).json({ ok: false, message: 'Post not found' })
    res.json({ ok: true, message: 'Post deleted' })
  } catch (error) {
    logFailure('posts', error)
    res.status(500).json({ ok: false, message: 'Unable to delete post' })
  }
})

router.post(
  '/blogs',
  requireAdmin,
  upload.fields([{ name: 'blogImage', maxCount: 1 }, { name: 'contentImage', maxCount: 1 }]),
  async (req, res) => {
    const { blogTitle, blogContent, date, altText } = req.body || {}
    const files = [req.files?.blogImage?.[0], req.files?.contentImage?.[0]].filter(Boolean)
    if (!blogTitle?.trim() || !blogContent?.trim() || !date) {
      return res.status(400).json({ ok: false, message: 'Title, content and date required' })
    }
    if (!validateImages(files)) {
      return res.status(400).json({ ok: false, message: 'Upload valid JPG, PNG, GIF, or WEBP images' })
    }

    const savedImages = []
    try {
      const db = await getDB()
      const blogImage = req.files?.blogImage?.[0] ? await saveImage(req.files.blogImage[0]) : null
      if (blogImage) savedImages.push(blogImage)
      const contentImage = req.files?.contentImage?.[0] ? await saveImage(req.files.contentImage[0]) : null
      if (contentImage) savedImages.push(contentImage)
      await db.collection(collections.blogs).insertOne({
        blogTitle: blogTitle.trim(),
        blogContent: blogContent.trim(),
        date,
        altText: altText || '',
        blogImageUrl: blogImage?.url || null,
        contentImageUrl: contentImage?.url || null,
        createdAt: new Date(),
        createdBy: req.admin.username,
      })
      res.status(201).json({ ok: true, message: 'Blog saved' })
    } catch (error) {
      await removeSavedImages(savedImages)
      logFailure('blogs', error)
      res.status(500).json({ ok: false, message: 'Unable to save blog' })
    }
  },
)

router.get('/blogs', requireAdmin, async (_req, res) => {
  try {
    const db = await getDB()
    const blogs = await db.collection(collections.blogs).find({}).sort({ createdAt: -1 }).toArray()
    res.json({ ok: true, blogs })
  } catch (error) {
    logFailure('blogs', error)
    res.status(500).json({ ok: false, message: 'Unable to load blogs' })
  }
})

router.delete('/blogs/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ ok: false, message: 'Invalid blog ID' })
  try {
    const db = await getDB()
    const result = await db.collection(collections.blogs).deleteOne({ _id: new ObjectId(req.params.id) })
    if (!result.deletedCount) return res.status(404).json({ ok: false, message: 'Blog not found' })
    res.json({ ok: true, message: 'Blog deleted' })
  } catch (error) {
    logFailure('blogs', error)
    res.status(500).json({ ok: false, message: 'Unable to delete blog' })
  }
})

router.post('/reports', requireAdmin, async (req, res) => {
  const { reportTitle, coverImageLink, category, reportDate, description, reportFileLink, downloadFileName } = req.body || {}
  if (!reportTitle?.trim() || !category?.trim() || !reportDate || !reportFileLink?.trim()) {
    return res.status(400).json({ ok: false, message: 'Title, category, date and file link required' })
  }
  try {
    const db = await getDB()
    await db.collection(collections.reports).insertOne({
      reportTitle: reportTitle.trim(),
      coverImageLink: coverImageLink?.trim() || '',
      category: category.trim(),
      reportDate,
      description: description || '',
      reportFileLink: reportFileLink.trim(),
      downloadFileName: downloadFileName?.trim() || reportTitle.trim(),
      createdAt: new Date(),
      createdBy: req.admin.username,
    })
    res.status(201).json({ ok: true, message: 'Report submitted' })
  } catch (error) {
    logFailure('reports', error)
    res.status(500).json({ ok: false, message: 'Unable to save report' })
  }
})

router.get('/reports', requireAdmin, async (_req, res) => {
  try {
    const db = await getDB()
    const reports = await db.collection(collections.reports).find({}).sort({ createdAt: -1 }).toArray()
    res.json({ ok: true, reports })
  } catch (error) {
    logFailure('reports', error)
    res.status(500).json({ ok: false, message: 'Unable to load reports' })
  }
})

router.delete('/reports/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ ok: false, message: 'Invalid report ID' })
  try {
    const db = await getDB()
    const result = await db.collection(collections.reports).deleteOne({ _id: new ObjectId(req.params.id) })
    if (!result.deletedCount) return res.status(404).json({ ok: false, message: 'Report not found' })
    res.json({ ok: true, message: 'Report deleted' })
  } catch (error) {
    logFailure('reports', error)
    res.status(500).json({ ok: false, message: 'Unable to delete report' })
  }
})

router.post('/updates', requireAdmin, async (req, res) => {
  const { title, update, excerpt, category, coverImageLink, author } = req.body || {}
  if (!title?.trim() || !update?.trim()) {
    return res.status(400).json({ ok: false, message: 'Title and update content required' })
  }
  try {
    const db = await getDB()
    await db.collection(collections.updates).insertOne({
      title: title.trim(),
      update: update.trim(),
      excerpt: excerpt?.trim() || update.trim().substring(0, 120),
      category: category?.trim() || 'Community',
      coverImageLink: coverImageLink?.trim() || '',
      author: author?.trim() || '',
      createdAt: new Date(),
      createdBy: req.admin.username,
    })
    res.status(201).json({ ok: true, message: 'Community update posted' })
  } catch (error) {
    logFailure('updates', error)
    res.status(500).json({ ok: false, message: 'Unable to save community update' })
  }
})

router.get('/updates', requireAdmin, async (_req, res) => {
  try {
    const db = await getDB()
    const updates = await db.collection(collections.updates).find({}).sort({ createdAt: -1 }).toArray()
    res.json({ ok: true, updates })
  } catch (error) {
    logFailure('updates', error)
    res.status(500).json({ ok: false, message: 'Unable to load community updates' })
  }
})

router.delete('/updates/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ ok: false, message: 'Invalid update ID' })
  try {
    const db = await getDB()
    const result = await db.collection(collections.updates).deleteOne({ _id: new ObjectId(req.params.id) })
    if (!result.deletedCount) return res.status(404).json({ ok: false, message: 'Update not found' })
    res.json({ ok: true, message: 'Update deleted' })
  } catch (error) {
    logFailure('updates', error)
    res.status(500).json({ ok: false, message: 'Unable to delete community update' })
  }
})

router.use((error, _req, res, next) => {
  if (error instanceof multer.MulterError) {
    const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : 400
    return res.status(status).json({
      ok: false,
      message: error.code === 'LIMIT_FILE_SIZE' ? 'Image must be 5 MB or smaller' : 'Invalid upload',
    })
  }
  next(error)
})

export default router
