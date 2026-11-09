import express from 'express'
import { ObjectId } from 'mongodb'
import { getDB } from '../lib/db.js'
import { createRequireAdmin } from '../lib/adminSession.js'

const router = express.Router()
const requireAdmin = createRequireAdmin()

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

// GET /api/posts — public, sorted newest first
router.get('/', async (_req, res) => {
  try {
    const db = await getDB()
    const posts = await db.collection('posts')
      .find({})
      .sort({ date: -1, createdAt: -1 })
      .toArray()

    // Convert every post's image URL before sending to frontend
    const convertedPosts = posts.map(post => ({
      ...post,
      imageUrl: convertGoogleDriveUrl(post.imageUrl)
    }))

    res.json({ ok: true, posts: convertedPosts })
  } catch (error) {
    console.error('[POSTS] GET error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load posts' })
  }
})

// POST /api/posts — auth protected
router.post('/', requireAdmin, async (req, res) => {
  try {
    const { date, topic, imageUrl, imageAlt, imageCaption, content } = req.body || {}
    if (!date || !topic?.trim() || !content?.trim()) {
      return res.status(400).json({ ok: false, message: 'Date, topic and content are required' })
    }
    const db = await getDB()
    await db.collection('posts').insertOne({
      topic: topic.trim(),
      date,
      imageUrl: convertGoogleDriveUrl(imageUrl),
      imageAlt: imageAlt?.trim() || '',
      imageCaption: imageCaption?.trim() || '',
      content: content.trim(),
      createdAt: new Date(),
    })
    res.status(201).json({ ok: true, message: 'Post created' })
  } catch (error) {
    console.error('[POSTS] POST error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to create post' })
  }
})

router.get('/:id', async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({
      ok: false, message: 'Invalid post ID'
    })
  }
  try {
    const db = await getDB()
    const post = await db
      .collection('posts')
      .findOne({ _id: new ObjectId(req.params.id) })
    if (!post) {
      return res.status(404).json({
        ok: false, message: 'Post not found'
      })
    }
    post.imageUrl = convertGoogleDriveUrl(post.imageUrl)
    res.json({ ok: true, post })
  } catch (error) {
    console.error('[POSTS] GET /:id error:', error.message)
    res.status(500).json({
      ok: false, message: 'Unable to load post'
    })
  }
})

// DELETE /api/posts/:id — auth protected
router.delete('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid post ID' })
  }
  try {
    const db = await getDB()
    const result = await db.collection('posts').deleteOne({ _id: new ObjectId(req.params.id) })
    if (!result.deletedCount) {
      return res.status(404).json({ ok: false, message: 'Post not found' })
    }
    res.json({ ok: true, message: 'Post deleted' })
  } catch (error) {
    console.error('[POSTS] DELETE error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to delete post' })
  }
})

// PUT /api/posts/:id — auth protected
router.put('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({
      ok: false, message: 'Invalid post ID'
    })
  }
  try {
    const {
      date, topic, imageUrl,
      imageAlt, imageCaption, content
    } = req.body || {}
    if (!date || !topic?.trim() || !content?.trim()) {
      return res.status(400).json({
        ok: false,
        message: 'Date, topic and content are required'
      })
    }
    const db = await getDB()
    const result = await db.collection('posts').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: {
        topic:        topic.trim(),
        date,
        imageUrl:     convertGoogleDriveUrl(imageUrl),
        imageAlt:     imageAlt?.trim()      || '',
        imageCaption: imageCaption?.trim()  || '',
        content:      content.trim(),
        updatedAt:    new Date(),
      }}
    )
    if (!result.matchedCount) {
      return res.status(404).json({
        ok: false, message: 'Post not found'
      })
    }
    res.json({ ok: true, message: 'Post updated' })
  } catch (error) {
    console.error('[POSTS] PUT error:', error.message)
    res.status(500).json({
      ok: false, message: 'Unable to update post'
    })
  }
})

export default router
