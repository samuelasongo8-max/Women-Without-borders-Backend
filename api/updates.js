import express from 'express'
import jwt from 'jsonwebtoken'
import { ObjectId } from 'mongodb'
import { getDB } from '../lib/db.js'
import { convertGoogleDriveUrl } from '../lib/driveUrl.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')

const collectionName = 'community_updates'

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

function normalizePayload(body = {}) {
  return {
    title: body.title?.trim() || '',
    category: body.category?.trim() || 'Community',
    author: body.author?.trim() || '',
    excerpt: body.excerpt?.trim() || '',
    coverImageLink: convertGoogleDriveUrl(body.coverImageLink),
    update: body.update?.trim() || '',
  }
}

router.get('/', async (_req, res) => {
  try {
    const db = await getDB()
    const updates = await db.collection(collectionName)
      .find({})
      .sort({ createdAt: -1 })
      .toArray()
    res.json({ ok: true, updates })
  } catch (error) {
    console.error('[UPDATES] GET error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load community updates' })
  }
})

router.get('/:id', async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid update ID' })
  }
  try {
    const db = await getDB()
    const update = await db.collection(collectionName).findOne({ _id: new ObjectId(req.params.id) })
    if (!update) return res.status(404).json({ ok: false, message: 'Update not found' })
    res.json({ ok: true, update })
  } catch (error) {
    console.error('[UPDATES] GET /:id error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load update' })
  }
})

router.post('/', requireAdmin, async (req, res) => {
  const payload = normalizePayload(req.body)
  if (!payload.title || !payload.update) {
    return res.status(400).json({ ok: false, message: 'Title and update content required' })
  }
  try {
    const db = await getDB()
    await db.collection(collectionName).insertOne({
      ...payload,
      excerpt: payload.excerpt || payload.update.substring(0, 140),
      createdAt: new Date(),
      createdBy: req.admin.username,
    })
    res.status(201).json({ ok: true, message: 'Community update posted' })
  } catch (error) {
    console.error('[UPDATES] POST error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to save community update' })
  }
})

router.put('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid update ID' })
  }
  const payload = normalizePayload(req.body)
  if (!payload.title || !payload.update) {
    return res.status(400).json({ ok: false, message: 'Title and update content required' })
  }
  try {
    const db = await getDB()
    const result = await db.collection(collectionName).updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { ...payload, excerpt: payload.excerpt || payload.update.substring(0, 140), updatedAt: new Date() } },
    )
    if (!result.matchedCount) return res.status(404).json({ ok: false, message: 'Update not found' })
    res.json({ ok: true, message: 'Community update updated' })
  } catch (error) {
    console.error('[UPDATES] PUT error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to update community update' })
  }
})

router.delete('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid update ID' })
  }
  try {
    const db = await getDB()
    const result = await db.collection(collectionName).deleteOne({ _id: new ObjectId(req.params.id) })
    if (!result.deletedCount) return res.status(404).json({ ok: false, message: 'Update not found' })
    res.json({ ok: true, message: 'Community update deleted' })
  } catch (error) {
    console.error('[UPDATES] DELETE error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to delete community update' })
  }
})

export default router
