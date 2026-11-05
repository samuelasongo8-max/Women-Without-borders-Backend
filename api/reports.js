import express from 'express'
import jwt from 'jsonwebtoken'
import { ObjectId } from 'mongodb'
import { getDB } from '../lib/db.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')

function requireAdmin(req, res, next) {
  const token = req.cookies?.adminToken
  if (!token) return res.status(401).json({
    ok: false,
    message: 'Not authenticated',
  })
  try {
    req.admin = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({
      ok: false,
      message: 'Session expired',
    })
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

function validateReportFields(fields) {
  return (
    fields.reportTitle?.trim() &&
    fields.category?.trim() &&
    fields.reportDate &&
    fields.reportFileLink?.trim()
  )
}

function reportDocument(fields, existing = {}) {
  return {
    ...existing,
    reportTitle: fields.reportTitle.trim(),
    category: fields.category.trim(),
    reportDate: fields.reportDate,
    coverImageLink: convertGoogleDriveUrl(fields.coverImageLink),
    reportFileLink: fields.reportFileLink.trim(),
    downloadFileName: fields.downloadFileName?.trim() || '',
    description: fields.description?.trim() || '',
  }
}

router.get('/', async (_req, res) => {
  try {
    const db = await getDB()
    const reports = await db.collection('reports')
      .find({})
      .sort({ reportDate: -1, createdAt: -1 })
      .toArray()
    res.json({ ok: true, reports })
  } catch (error) {
    console.error('[REPORTS] GET error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load reports' })
  }
})

router.get('/:id', async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid report ID' })
  }

  try {
    const db = await getDB()
    const report = await db.collection('reports')
      .findOne({ _id: new ObjectId(req.params.id) })

    if (!report) {
      return res.status(404).json({ ok: false, message: 'Report not found' })
    }

    res.json({ ok: true, report })
  } catch (error) {
    console.error('[REPORTS] GET /:id error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to load report' })
  }
})

router.post('/', requireAdmin, async (req, res) => {
  const fields = req.body || {}
  if (!validateReportFields(fields)) {
    return res.status(400).json({
      ok: false,
      message: 'Title, category, date and file link are required',
    })
  }

  try {
    const db = await getDB()
    await db.collection('reports').insertOne({
      ...reportDocument(fields),
      createdAt: new Date(),
    })
    res.status(201).json({ ok: true, message: 'Report created' })
  } catch (error) {
    console.error('[REPORTS] POST error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to create report' })
  }
})

router.put('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid report ID' })
  }

  const fields = req.body || {}
  if (!validateReportFields(fields)) {
    return res.status(400).json({
      ok: false,
      message: 'Title, category, date and file link are required',
    })
  }

  try {
    const db = await getDB()
    const result = await db.collection('reports').updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          ...reportDocument(fields),
          updatedAt: new Date(),
        },
      },
    )

    if (!result.matchedCount) {
      return res.status(404).json({ ok: false, message: 'Report not found' })
    }

    res.json({ ok: true, message: 'Report updated' })
  } catch (error) {
    console.error('[REPORTS] PUT error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to update report' })
  }
})

router.delete('/:id', requireAdmin, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ ok: false, message: 'Invalid report ID' })
  }

  try {
    const db = await getDB()
    const result = await db.collection('reports').deleteOne({
      _id: new ObjectId(req.params.id),
    })

    if (!result.deletedCount) {
      return res.status(404).json({ ok: false, message: 'Report not found' })
    }

    res.json({ ok: true, message: 'Report deleted' })
  } catch (error) {
    console.error('[REPORTS] DELETE error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to delete report' })
  }
})

export default router
