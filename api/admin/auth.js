import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import { getDB } from '../../lib/db.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')
console.log('[AUTH] JWT_SECRET loaded:', !!JWT_SECRET)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: 'Too many attempts. Try later.' },
})

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  maxAge: 8 * 60 * 60 * 1000,
  path: '/',
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
}

router.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {}
    const emailValue = (email || '').trim().toLowerCase()
    if (!emailValue || !isValidEmail(emailValue))
      return res.status(400).json({ ok: false, message: 'A valid email address is required' })
    if (!password || password.length < 8)
      return res.status(400).json({ ok: false, message: 'Password must be at least 8 characters' })

    const db = await getDB()
    const admins = db.collection('admins')
    const count = await admins.countDocuments()
    if (count >= 2)
      return res.status(409).json({ ok: false, message: 'Maximum admin accounts reached' })
    if (await admins.findOne({ $or: [{ email: emailValue }, { username: emailValue }] }))
      return res.status(409).json({ ok: false, message: 'An account with this email already exists' })

    await admins.insertOne({
      email: emailValue,
      username: emailValue,
      password: await bcrypt.hash(password, 12),
      createdAt: new Date(),
    })
    res.status(201).json({ ok: true, message: 'Account created' })
  } catch (error) {
    console.error('[AUTH] Registration FULL error:', error)
    if (error?.code === 11000) return res.status(409).json({ ok: false, message: 'An account with this email already exists' })
    res.status(500).json({ ok: false, message: error?.message || 'Unable to complete request' })
  }
})

router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, username, identifier, password } = req.body || {}
    const raw = (email || username || identifier || '').trim()
    if (!raw || !password) return res.status(400).json({ ok: false, message: 'Email and password are required' })

    const lower = raw.toLowerCase()
    const db = await getDB()
    const admin = await db.collection('admins').findOne({
      $or: [{ email: lower }, { username: lower }, { username: raw }],
    })
    if (!admin || !(await bcrypt.compare(password, admin.password)))
      return res.status(401).json({ ok: false, message: 'Invalid credentials' })

    const identity = admin.email || admin.username
    const token = jwt.sign({ id: admin._id.toString(), username: identity }, JWT_SECRET, { expiresIn: '8h' })
    res.cookie('adminToken', token, cookieOptions).json({ ok: true, username: identity })
  } catch (error) {
    console.error('[AUTH] Login FULL error:', error)
    res.status(500).json({ ok: false, message: error?.message || 'Unable to complete request' })
  }
})

router.post('/logout', (_req, res) => {
  res.clearCookie('adminToken', { ...cookieOptions, maxAge: undefined }).json({ ok: true })
})

router.get('/me', (req, res) => {
  try {
    const token = req.cookies?.adminToken
    console.log('[ME] adminToken present:', !!token)
    if (!token) return res.status(401).json({ ok: false, message: 'Not authenticated' })
    const decoded = jwt.verify(token, JWT_SECRET)
    res.json({ ok: true, username: decoded.username })
  } catch {
    res.status(401).json({ ok: false, message: 'Session expired' })
  }
})

export default router
