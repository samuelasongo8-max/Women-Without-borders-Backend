import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'
import { getDB } from '../../lib/db.js'

const router = express.Router()
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')
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
  sameSite: 'strict',
  maxAge: 8 * 60 * 60 * 1000,
  path: '/',
}

router.post('/register', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username?.trim()) return res.status(400).json({ ok: false, message: 'Username required' })
    if (username.trim().length < 3 || username.trim().length > 64)
      return res.status(400).json({ ok: false, message: 'Username must be 3–64 characters' })
    if (!password || password.length < 8)
      return res.status(400).json({ ok: false, message: 'Password must be 8+ characters' })

    const db = await getDB()
    const admins = db.collection('admins')
    const usernameValue = username.trim().toLowerCase()
    const count = await admins.countDocuments()
    if (count >= 2)
      return res.status(409).json({ ok: false, message: 'Maximum admin accounts reached' })
    if (await admins.findOne({ username: usernameValue }))
      return res.status(409).json({ ok: false, message: 'Username already taken' })

    await admins.insertOne({
      username: usernameValue,
      password: await bcrypt.hash(password, 12),
      createdAt: new Date(),
    })
    res.status(201).json({ ok: true, message: 'Account created' })
  } catch (error) {
    if (error?.code === 11000) return res.status(409).json({ ok: false, message: 'Account already exists' })
    console.error('[AUTH] Registration error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to complete request' })
  }
})

router.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username || !password) return res.status(400).json({ ok: false, message: 'All fields required' })
    const db = await getDB()
    const admin = await db.collection('admins').findOne({ username: username.trim().toLowerCase() })
    if (!admin || !(await bcrypt.compare(password, admin.password)))
      return res.status(401).json({ ok: false, message: 'Invalid credentials' })

    const token = jwt.sign({ id: admin._id.toString(), username: admin.username }, JWT_SECRET, { expiresIn: '8h' })
    res.cookie('adminToken', token, cookieOptions).json({ ok: true, username: admin.username })
  } catch (error) {
    console.error('[AUTH] Login error:', error.message)
    res.status(500).json({ ok: false, message: 'Unable to complete request' })
  }
})

router.post('/logout', (_req, res) => {
  res.clearCookie('adminToken', { ...cookieOptions, maxAge: undefined }).json({ ok: true })
})

router.get('/me', (req, res) => {
  try {
    const token = req.cookies?.adminToken
    if (!token) return res.status(401).json({ ok: false, message: 'Not authenticated' })
    const decoded = jwt.verify(token, JWT_SECRET)
    res.json({ ok: true, username: decoded.username })
  } catch {
    res.status(401).json({ ok: false, message: 'Session expired' })
  }
})

export default router
