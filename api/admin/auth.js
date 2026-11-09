import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { randomUUID, timingSafeEqual } from 'node:crypto'
import { getDB } from '../../lib/db.js'
import { getActiveAdminSession, ADMIN_SESSION_COLLECTION } from '../../lib/adminSession.js'
import { createMongoIpRateLimiter } from '../../lib/mongoIpRateLimiter.js'

const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')

export function createAdminCookieOptions(nodeEnv = process.env.NODE_ENV) {
  const production = nodeEnv === 'production'
  return {
    httpOnly: true,
    secure: production,
    sameSite: production ? 'none' : 'lax',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  }
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
}

export function createAdminAuthRouter({
  getDBFn = getDB,
  jwtSecret = JWT_SECRET,
  privateEntryLimit = 10,
  privateEntryWindowMs = 15 * 60 * 1000,
  limiterNow = Date.now,
  nodeEnv = process.env.NODE_ENV,
} = {}) {
  const router = express.Router()
  const cookieOptions = createAdminCookieOptions(nodeEnv)
  const authLimiter = createMongoIpRateLimiter({
    getDBFn,
    scope: 'admin-auth',
    limit: 5,
    windowMs: 15 * 60 * 1000,
  })
  const privateEntryLimiter = createMongoIpRateLimiter({
    getDBFn,
    scope: 'admin-private-entry',
    limit: privateEntryLimit,
    windowMs: privateEntryWindowMs,
    now: limiterNow,
  })

router.post('/register', authLimiter, async (req, res) => {
  try {
    const expectedKey = Buffer.from(process.env.ADMIN_REGISTER_KEY || '')
    const providedKey = Buffer.from(req.get('X-Admin-Registration-Key') || '')
    if (!expectedKey.length || expectedKey.length !== providedKey.length || !timingSafeEqual(expectedKey, providedKey)) {
      return res.status(403).json({ ok: false, message: 'Registration is unavailable' })
    }
    const { email, password } = req.body || {}
    const emailValue = (email || '').trim().toLowerCase()
    if (!emailValue || !isValidEmail(emailValue))
      return res.status(400).json({ ok: false, message: 'A valid email address is required' })
    if (typeof password !== 'string' || password.length < 8)
      return res.status(400).json({ ok: false, message: 'Password must be at least 8 characters' })
    if (bcrypt.truncates(password))
      return res.status(400).json({ ok: false, message: 'Password must be 72 UTF-8 bytes or fewer' })

    const db = await getDBFn()
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
    console.error('[AUTH] ADMIN_REGISTRATION_FAILED')
    if (error?.code === 11000) return res.status(409).json({ ok: false, message: 'An account with this email already exists' })
    res.status(500).json({ ok: false, message: 'Unable to complete request' })
  }
})

router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, username, identifier, password } = req.body || {}
    const identifierValue = email || username || identifier
    if (typeof identifierValue !== 'string' || typeof password !== 'string' || !identifierValue.trim() || !password || password.length > 1024) return res.status(400).json({ ok: false, message: 'Email and password are required' })
    const raw = identifierValue.trim()

    const lower = raw.toLowerCase()
    const db = await getDBFn()
    const admin = await db.collection('admins').findOne({
      $or: [{ email: lower }, { username: lower }, { username: raw }],
    })
    if (!admin || !(await bcrypt.compare(password, admin.password)))
      return res.status(401).json({ ok: false, message: 'Invalid credentials' })

    const identity = admin.email || admin.username
    const jti = randomUUID()
    const token = jwt.sign({ id: admin._id.toString(), username: identity, jti }, jwtSecret, { expiresIn: '8h' })
    const claims = jwt.verify(token, jwtSecret)
    await db.collection(ADMIN_SESSION_COLLECTION).insertOne({
      _id: jti,
      adminId: claims.id,
      username: identity,
      createdAt: new Date(),
      expiresAt: new Date(claims.exp * 1000),
    })
    res.cookie('adminToken', token, cookieOptions).json({ ok: true, username: identity })
  } catch {
    console.error('[AUTH] ADMIN_LOGIN_FAILED')
    res.status(500).json({ ok: false, message: 'Unable to complete request' })
  }
})

router.get('/private-entry-check', privateEntryLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store')
  res.set('X-Robots-Tag', 'noindex, nofollow, noarchive')
  const normalize = (value) => {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('?') || value.includes('#')) return ''
    return value.replace(/\\/g, '/').replace(/\/{2,}/g, '/').replace(/\/$/, '')
  }
  const configuredPath = normalize(process.env.PRIVATE_ADMIN_PATH || '')
  if (!configuredPath.startsWith('/manage/')) return res.status(404).json({ ok: false })
  const expected = Buffer.from(configuredPath)
  const provided = Buffer.from(normalize(req.get('X-Private-Admin-Path') || ''))
  if (!expected.length || expected.length !== provided.length || !timingSafeEqual(expected, provided)) return res.status(404).json({ ok: false })
  return res.json({ ok: true })
})

router.post('/logout', async (req, res) => {
  const token = req.cookies?.adminToken
  let claims = null
  if (token) {
    try {
      claims = jwt.verify(token, jwtSecret)
    } catch {
      // Invalid and expired JWTs are already unusable.
    }
  }
  if (claims?.jti) {
    try {
      const db = await getDBFn()
      await db.collection(ADMIN_SESSION_COLLECTION).updateOne(
        { _id: claims.jti, revokedAt: { $exists: false } },
        { $set: { revokedAt: new Date() } },
      )
    } catch {
      // Keep the cookie so the caller can retry; a copied token could still
      // be active until revocation is recorded.
      return res.status(503).json({ ok: false, message: 'Unable to invalidate the session. Please retry.' })
    }
  }
  const { maxAge: _maxAge, ...clearOptions } = cookieOptions
  res.clearCookie('adminToken', clearOptions)
  return res.json({ ok: true })
})

router.get('/me', async (req, res) => {
  try {
    const claims = await getActiveAdminSession(req.cookies?.adminToken, { getDBFn, jwtSecret })
    if (!claims) return res.status(401).json({ ok: false, message: 'Session expired' })
    return res.json({ ok: true, username: claims.username })
  } catch {
    return res.status(503).json({ ok: false, message: 'Authentication service unavailable' })
  }
})

  return router
}

export default createAdminAuthRouter()
