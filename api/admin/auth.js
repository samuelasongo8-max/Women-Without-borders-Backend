import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { randomUUID, timingSafeEqual } from 'node:crypto'
import { getDB } from '../../lib/db.js'
import { getActiveAdminSession, ADMIN_SESSION_COLLECTION } from '../../lib/adminSession.js'
import { createMongoIpRateLimiter } from '../../lib/mongoIpRateLimiter.js'

const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET not set')

const MAX_ADMIN_ACCOUNTS = 3
const MIN_ADMIN_PASSWORD_LENGTH = 12
const MIN_REGISTRATION_KEY_BYTES = 32
const THIRD_ADMIN_SLOT_ID = 'admin-registration-third-account'
const THIRD_ADMIN_ACCOUNT_ID = 'owner-created-third-administrator'
const REGISTRATION_CLAIM_LEASE_MS = 5 * 60 * 1000
const ADMIN_ACCOUNT_LIMIT_MESSAGE = 'Administrator account limit reached. This website supports a maximum of three administrator accounts.'

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
  nodeEnv = process.env.NODE_ENV,
  now = Date.now,
  registrationClaimLeaseMs = REGISTRATION_CLAIM_LEASE_MS,
} = {}) {
  const router = express.Router()
  const cookieOptions = createAdminCookieOptions(nodeEnv)
  const claimLeaseMs = Number.isFinite(registrationClaimLeaseMs) && registrationClaimLeaseMs > 0
    ? registrationClaimLeaseMs
    : REGISTRATION_CLAIM_LEASE_MS
  const authLimiter = createMongoIpRateLimiter({
    getDBFn,
    scope: 'admin-auth',
    limit: 5,
    windowMs: 15 * 60 * 1000,
  })
  router.post('/register', authLimiter, async (req, res) => {
    let db
    let claimId

    try {
      const expectedKey = Buffer.from(process.env.ADMIN_REGISTER_KEY || '')
      const providedKey = Buffer.from(req.get('X-Admin-Registration-Key') || '')
      if (
        expectedKey.length < MIN_REGISTRATION_KEY_BYTES
        || expectedKey.length !== providedKey.length
        || !timingSafeEqual(expectedKey, providedKey)
      ) {
        return res.status(403).json({ ok: false, message: 'Registration is unavailable' })
      }

      const { email, password } = req.body || {}
      const emailValue = typeof email === 'string' ? email.trim().toLowerCase() : ''
      if (!emailValue || !isValidEmail(emailValue)) {
        return res.status(400).json({ ok: false, message: 'A valid email address is required' })
      }
      if (typeof password !== 'string' || password.length < MIN_ADMIN_PASSWORD_LENGTH) {
        return res.status(400).json({ ok: false, message: `Password must be at least ${MIN_ADMIN_PASSWORD_LENGTH} characters` })
      }
      if (bcrypt.truncates(password)) {
        return res.status(400).json({ ok: false, message: 'Password must be 72 UTF-8 bytes or fewer' })
      }

      db = await getDBFn()
      const admins = db.collection('admins')
      const count = await admins.countDocuments()
      if (count >= MAX_ADMIN_ACCOUNTS) {
        return res.status(409).json({ ok: false, message: ADMIN_ACCOUNT_LIMIT_MESSAGE })
      }
      if (count !== MAX_ADMIN_ACCOUNTS - 1) {
        return res.status(409).json({
          ok: false,
          message: 'Registration is available only after the two existing administrator accounts are present.',
        })
      }
      if (await admins.findOne({ $or: [{ email: emailValue }, { username: emailValue }] })) {
        return res.status(409).json({ ok: false, message: 'An account with this email already exists' })
      }

      const passwordHash = await bcrypt.hash(password, 12)
      const registrationState = db.collection('admin_security_limits')

      // This persistent guard shares the existing rate-limit collection. Its ID
      // is not a rate-limit hash, and it has no expiresAt field for the TTL index.
      try {
        await registrationState.insertOne({
          _id: THIRD_ADMIN_SLOT_ID,
          state: 'open',
          createdAt: new Date(),
        })
      } catch (error) {
        if (error?.code !== 11000) throw error
      }

      // A claim can be abandoned by a process crash. It is recoverable after a
      // short lease, but the fixed _id below still permits only one third admin
      // if an old process resumes after its lease has expired.
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const claimTime = new Date(now())
        const nextClaimId = randomUUID()
        const claim = await registrationState.updateOne(
          { _id: THIRD_ADMIN_SLOT_ID, state: 'open' },
          { $set: { state: 'claimed', claimId: nextClaimId, claimedAt: claimTime } },
        )
        if (claim.modifiedCount === 1) {
          claimId = nextClaimId
          break
        }

        const [latestCount, slot] = await Promise.all([
          admins.countDocuments(),
          registrationState.findOne({ _id: THIRD_ADMIN_SLOT_ID }),
        ])
        if (latestCount >= MAX_ADMIN_ACCOUNTS || slot?.state === 'consumed') {
          return res.status(409).json({ ok: false, message: ADMIN_ACCOUNT_LIMIT_MESSAGE })
        }
        if (latestCount !== MAX_ADMIN_ACCOUNTS - 1 || slot?.state !== 'claimed') {
          return res.status(409).json({
            ok: false,
            message: 'The third administrator registration is already in progress or has been used.',
          })
        }

        const claimedAt = new Date(slot.claimedAt).getTime()
        const reclaimBefore = new Date(claimTime.getTime() - claimLeaseMs)
        if (!Number.isFinite(claimedAt) || claimedAt > reclaimBefore.getTime()) {
          return res.status(409).json({
            ok: false,
            message: 'The third administrator registration is already in progress or has been used.',
          })
        }

        const reopened = await registrationState.updateOne(
          { _id: THIRD_ADMIN_SLOT_ID, state: 'claimed', claimedAt: { $lte: reclaimBefore } },
          {
            $set: { state: 'open' },
            $unset: { claimId: '', claimedAt: '' },
          },
        )
        if (reopened.modifiedCount !== 1) {
          return res.status(409).json({
            ok: false,
            message: 'The third administrator registration is already in progress or has been used.',
          })
        }
      }

      if (!claimId) {
        return res.status(409).json({
          ok: false,
          message: 'The third administrator registration is already in progress or has been used.',
        })
      }

      let insertedAdmin
      try {
        insertedAdmin = await admins.insertOne({
          _id: THIRD_ADMIN_ACCOUNT_ID,
          email: emailValue,
          username: emailValue,
          password: passwordHash,
          createdAt: new Date(),
        })
      } catch (error) {
        // Reopen only if Mongo confirms that no third account was created.
        try {
          const [latestCount, matchingAdmin] = await Promise.all([
            admins.countDocuments(),
            admins.findOne({ $or: [{ email: emailValue }, { username: emailValue }] }),
          ])
          if (latestCount === MAX_ADMIN_ACCOUNTS - 1 && !matchingAdmin) {
            await registrationState.updateOne(
              { _id: THIRD_ADMIN_SLOT_ID, state: 'claimed', claimId },
              {
                $set: { state: 'open' },
                $unset: { claimId: '', claimedAt: '' },
              },
            )
          }
        } catch {
          console.error('[AUTH] ADMIN_REGISTRATION_SLOT_RELEASE_FAILED')
        }
        throw error
      }

      try {
        await registrationState.updateOne(
          { _id: THIRD_ADMIN_SLOT_ID, state: 'claimed', claimId },
          {
            $set: { state: 'consumed', adminId: insertedAdmin.insertedId, consumedAt: new Date() },
            $unset: { claimId: '' },
          },
        )
      } catch {
        // The claimed state remains closed and the account-count check is a
        // second fail-closed guard if finalizing this marker encounters an error.
        console.error('[AUTH] ADMIN_REGISTRATION_SLOT_FINALIZE_FAILED')
      }

      return res.status(201).json({ ok: true, message: 'Account created' })
    } catch (error) {
      console.error('[AUTH] ADMIN_REGISTRATION_FAILED')
      if (error?.code === 11000) {
        return res.status(409).json({ ok: false, message: 'An account with this email already exists' })
      }
      return res.status(500).json({ ok: false, message: 'Unable to complete request' })
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
