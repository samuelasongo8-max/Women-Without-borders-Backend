import jwt from 'jsonwebtoken'
import { getDB } from './db.js'

export const ADMIN_SESSION_COLLECTION = 'admin_sessions'

export async function getActiveAdminSession(token, {
  getDBFn = getDB,
  jwtSecret = process.env.JWT_SECRET,
} = {}) {
  if (!token || !jwtSecret) return null

  let claims
  try {
    claims = jwt.verify(token, jwtSecret)
  } catch {
    return null
  }

  if (!claims.id || !claims.jti) return null

  const db = await getDBFn()
  const session = await db.collection(ADMIN_SESSION_COLLECTION).findOne({
    _id: claims.jti,
    adminId: claims.id,
    revokedAt: { $exists: false },
    expiresAt: { $gt: new Date() },
  })

  return session ? claims : null
}

export function createRequireAdmin({
  getDBFn = getDB,
  jwtSecret = process.env.JWT_SECRET,
} = {}) {
  return async function requireAdmin(req, res, next) {
    const token = req.cookies?.adminToken
    if (!token) return res.status(401).json({ ok: false, message: 'Not authenticated' })

    try {
      const claims = await getActiveAdminSession(token, { getDBFn, jwtSecret })
      if (!claims) return res.status(401).json({ ok: false, message: 'Session expired' })
      req.admin = claims
      return next()
    } catch {
      return res.status(503).json({ ok: false, message: 'Authentication service unavailable' })
    }
  }
}
