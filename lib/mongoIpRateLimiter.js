import { createHash } from 'node:crypto'
import { getDB } from './db.js'

const COLLECTION = 'admin_security_limits'

/** Fixed-window limiter backed by Mongo so counters are shared by Render instances. */
export function createMongoIpRateLimiter({
  getDBFn = getDB,
  scope = 'default',
  limit = 10,
  windowMs = 15 * 60 * 1000,
  now = Date.now,
} = {}) {
  return async function mongoIpRateLimit(req, res, next) {
    const currentTime = now()
    const bucket = Math.floor(currentTime / windowMs)
    const expiresAt = new Date((bucket + 1) * windowMs)
    const ip = req.ip || req.socket?.remoteAddress || 'unknown'
    const key = createHash('sha256').update(`${scope}:${bucket}:${ip}`).digest('hex')

    try {
      const db = await getDBFn()
      const counters = db.collection(COLLECTION)
      try {
        await counters.updateOne(
          { _id: key },
          { $inc: { count: 1 }, $setOnInsert: { expiresAt } },
          { upsert: true },
        )
      } catch (error) {
        // Concurrent first requests on separate instances can race to upsert
        // the same unique bucket. Retry as an update after the winner inserts.
        if (error?.code !== 11000) throw error
        await counters.updateOne({ _id: key }, { $inc: { count: 1 } })
      }
      const counter = await counters.findOne({ _id: key })
      const remainingSeconds = Math.max(1, Math.ceil((expiresAt.getTime() - currentTime) / 1000))
      res.set('RateLimit-Limit', String(limit))
      res.set('RateLimit-Remaining', String(Math.max(0, limit - (counter?.count || 0))))

      if ((counter?.count || 0) > limit) {
        res.set('Retry-After', String(remainingSeconds))
        res.set('RateLimit-Reset', String(remainingSeconds))
        return res.status(429).json({ ok: false, message: 'Too many attempts. Try again later.' })
      }

      return next()
    } catch {
      return res.status(503).json({ ok: false, message: 'Security check temporarily unavailable.' })
    }
  }
}
