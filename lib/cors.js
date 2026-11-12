export const CORS_ORIGIN_REJECTED = 'CORS_ORIGIN_REJECTED'

export function createCorsOptions({
  nodeEnv = process.env.NODE_ENV,
  configuredOrigins = process.env.CORS_ORIGIN || '',
} = {}) {
  const allowedOrigins = new Set(
    configuredOrigins
      .split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin && origin !== '*'),
  )

  return {
    origin(origin, callback) {
      if (!origin) return callback(null, true)

      if (allowedOrigins.has(origin)) {
        return callback(null, true)
      }

      const isLocalhost = /^http:\/\/localhost:\d+$/.test(origin)
      if (isLocalhost) {
        if (nodeEnv !== 'production') return callback(null, true)
        return rejectOrigin(callback)
      }

      return rejectOrigin(callback)
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Cookie',
      'X-Admin-Registration-Key',
    ],
  }
}

function rejectOrigin(callback) {
  const error = new Error('Origin not allowed')
  error.code = CORS_ORIGIN_REJECTED
  return callback(error)
}

export function corsErrorHandler(error, _req, res, next) {
  if (error?.code !== CORS_ORIGIN_REJECTED) return next(error)
  return res.status(403).json({ ok: false, message: 'Origin not allowed' })
}
