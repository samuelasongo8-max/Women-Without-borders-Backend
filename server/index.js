import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import { fileURLToPath } from 'node:url'
import adminAuth from '../api/admin/auth.js'
import adminContent from '../api/admin/content.js'
import postsRouter from '../api/posts.js'
import blogsRouter from '../api/blogs.js'
import reportsRouter from '../api/reports.js'
import updatesRouter from '../api/updates.js'

const app = express()
const port = Number(process.env.PORT || 4000)
const prodOrigins = (
  process.env.CORS_ORIGIN || ''
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)

app.disable('x-powered-by')
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true)

    // Allow ANY localhost port in development
    // This fixes the jumping port problem
    // permanently — 3001, 3002, 3003 all work
    const isLocalhost = /^http:\/\/localhost:\d+$/.test(origin)
    if (isLocalhost) {
      return callback(null, true)
    }

    // Allow your production Vercel URL
    if (prodOrigins.includes(origin)) {
      return callback(null, true)
    }

    console.warn('[CORS] Blocked:', origin)
    return callback(new Error(`CORS blocked: ${origin}`))
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
}))
app.options(/.*/, cors())
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())

// Debug logging — shows cookies on every request
app.use((req, res, next) => {
  console.log(
    '[REQ]',
    req.method,
    req.path,
    '| cookies:',
    Object.keys(req.cookies || {}).length > 0
      ? JSON.stringify(req.cookies)
      : 'none'
  )
  next()
})

app.use('/api/admin', adminAuth)
app.use('/api/admin/content', adminContent)
app.use('/api/posts', postsRouter)
app.use('/api/blogs', blogsRouter)
app.use('/api/reports', reportsRouter)
app.use('/api/updates', updatesRouter)
app.use('/uploads', express.static(fileURLToPath(new URL('../public/uploads/', import.meta.url)), {
  dotfiles: 'deny',
  index: false,
}))
app.get('/health', (_req, res) => res.json({ ok: true }))

app.listen(port, () => {
  console.log(`[SERVER] Running on port ${port} ✅`)
  console.log('[ENV] JWT_SECRET set:', !!process.env.JWT_SECRET)
  console.log('[ENV] MONGODB_URI set:', !!process.env.MONGODB_URI)
  console.log('[ENV] CORS_ORIGIN:', process.env.CORS_ORIGIN || 'not set')
})
