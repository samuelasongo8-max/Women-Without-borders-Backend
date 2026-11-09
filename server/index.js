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
import { createCorsOptions, corsErrorHandler } from '../lib/cors.js'

const app = express()
const port = Number(process.env.PORT || 4000)
// Render terminates TLS and forwards the client address through its single
// trusted edge proxy. Never enable this in development or trust all hops.
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : false)
const corsOptions = createCorsOptions()

app.disable('x-powered-by')
app.use(cors(corsOptions))
app.options(/.*/, cors(corsOptions))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())

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

app.use(corsErrorHandler)

app.listen(port, () => {
  console.log(`[SERVER] Running on port ${port} ✅`)
  console.log('[ENV] JWT_SECRET set:', !!process.env.JWT_SECRET)
  console.log('[ENV] MONGODB_URI set:', !!process.env.MONGODB_URI)
  console.log('[ENV] CORS_ORIGIN:', process.env.CORS_ORIGIN || 'not set')
})
