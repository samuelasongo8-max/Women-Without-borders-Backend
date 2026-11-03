import 'dotenv/config'
import express from 'express'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import { fileURLToPath } from 'node:url'
import adminAuth from '../api/admin/auth.js'
import adminContent from '../api/admin/content.js'

const app = express()
const port = Number(process.env.PORT || 4000)

app.disable('x-powered-by')
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}))
app.use(express.json({ limit: '1mb' }))
app.use(cookieParser())
app.use('/api/admin', adminAuth)
app.use('/api/admin/content', adminContent)
app.use('/uploads', express.static(fileURLToPath(new URL('../../public/uploads/', import.meta.url)), {
  dotfiles: 'deny',
  index: false,
}))
app.get('/health', (_req, res) => res.json({ ok: true }))

app.listen(port, () => console.log(`[SERVER] Listening on port ${port}`))
