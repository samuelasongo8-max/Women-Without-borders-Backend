import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import cors from 'cors'
import { createCorsOptions, corsErrorHandler } from '../lib/cors.js'

async function withCorsServer(options, callback) {
  const app = express()
  const corsOptions = createCorsOptions(options)
  app.use(cors(corsOptions))
  app.options(/.*/, cors(corsOptions))
  app.get('/resource', (_req, res) => res.json({ ok: true }))
  app.use(corsErrorHandler)

  const server = app.listen(0, '127.0.0.1')
  await once(server, 'listening')
  try {
    await callback(`http://127.0.0.1:${server.address().port}`)
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  }
}

test('localhost origins are accepted in development', async () => {
  await withCorsServer({ nodeEnv: 'development', configuredOrigins: '' }, async (base) => {
    const response = await fetch(`${base}/resource`, { headers: { Origin: 'http://localhost:5173' } })
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://localhost:5173')
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true')
  })
})

test('localhost origins are rejected in production', async () => {
  await withCorsServer({ nodeEnv: 'production', configuredOrigins: 'https://women-without-border-hub.vercel.app,http://localhost:5173' }, async (base) => {
    const response = await fetch(`${base}/resource`, { headers: { Origin: 'http://localhost:5173' } })
    assert.equal(response.status, 403)
    assert.equal(response.headers.get('access-control-allow-origin'), null)
    assert.deepEqual(await response.json(), { ok: false, message: 'Origin not allowed' })
  })
})

test('configured production origin is accepted with credentials', async () => {
  const origin = 'https://women-without-border-hub.vercel.app'
  await withCorsServer({ nodeEnv: 'production', configuredOrigins: origin }, async (base) => {
    const response = await fetch(`${base}/resource`, { headers: { Origin: origin } })
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('access-control-allow-origin'), origin)
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true')
  })
})

test('unconfigured production browser origins are rejected', async () => {
  await withCorsServer({ nodeEnv: 'production', configuredOrigins: 'https://women-without-border-hub.vercel.app' }, async (base) => {
    const response = await fetch(`${base}/resource`, { headers: { Origin: 'https://untrusted.example' } })
    assert.equal(response.status, 403)
    assert.equal(response.headers.get('access-control-allow-origin'), null)
  })
})

test('multiple comma-separated production origins are accepted', async () => {
  const origins = ['https://women-without-border-hub.vercel.app', 'https://preview.example']
  await withCorsServer({ nodeEnv: 'production', configuredOrigins: ` ${origins[0]} , ${origins[1]} ` }, async (base) => {
    for (const origin of origins) {
      const response = await fetch(`${base}/resource`, { headers: { Origin: origin } })
      assert.equal(response.status, 200)
      assert.equal(response.headers.get('access-control-allow-origin'), origin)
      assert.equal(response.headers.get('access-control-allow-credentials'), 'true')
    }
  })
})

test('preflight uses the same allowlist and credentialed request configuration', async () => {
  const allowedOrigin = 'https://women-without-border-hub.vercel.app'
  await withCorsServer({ nodeEnv: 'production', configuredOrigins: allowedOrigin }, async (base) => {
    const allowed = await fetch(`${base}/resource`, {
      method: 'OPTIONS',
      headers: {
        Origin: allowedOrigin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type,x-private-admin-path,x-admin-registration-key',
      },
    })
    assert.equal(allowed.status, 204)
    assert.equal(allowed.headers.get('access-control-allow-origin'), allowedOrigin)
    assert.equal(allowed.headers.get('access-control-allow-credentials'), 'true')
    assert.match(allowed.headers.get('access-control-allow-methods') || '', /POST/)
    assert.match(allowed.headers.get('access-control-allow-headers') || '', /X-Private-Admin-Path/i)
    assert.match(allowed.headers.get('access-control-allow-headers') || '', /X-Admin-Registration-Key/i)

    const rejected = await fetch(`${base}/resource`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://untrusted.example',
        'Access-Control-Request-Method': 'POST',
      },
    })
    assert.equal(rejected.status, 403)
    assert.equal(rejected.headers.get('access-control-allow-origin'), null)
  })
})

test('requests without an Origin header remain allowed without wildcard CORS headers', async () => {
  await withCorsServer({ nodeEnv: 'production', configuredOrigins: '*' }, async (base) => {
    const response = await fetch(`${base}/resource`)
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('access-control-allow-origin'), null)
  })
})
