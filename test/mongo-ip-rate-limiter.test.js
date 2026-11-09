import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import express from 'express'
import { createMongoIpRateLimiter } from '../lib/mongoIpRateLimiter.js'

async function withLimiterServer(getDBFn, callback) {
  const app = express()
  app.set('trust proxy', false)
  app.use('/limited', createMongoIpRateLimiter({ getDBFn, scope: 'test', limit: 1, windowMs: 60_000, now: () => 1_000 }))
  app.get('/limited', (_req, res) => res.json({ ok: true }))
  const server = app.listen(0, '127.0.0.1')
  await once(server, 'listening')
  try {
    await callback(`http://127.0.0.1:${server.address().port}`)
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  }
}

test('Mongo rate limiter retries a concurrent first-bucket upsert and enforces the limit', async () => {
  let count = 0
  let firstUpsert = true
  const counters = {
    async updateOne(_query, update, options) {
      if (options?.upsert && firstUpsert) {
        firstUpsert = false
        count = 1 // Simulate another instance winning the initial insert race.
        const error = new Error('duplicate key')
        error.code = 11000
        throw error
      }
      count += update.$inc.count
    },
    async findOne() { return { count } },
  }
  await withLimiterServer(async () => ({ collection: () => counters }), async (base) => {
    const first = await fetch(`${base}/limited`)
    assert.equal(first.status, 429, 'the raced first request plus this request are both counted')
    assert.equal(first.headers.get('ratelimit-remaining'), '0')
    const next = await fetch(`${base}/limited`)
    assert.equal(next.status, 429)
    assert.ok(Number(next.headers.get('retry-after')) > 0)
  })
})

test('Mongo rate limiter fails closed with 503 when the database is unavailable', async () => {
  await withLimiterServer(async () => { throw new Error('database unavailable') }, async (base) => {
    const response = await fetch(`${base}/limited`)
    assert.equal(response.status, 503)
    assert.deepEqual(await response.json(), { ok: false, message: 'Security check temporarily unavailable.' })
  })
})
