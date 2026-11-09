import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { randomUUID } from 'node:crypto'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import express from 'express'
import cookieParser from 'cookie-parser'

process.env.JWT_SECRET = 'local-test-jwt-secret-not-for-production'
process.env.PRIVATE_ADMIN_PATH = `/manage/${randomUUID()}`
process.env.ADMIN_REGISTER_KEY = 'local-test-registration-key'
process.env.NODE_ENV = 'production'

const { createAdminAuthRouter, createAdminCookieOptions } = await import('../api/admin/auth.js')
const { createAdminContentRouter } = await import('../api/admin/content.js')

const JWT_SECRET = process.env.JWT_SECRET
const PASSWORD = 'local-test-password'
const admin = {
  _id: 'admin-test-id',
  email: 'admin@example.test',
  username: 'admin@example.test',
  password: await bcrypt.hash(PASSWORD, 4),
}

function matchesSession(session, query) {
  if (!session || session._id !== query._id || session.adminId !== query.adminId) return false
  if (query.revokedAt?.$exists === false && 'revokedAt' in session) return false
  if (query.expiresAt?.$gt && !(session.expiresAt > query.expiresAt.$gt)) return false
  return true
}

function createFakeDatabase() {
  const sessions = new Map()
  const counters = new Map()
  const registeredAdmins = []
  const sessionCollection = {
    async insertOne(doc) {
      if (sessions.has(doc._id)) throw new Error('duplicate session id')
      sessions.set(doc._id, structuredClone(doc))
    },
    async findOne(query) {
      const session = sessions.get(query._id)
      return matchesSession(session, query) ? structuredClone(session) : null
    },
    async updateOne(query, update) {
      const session = sessions.get(query._id)
      if (!session || (query.revokedAt?.$exists === false && 'revokedAt' in session)) {
        return { matchedCount: 0 }
      }
      Object.assign(session, update.$set)
      return { matchedCount: 1 }
    },
  }
  const counterCollection = {
    async updateOne(query, update) {
      const current = counters.get(query._id) || { _id: query._id, ...update.$setOnInsert, count: 0 }
      current.count += update.$inc.count
      counters.set(query._id, current)
    },
    async findOne(query) {
      return counters.get(query._id) || null
    },
  }
  const adminCollection = {
    async findOne(query) {
      if (query?.$or?.length === 3) return admin
      const candidates = [admin, ...registeredAdmins]
      return candidates.find((candidate) => query?.$or?.some((condition) =>
        (condition.email && condition.email === candidate.email) ||
        (condition.username && condition.username === candidate.username),
      )) || null
    },
    async countDocuments() { return 1 + registeredAdmins.length },
    async insertOne(document) {
      registeredAdmins.push({ ...structuredClone(document), _id: `registered-admin-${registeredAdmins.length + 1}` })
    },
  }
  const emptyContentCollection = {
    find() { return { sort() { return { toArray: async () => [] } } } },
  }

  return {
    collection(name) {
      if (name === 'admins') return adminCollection
      if (name === 'admin_sessions') return sessionCollection
      if (name === 'admin_security_limits') return counterCollection
      if (['posts', 'blogs', 'reports', 'community_updates'].includes(name)) return emptyContentCollection
      throw new Error(`Unexpected collection: ${name}`)
    },
    sessions,
    registeredAdmins,
  }
}

async function startApp({ privateEntryLimit = 10, database = createFakeDatabase(), limiterNow = Date.now, nodeEnv = 'production' } = {}) {
  const app = express()
  app.set('trust proxy', 1)
  app.use(express.json())
  app.use(cookieParser())
  const getDBFn = async () => database
  app.use('/api/admin', createAdminAuthRouter({
    getDBFn,
    jwtSecret: JWT_SECRET,
    privateEntryLimit,
    privateEntryWindowMs: 15 * 60 * 1000,
    limiterNow,
    nodeEnv,
  }))
  app.use('/api/admin/content', createAdminContentRouter({ getDBFn, jwtSecret: JWT_SECRET }))

  const server = app.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return {
    database,
    base: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  }
}

async function withApp(options, callback) {
  const app = await startApp(options)
  try {
    return await callback(app)
  } finally {
    await app.close()
  }
}

function createFailingAdminDatabase(failurePoint, internalMessage) {
  const database = createFakeDatabase()
  return {
    registeredAdmins: database.registeredAdmins,
    collection(name) {
      if (name !== 'admins') return database.collection(name)
      return {
        async countDocuments() {
          if (failurePoint === 'registration') throw new Error(internalMessage)
          return 1
        },
        async findOne(query) {
          if (failurePoint === 'login' && query?.$or?.length === 3) throw new Error(internalMessage)
          return null
        },
      }
    },
  }
}

async function captureAuthErrorLogs(callback) {
  const originalError = console.error
  const entries = []
  console.error = (...args) => entries.push(args.map((value) => typeof value === 'string' ? value : '[non-string]').join(' '))
  try {
    return { result: await callback(), entries }
  } finally {
    console.error = originalError
  }
}

test('wrong private path is rejected and repeated guesses receive 429', async () => {
  let currentTime = Date.now()
  await withApp({ privateEntryLimit: 3, limiterNow: () => currentTime }, async ({ base }) => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await fetch(`${base}/api/admin/private-entry-check`, {
        headers: { 'X-Private-Admin-Path': '/manage/wrong-guess' },
      })
      assert.equal(response.status, 404)
    }
    const blocked = await fetch(`${base}/api/admin/private-entry-check`, {
      headers: { 'X-Private-Admin-Path': process.env.PRIVATE_ADMIN_PATH },
    })
    assert.equal(blocked.status, 429)
    assert.ok(Number(blocked.headers.get('retry-after')) > 0)

    const otherClient = await fetch(`${base}/api/admin/private-entry-check`, {
      headers: {
        'X-Private-Admin-Path': '/manage/wrong-guess',
        'X-Forwarded-For': '198.51.100.9',
      },
    })
    assert.equal(otherClient.status, 404, 'a separate client IP has an independent counter')

    currentTime += 15 * 60 * 1000
    const afterCooldown = await fetch(`${base}/api/admin/private-entry-check`, {
      headers: { 'X-Private-Admin-Path': '/manage/wrong-guess' },
    })
    assert.equal(afterCooldown.status, 404, 'the temporary cooldown expires after the fixed window')
  })
})

test('the configured private path check succeeds without creating an authenticated session', async () => {
  await withApp({}, async ({ base }) => {
    const entry = await fetch(`${base}/api/admin/private-entry-check`, {
      headers: { 'X-Private-Admin-Path': process.env.PRIVATE_ADMIN_PATH },
    })
    assert.equal(entry.status, 200)

    const me = await fetch(`${base}/api/admin/me`)
    assert.equal(me.status, 401)
    assert.equal(me.headers.get('set-cookie'), null)
  })
})

test('protected Posts, Blogs, Reports, and Updates APIs reject requests without a session', async () => {
  await withApp({}, async ({ base }) => {
    for (const section of ['posts', 'blogs', 'reports', 'updates']) {
      const response = await fetch(`${base}/api/admin/content/${section}`)
      assert.equal(response.status, 401, `${section} must require an admin session`)
    }
  })
})

test('logout revokes a copied JWT and returns a matching production cookie clear', async () => {
  await withApp({}, async ({ base }) => {
    const login = await fetch(`${base}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: admin.email, password: PASSWORD }),
    })
    assert.equal(login.status, 200)
    const issuedCookie = login.headers.get('set-cookie')
    assert.match(issuedCookie, /HttpOnly/i)
    assert.match(issuedCookie, /Secure/i)
    assert.match(issuedCookie, /SameSite=None/i)
    assert.match(issuedCookie, /Path=\//i)
    assert.match(issuedCookie, /Max-Age=28800/i)
    const token = issuedCookie.match(/adminToken=([^;]+)/)?.[1]
    assert.ok(token)
    const copiedCookie = `adminToken=${token}`

    const active = await fetch(`${base}/api/admin/me`, { headers: { Cookie: copiedCookie } })
    assert.equal(active.status, 200)
    const protectedResponse = await fetch(`${base}/api/admin/content/posts`, { headers: { Cookie: copiedCookie } })
    assert.equal(protectedResponse.status, 200)

    const logout = await fetch(`${base}/api/admin/logout`, { method: 'POST', headers: { Cookie: copiedCookie } })
    assert.equal(logout.status, 200)
    const clearedCookie = logout.headers.get('set-cookie')
    assert.match(clearedCookie, /HttpOnly/i)
    assert.match(clearedCookie, /Secure/i)
    assert.match(clearedCookie, /SameSite=None/i)
    assert.match(clearedCookie, /Path=\//i)
    assert.match(clearedCookie, /Expires=Thu, 01 Jan 1970/i)

    const replay = await fetch(`${base}/api/admin/me`, { headers: { Cookie: copiedCookie } })
    assert.equal(replay.status, 401)
    const replayProtected = await fetch(`${base}/api/admin/content/posts`, { headers: { Cookie: copiedCookie } })
    assert.equal(replayProtected.status, 401)
  })
})

test('admin cookies use secure cross-site settings in production and local settings in development', async () => {
  assert.deepEqual(createAdminCookieOptions('production'), {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  })
  assert.deepEqual(createAdminCookieOptions('development'), {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  })

  await withApp({ nodeEnv: 'development' }, async ({ base }) => {
    const login = await fetch(`${base}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: admin.email, password: PASSWORD }),
    })
    assert.equal(login.status, 200)
    const cookie = login.headers.get('set-cookie')
    assert.match(cookie, /HttpOnly/i)
    assert.match(cookie, /SameSite=Lax/i)
    assert.doesNotMatch(cookie, /; Secure/i)
    assert.match(cookie, /Path=\//i)
    assert.match(cookie, /Max-Age=28800/i)
  })
})

test('invalid and expired JWTs are rejected by session and content APIs', async () => {
  await withApp({}, async ({ base }) => {
    const expired = jwt.sign({ id: admin._id, username: admin.username, jti: 'expired-session' }, JWT_SECRET, { expiresIn: -1 })
    const noSessionId = jwt.sign({ id: admin._id, username: admin.username }, JWT_SECRET, { expiresIn: '1h' })
    for (const token of ['not-a-jwt', expired, noSessionId]) {
      const headers = { Cookie: `adminToken=${token}` }
      assert.equal((await fetch(`${base}/api/admin/me`, { headers })).status, 401)
      assert.equal((await fetch(`${base}/api/admin/content/posts`, { headers })).status, 401)
    }
  })
})

test('expired database sessions and Mongo failures fail closed', async () => {
  const database = createFakeDatabase()
  const expiredJti = 'expired-database-session'
  const expiredToken = jwt.sign({ id: admin._id, username: admin.username, jti: expiredJti }, JWT_SECRET, { expiresIn: '1h' })
  database.sessions.set(expiredJti, {
    _id: expiredJti,
    adminId: admin._id,
    expiresAt: new Date(Date.now() - 60_000),
  })

  const failingDatabase = {
    collection(name) {
      if (name === 'admin_sessions') {
        return {
          async findOne() { throw new Error('test database read failure') },
          async updateOne() { throw new Error('test database write failure') },
        }
      }
      if (name === 'admin_security_limits') {
        return {
          async updateOne() { throw new Error('test limiter write failure') },
        }
      }
      return database.collection(name)
    },
  }

  await withApp({ database }, async ({ base }) => {
    assert.equal((await fetch(`${base}/api/admin/me`, { headers: { Cookie: `adminToken=${expiredToken}` } })).status, 401)
  })

  await withApp({ database: failingDatabase }, async ({ base }) => {
    const token = jwt.sign({ id: admin._id, username: admin.username, jti: 'mongo-error-session' }, JWT_SECRET, { expiresIn: '1h' })
    const cookie = `adminToken=${token}`
    const privateCheck = await fetch(`${base}/api/admin/private-entry-check`, {
      headers: { 'X-Private-Admin-Path': process.env.PRIVATE_ADMIN_PATH },
    })
    assert.equal(privateCheck.status, 503)

    const sessionCheck = await fetch(`${base}/api/admin/me`, { headers: { Cookie: cookie } })
    assert.equal(sessionCheck.status, 503)

    const logout = await fetch(`${base}/api/admin/logout`, { method: 'POST', headers: { Cookie: cookie } })
    assert.equal(logout.status, 503)
    assert.equal(logout.headers.get('set-cookie'), null, 'do not clear the cookie before revocation succeeds')

    const protectedApi = await fetch(`${base}/api/admin/content/posts`, { headers: { Cookie: cookie } })
    assert.equal(protectedApi.status, 503)
  })
})

test('login rate limiting remains active per client within the cooldown window', async () => {
  await withApp({}, async ({ base }) => {
    const statuses = []
    for (let attempt = 0; attempt < 6; attempt += 1) {
      const response = await fetch(`${base}/api/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: admin.email, password: 'wrong-password' }),
      })
      statuses.push(response.status)
    }
    assert.deepEqual(statuses, [401, 401, 401, 401, 401, 429])
  })
})

test('registration rejects missing and incorrect registration keys', async () => {
  await withApp({}, async ({ base }) => {
    for (const key of [null, 'wrong-key']) {
      const headers = { 'Content-Type': 'application/json' }
      if (key) headers['X-Admin-Registration-Key'] = key
      const response = await fetch(`${base}/api/admin/register`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email: 'new@example.test', password: 'long-test-password' }),
      })
      assert.equal(response.status, 403)
    }
  })
})

test('registration accepts a correct key and a password at bcryptjs UTF-8 byte limit', async () => {
  const password = '\u00e9'.repeat(36)
  assert.equal(Buffer.byteLength(password, 'utf8'), 72)
  assert.equal(bcrypt.truncates(password), false)

  const database = createFakeDatabase()
  await withApp({ database }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'new-admin@example.test', password }),
    })

    assert.equal(response.status, 201)
    assert.equal(database.registeredAdmins.length, 1)
    assert.match(database.registeredAdmins[0].password, /^\$2[ab]\$12\$/)
    assert.equal(await bcrypt.compare(password, database.registeredAdmins[0].password), true)
  })
})

test('registration rejects passwords bcryptjs would truncate, including multibyte UTF-8', async () => {
  const passwords = ['a'.repeat(73), '\u00e9'.repeat(37)]

  for (const [index, password] of passwords.entries()) {
    assert.equal(bcrypt.truncates(password), true)
    const database = createFakeDatabase()

    await withApp({ database }, async ({ base }) => {
      const response = await fetch(`${base}/api/admin/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
        },
        body: JSON.stringify({ email: `long-password-${index}@example.test`, password }),
      })

      assert.equal(response.status, 400)
      assert.match((await response.json()).message, /72 UTF-8 bytes or fewer/)
      assert.equal(database.registeredAdmins.length, 0)
    })
  }
})

test('registration database failures log only a safe event and return a generic response', async () => {
  const internalMessage = 'SYNTHETIC_DATABASE_TOPOLOGY_ERROR_MARKER'
  const email = 'registration-log-test@example.test'
  const password = 'test-only-registration-password'
  const database = createFailingAdminDatabase('registration', internalMessage)

  const { result, entries } = await captureAuthErrorLogs(() => withApp({ database }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email, password }),
    })
    return { status: response.status, body: await response.json() }
  }))

  assert.deepEqual(result, { status: 500, body: { ok: false, message: 'Unable to complete request' } })
  assert.deepEqual(entries, ['[AUTH] ADMIN_REGISTRATION_FAILED'])
  const logged = entries.join('\n')
  for (const sensitiveValue of [internalMessage, email, password, process.env.ADMIN_REGISTER_KEY]) {
    assert.equal(logged.includes(sensitiveValue), false)
    assert.equal(JSON.stringify(result.body).includes(sensitiveValue), false)
  }
})

test('login database failures log only a safe event and return a generic response', async () => {
  const internalMessage = 'SYNTHETIC_LOGIN_DATABASE_ERROR_MARKER'
  const password = 'test-only-login-password'
  const database = createFailingAdminDatabase('login', internalMessage)

  const { result, entries } = await captureAuthErrorLogs(() => withApp({ database }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: admin.email, password }),
    })
    return { status: response.status, body: await response.json() }
  }))

  assert.deepEqual(result, { status: 500, body: { ok: false, message: 'Unable to complete request' } })
  assert.deepEqual(entries, ['[AUTH] ADMIN_LOGIN_FAILED'])
  const logged = entries.join('\n')
  for (const sensitiveValue of [internalMessage, admin.email, password]) {
    assert.equal(logged.includes(sensitiveValue), false)
    assert.equal(JSON.stringify(result.body).includes(sensitiveValue), false)
  }
})
