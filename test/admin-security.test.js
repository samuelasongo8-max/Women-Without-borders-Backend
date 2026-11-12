import test from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import express from 'express'
import cookieParser from 'cookie-parser'

process.env.JWT_SECRET = 'local-test-jwt-secret-not-for-production'
process.env.ADMIN_REGISTER_KEY = 'local-test-registration-key-with-at-least-thirty-two-bytes'
process.env.NODE_ENV = 'production'

const { createAdminAuthRouter, createAdminCookieOptions } = await import('../api/admin/auth.js')
const { createAdminContentRouter } = await import('../api/admin/content.js')

const JWT_SECRET = process.env.JWT_SECRET
const PASSWORD = 'local-test-password-for-first-admin'
const SECOND_PASSWORD = 'local-test-password-for-second-admin'
const admin = {
  _id: 'admin-test-id',
  email: 'admin@test.com',
  username: 'admin@test.com',
  password: await bcrypt.hash(PASSWORD, 4),
}
const secondAdmin = {
  _id: 'second-admin-test-id',
  email: 'samuelasongoinfoo@gmail.com',
  username: 'samuelasongoinfoo@gmail.com',
  password: await bcrypt.hash(SECOND_PASSWORD, 4),
}

function matchesSession(session, query) {
  if (!session || session._id !== query._id || session.adminId !== query.adminId) return false
  if (query.revokedAt?.$exists === false && 'revokedAt' in session) return false
  if (query.expiresAt?.$gt && !(session.expiresAt > query.expiresAt.$gt)) return false
  return true
}

function matchesCounter(counter, query) {
  if (!counter) return false
  return Object.entries(query).every(([key, value]) => {
    if (value && typeof value === 'object' && '$lte' in value) {
      return new Date(counter[key]).getTime() <= new Date(value.$lte).getTime()
    }
    return counter[key] === value
  })
}

function createFakeDatabase({ failNextAdminInsert = false } = {}) {
  const sessions = new Map()
  const counters = new Map()
  const existingAdmins = [admin, secondAdmin]
  const registeredAdmins = []
  let shouldFailAdminInsert = failNextAdminInsert
  const sharedContent = {
    posts: [{ _id: 'shared-post', topic: 'Existing shared post' }],
    blogs: [],
    reports: [{ _id: 'shared-report', reportTitle: 'Existing shared report' }],
    community_updates: [{ _id: 'shared-update', title: 'Existing shared update' }],
  }
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
    async insertOne(document) {
      if (counters.has(document._id)) {
        const error = new Error('duplicate key')
        error.code = 11000
        throw error
      }
      counters.set(document._id, structuredClone(document))
      return { insertedId: document._id }
    },
    async updateOne(query, update, options = {}) {
      let current = counters.get(query._id)
      if (current && !matchesCounter(current, query)) {
        return { matchedCount: 0, modifiedCount: 0 }
      }
      if (!current && !options.upsert) return { matchedCount: 0, modifiedCount: 0 }
      if (!current) current = { _id: query._id, ...(update.$setOnInsert || {}) }
      if (update.$inc) {
        for (const [key, value] of Object.entries(update.$inc)) current[key] = (current[key] || 0) + value
      }
      Object.assign(current, update.$set || {})
      for (const key of Object.keys(update.$unset || {})) delete current[key]
      counters.set(query._id, current)
      return { matchedCount: 1, modifiedCount: 1 }
    },
    async findOne(query) {
      const value = counters.get(query._id)
      return matchesCounter(value, query) ? structuredClone(value) : null
    },
  }
  const adminCollection = {
    async findOne(query) {
      const candidates = [...existingAdmins, ...registeredAdmins]
      if (query?.$or) {
        return candidates.find((candidate) => query.$or.some((condition) =>
          Object.entries(condition).every(([key, value]) => candidate[key] === value),
        )) || null
      }
      return candidates.find((candidate) =>
        Object.entries(query).every(([key, value]) => candidate[key] === value),
      ) || null
    },
    async countDocuments() { return existingAdmins.length + registeredAdmins.length },
    async insertOne(document) {
      if (shouldFailAdminInsert) {
        shouldFailAdminInsert = false
        throw new Error('synthetic insert failure')
      }
      const candidates = [...existingAdmins, ...registeredAdmins]
      if (candidates.some((candidate) => candidate._id === document._id || candidate.email === document.email || candidate.username === document.username)) {
        const error = new Error('duplicate key')
        error.code = 11000
        throw error
      }
      const registeredAdmin = { ...structuredClone(document), _id: document._id || `registered-admin-${registeredAdmins.length + 1}` }
      registeredAdmins.push(registeredAdmin)
      return { insertedId: registeredAdmin._id }
    },
  }
  const contentCollection = (name) => ({
    find() { return { sort() { return { toArray: async () => structuredClone(sharedContent[name]) } } } },
    async insertOne(document) {
      const record = { ...structuredClone(document), _id: `shared-${name}-${sharedContent[name].length + 1}` }
      sharedContent[name].push(record)
      return { insertedId: record._id }
    },
  })

  return {
    collection(name) {
      if (name === 'admins') return adminCollection
      if (name === 'admin_sessions') return sessionCollection
      if (name === 'admin_security_limits') return counterCollection
      if (Object.hasOwn(sharedContent, name)) return contentCollection(name)
      throw new Error(`Unexpected collection: ${name}`)
    },
    sessions,
    counters,
    existingAdmins,
    registeredAdmins,
    sharedContent,
  }
}

async function startApp({ database = createFakeDatabase(), nodeEnv = 'production', authOptions = {} } = {}) {
  const app = express()
  app.set('trust proxy', 1)
  app.use(express.json())
  app.use(cookieParser())
  const getDBFn = async () => database
  app.use('/api/admin', createAdminAuthRouter({
    getDBFn,
    jwtSecret: JWT_SECRET,
    nodeEnv,
    ...authOptions,
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
          return 2
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

test('invalid administrator credentials are rejected without issuing a session', async () => {
  await withApp({}, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: admin.email, password: 'wrong-test-password' }),
    })
    assert.equal(response.status, 401)
    assert.deepEqual(await response.json(), { ok: false, message: 'Invalid credentials' })
    assert.equal(response.headers.get('set-cookie'), null)
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

    const savedKey = process.env.ADMIN_REGISTER_KEY
    process.env.ADMIN_REGISTER_KEY = 'too-short-test-key'
    try {
      const response = await fetch(`${base}/api/admin/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
        },
        body: JSON.stringify({ email: 'short-key@example.test', password: 'a-long-enough-test-password' }),
      })
      assert.equal(response.status, 403)
    } finally {
      process.env.ADMIN_REGISTER_KEY = savedKey
    }
  })
})

test('the one-time registration creates exactly the third administrator and preserves both existing accounts', async () => {
  const password = '\u00e9'.repeat(36)
  assert.equal(Buffer.byteLength(password, 'utf8'), 72)
  assert.equal(bcrypt.truncates(password), false)

  const database = createFakeDatabase()
  const originalAccounts = database.existingAdmins.map(({ email, username, password: hash }) => ({ email, username, hash }))
  await withApp({ database }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'third-admin@example.test', password }),
    })

    assert.equal(response.status, 201)
    assert.equal(database.registeredAdmins.length, 1)
    assert.match(database.registeredAdmins[0].password, /^\$2[ab]\$12\$/)
    assert.equal(await bcrypt.compare(password, database.registeredAdmins[0].password), true)
    assert.deepEqual(
      database.existingAdmins.map(({ email, username, password: hash }) => ({ email, username, hash })),
      originalAccounts,
    )
    assert.equal(await database.collection('admins').countDocuments(), 3)
    assert.equal(database.counters.get('admin-registration-third-account').state, 'consumed')

    const fourth = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'fourth-admin@example.test', password: 'another-long-test-password' }),
    })
    assert.equal(fourth.status, 409)
    assert.equal((await fourth.json()).message, 'Administrator account limit reached. This website supports a maximum of three administrator accounts.')
    assert.equal(database.registeredAdmins.length, 1)

    const savedKey = process.env.ADMIN_REGISTER_KEY
    process.env.ADMIN_REGISTER_KEY = ''
    try {
      const disabled = await fetch(`${base}/api/admin/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Registration-Key': savedKey,
        },
        body: JSON.stringify({ email: 'disabled-admin@example.test', password: 'another-long-test-password' }),
      })
      assert.equal(disabled.status, 403)
    } finally {
      process.env.ADMIN_REGISTER_KEY = savedKey
    }
  })
})

test('simultaneous authorized registrations can claim only one third-admin slot', async () => {
  const database = createFakeDatabase()
  await withApp({ database }, async ({ base }) => {
    const responses = await Promise.all(['one', 'two'].map((suffix) => fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: `concurrent-${suffix}@example.test`, password: 'a-secure-local-test-password' }),
    })))

    assert.deepEqual(responses.map((response) => response.status).sort(), [201, 409])
    assert.equal(database.registeredAdmins.length, 1)
    assert.equal(await database.collection('admins').countDocuments(), 3)
  })
})

test('an abandoned third-admin claim is recovered after its lease without allowing a fourth account', async () => {
  const database = createFakeDatabase()
  const testNow = 1_000_000
  database.counters.set('admin-registration-third-account', {
    _id: 'admin-registration-third-account',
    state: 'claimed',
    claimId: 'abandoned-request',
    claimedAt: new Date(testNow - 60_001),
  })

  await withApp({
    database,
    authOptions: { now: () => testNow, registrationClaimLeaseMs: 60_000 },
  }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'recovered-owner@example.test', password: 'a-secure-local-test-password' }),
    })

    assert.equal(response.status, 201)
    assert.equal(await database.collection('admins').countDocuments(), 3)
    assert.equal(database.registeredAdmins[0]._id, 'owner-created-third-administrator')
    assert.equal(database.counters.get('admin-registration-third-account').state, 'consumed')

    const fourth = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'fourth-after-recovery@example.test', password: 'a-secure-local-test-password' }),
    })
    assert.equal(fourth.status, 409)
    assert.equal(await database.collection('admins').countDocuments(), 3)
  })
})

test('a failed third-admin insert releases its own claim so the owner can retry safely', async () => {
  const database = createFakeDatabase({ failNextAdminInsert: true })
  await withApp({ database }, async ({ base }) => {
    const request = (email) => fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email, password: 'a-secure-local-test-password' }),
    })

    const failed = await request('retry-owner@example.test')
    assert.equal(failed.status, 500)
    assert.equal(await database.collection('admins').countDocuments(), 2)
    assert.equal(database.counters.get('admin-registration-third-account').state, 'open')

    const retried = await request('retry-owner@example.test')
    assert.equal(retried.status, 201)
    assert.equal(await database.collection('admins').countDocuments(), 3)
    assert.equal(database.counters.get('admin-registration-third-account').state, 'consumed')
  })
})

test('a consumed registration marker remains closed even if the database is manually altered', async () => {
  const database = createFakeDatabase()
  database.counters.set('admin-registration-third-account', {
    _id: 'admin-registration-third-account',
    state: 'consumed',
    adminId: 'owner-created-third-administrator',
    consumedAt: new Date(),
  })

  await withApp({ database }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'replacement-owner@example.test', password: 'a-secure-local-test-password' }),
    })
    assert.equal(response.status, 409)
    assert.equal((await response.json()).message, 'Administrator account limit reached. This website supports a maximum of three administrator accounts.')
    assert.equal(await database.collection('admins').countDocuments(), 2)
  })
})

test('all three administrators use the same dashboard data and can see a shared update', async () => {
  const database = createFakeDatabase()
  const originalAccounts = database.existingAdmins.map(({ email, username, password: hash }) => ({ email, username, hash }))

  await withApp({ database }, async ({ base }) => {
    const registration = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'third-admin@example.test', password: 'third-admin-test-password' }),
    })
    assert.equal(registration.status, 201)

    const credentials = [
      { email: admin.email, password: PASSWORD },
      { email: secondAdmin.email, password: SECOND_PASSWORD },
      { email: 'third-admin@example.test', password: 'third-admin-test-password' },
    ]
    const sessions = []
    for (const account of credentials) {
      const login = await fetch(`${base}/api/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(account),
      })
      assert.equal(login.status, 200)
      sessions.push(login.headers.get('set-cookie').split(';')[0])
    }

    const routeToField = { posts: 'posts', reports: 'reports', updates: 'updates' }
    const expectedContentIds = { posts: 'shared-post', reports: 'shared-report', updates: 'shared-update' }
    for (const cookie of sessions) {
      for (const [section, field] of Object.entries(routeToField)) {
        const response = await fetch(`${base}/api/admin/content/${section}`, { headers: { Cookie: cookie } })
        assert.equal(response.status, 200)
        const body = await response.json()
        assert.equal(body[field].length, 1)
        assert.equal(body[field][0]._id, expectedContentIds[section])
      }
    }

    const form = new FormData()
    form.set('title', 'Shared update created by third admin')
    form.set('update', 'A shared update stored in the common collection.')
    const createUpdate = await fetch(`${base}/api/admin/content/updates`, {
      method: 'POST',
      headers: { Cookie: sessions[2] },
      body: form,
    })
    assert.equal(createUpdate.status, 201)

    for (const cookie of sessions.slice(0, 2)) {
      const response = await fetch(`${base}/api/admin/content/updates`, { headers: { Cookie: cookie } })
      assert.equal(response.status, 200)
      const body = await response.json()
      assert.ok(body.updates.some((item) => item.title === 'Shared update created by third admin'))
    }

    assert.deepEqual(
      database.existingAdmins.map(({ email, username, password: hash }) => ({ email, username, hash })),
      originalAccounts,
    )
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

test('registration enforces a minimum 12-character password', async () => {
  const database = createFakeDatabase()
  await withApp({ database }, async ({ base }) => {
    const response = await fetch(`${base}/api/admin/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Registration-Key': process.env.ADMIN_REGISTER_KEY,
      },
      body: JSON.stringify({ email: 'short-password@example.test', password: 'short-pass' }),
    })
    assert.equal(response.status, 400)
    assert.equal((await response.json()).message, 'Password must be at least 12 characters')
    assert.equal(database.registeredAdmins.length, 0)
  })
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
