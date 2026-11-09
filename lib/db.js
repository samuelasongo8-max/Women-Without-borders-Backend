import { MongoClient } from 'mongodb'

let client
let database

export async function getDB() {
  if (database) return database

  const uri = process.env.MONGODB_URI
  const dbName = process.env.MONGODB_DB || 'kakuma-community-connect'
  if (!uri) throw new Error('MONGODB_URI not set')

  client = client || new MongoClient(uri)
  await client.connect()
  database = client.db(dbName)
  try {
    await database.collection('admins').createIndex({ username: 1 }, { unique: true })
  } catch {
    console.error('[DB] ADMIN_USERNAME_INDEX_SETUP_FAILED')
  }
  try {
    await database.collection('admins').createIndex({ email: 1 }, { unique: true, partialFilterExpression: { email: { $type: 'string' } } })
  } catch {
    console.error('[DB] ADMIN_EMAIL_INDEX_SETUP_FAILED')
  }
  try {
    await database.collection('admin_sessions').createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, name: 'admin_sessions_expiry' },
    )
  } catch {
    console.error('[DB] ADMIN_SESSION_TTL_INDEX_SETUP_FAILED')
  }
  try {
    await database.collection('admin_security_limits').createIndex(
      { expiresAt: 1 },
      { expireAfterSeconds: 0, name: 'admin_security_limits_expiry' },
    )
  } catch {
    console.error('[DB] ADMIN_RATE_LIMIT_TTL_INDEX_SETUP_FAILED')
  }
  return database
}
