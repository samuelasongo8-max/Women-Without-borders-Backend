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
  await database.collection('admins').createIndex({ username: 1 }, { unique: true })
  return database
}
