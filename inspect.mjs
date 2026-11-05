import 'dotenv/config'
import { getDB } from './lib/db.js'

const db = await getDB()
const admins = db.collection('admins')
const count = await admins.countDocuments()
console.log('admins count:', count)
const docs = await admins.find({}).toArray()
for (const d of docs) {
  console.log(JSON.stringify({ _id: d._id, username: d.username, email: d.email, role: d.role, createdAt: d.createdAt, hasPassword: !!d.password }, null, 2))
}
// also list collections
const cols = await db.listCollections().toArray()
console.log('collections:', cols.map(c => c.name))
process.exit(0)
