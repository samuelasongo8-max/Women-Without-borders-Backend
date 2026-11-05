import 'dotenv/config'
import { getDB } from './lib/db.js'

const db = await getDB()
for (const name of ['users', 'admin', 'unverifiedUsers']) {
  try {
    const col = db.collection(name)
    const count = await col.countDocuments()
    console.log(`\n=== ${name}: ${count} docs ===`)
    const docs = await col.find({}).limit(20).toArray()
    for (const d of docs) {
      // redact password hash content but show keys
      const copy = { ...d }
      if (copy.password) copy.password = `[hash len ${copy.password.length}]`
      console.log(JSON.stringify(copy))
    }
  } catch (e) {
    console.log(name, 'ERR', e.message)
  }
}
process.exit(0)
