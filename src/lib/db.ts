import { eq } from 'drizzle-orm'
import { db } from '../db'
import { users } from '../db/schema'

export async function selectUserByEmail(email: string) {
    const data = await db.select().from(users).where(eq(users.email, email))

    if (!data.length) return null

    return data[0]
}
