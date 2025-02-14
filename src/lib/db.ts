import { eq } from 'drizzle-orm'
import { db } from '../db'
import { users, UserSelect } from '../db/schema'

export async function selectUserByEmail(email: string): Promise<UserSelect | null> {
    const data = await db.select().from(users).where(eq(users.email, email))
    if (!data.length) return null
    return data[0]
}
