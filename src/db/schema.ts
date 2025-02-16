import { InferInsertModel, InferSelectModel } from 'drizzle-orm'
import { integer, pgTable, timestamp, uuid, varchar } from 'drizzle-orm/pg-core'
import { createSelectSchema } from 'drizzle-zod'
import { AccountStatus, Roles } from '../types/auth'

export const users = pgTable('users', {
    userId: uuid('user_id').primaryKey().defaultRandom(), // Unique User ID
    email: varchar('email', { length: 255 }).notNull().unique(), // Email
    password: varchar('password_hash').notNull(), // Hashed Password
    role: integer('role').notNull().default(Roles.USER),
    status: integer('status').notNull().default(AccountStatus.ACTIVE), // Account status
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow(), // Account creation timestamp
    updatedAt: timestamp('updated_at', { withTimezone: true })
        .defaultNow()
        .$onUpdateFn(() => new Date()), // Last update timestamp
})

export type UserInsert = InferInsertModel<typeof users>
export type UserSelect = InferSelectModel<typeof users>
export const userSelectSchema = createSelectSchema(users, {
    email: (schema) => schema.email(),
})

export const userLoginSchema = userSelectSchema.pick({ email: true, password: true })

export const refreshTokens = pgTable('refresh_tokens', {
    sessionId: uuid('session_id').primaryKey().defaultRandom(), // Unique Session ID
    userId: uuid('user_id')
        .notNull()
        .references(() => users.userId, { onDelete: 'cascade' }), // Foreign Key to Users Table
    signature: varchar('signature').notNull(), // Stores browser/device details
    ip: varchar('ip').notNull(), // IP Address
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
})

export type RefreshTokenInsert = typeof refreshTokens.$inferInsert
export type RefreshTokenSelect = typeof refreshTokens.$inferSelect
