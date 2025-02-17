import { Request, Response } from 'express'
import bcrypt from 'bcrypt'
import jwt, { verify, JwtPayload, decode, TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken'
import crypto from 'node:crypto'
import { db } from '../db'
import { refreshTokens, RefreshTokenSelect, UserSelect } from '../db/schema'
import { and, eq } from 'drizzle-orm'
import { AccessTokenJWT, ValidatedToken } from '../types/auth'
import { DrizzleError } from 'drizzle-orm'

/**
 * Verify JWT and return null if it fails
 */
export function verifyJWT<T extends JwtPayload>(token: string, secret: string): ValidatedToken<T> {
    try {
        const payload = verify(token, secret) as T
        return {
            valid: true,
            payload,
        }
    } catch (err) {
        const payload = decode(token) as T
        if (err instanceof TokenExpiredError) {
            return {
                valid: false,
                payload,
                expired: true,
            }
        } else if (err instanceof JsonWebTokenError) {
            logging.warn(`Incorrect token or signature for user with id: ${payload.sub}`)

            return {
                valid: false,
                payload,
            }
        }
        return {
            valid: false,
            payload,
        }
    }
}

/**
 * Generate a device signature based on the user agent, os, platform, accept-encoding and country
 */
export function generateSessionSignature(req: Request) {
    const browser = req.useragent?.browser ?? 'unknown'
    const os = req.useragent?.os ?? 'unknown'
    const platform = req.useragent?.platform ?? 'unknown'
    const acceptEncoding = req.headers['accept-encoding'] ?? 'unknown'
    const country = req.geo?.country ?? 'unknown'

    return `${browser}${os}${platform}${acceptEncoding}${country}`
}

/**
 * Create a hashed device signature
 */
export function generateHashedSessionSignature(req: Request) {
    const signature = generateSessionSignature(req)
    return bcrypt.hashSync(signature, 10)
}

/**
 * Compare the device signature with the hashed signature
 */
export function verifySessionSignature(req: Request, hashedSignature: string) {
    const signature = generateSessionSignature(req)
    return bcrypt.compareSync(signature, hashedSignature)
}

const ENCRYPTION_KEY = process.env.REFRESH_TOKEN_ENCRYPTION_KEY!
if (!ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY is missing.')
}

// Convert to Buffer using HEX (if key is stored in hex format)
const encryptionKeyBuffer = Buffer.from(ENCRYPTION_KEY, 'hex')

if (encryptionKeyBuffer.length !== 32) {
    throw new Error(`ENCRYPTION_KEY must be exactly 32 bytes long. Current length: ${encryptionKeyBuffer.length}`)
}

const IV_LENGTH = 16 // AES-GCM standard IV length

export function encryptToken(token: string): string {
    const iv = crypto.randomBytes(IV_LENGTH)
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKeyBuffer, iv)

    let encrypted = cipher.update(token, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    const authTag = cipher.getAuthTag().toString('hex')

    return `${iv.toString('hex')}:${authTag}:${encrypted}`
}

export function decryptToken(encryptedToken: string): string {
    const parts = encryptedToken.split(':')
    if (parts.length !== 3) {
        throw new Error('Invalid token format')
    }

    const iv = Buffer.from(parts[0], 'hex')
    const authTag = Buffer.from(parts[1], 'hex')
    const encryptedText = parts[2]

    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKeyBuffer, iv)
    decipher.setAuthTag(authTag)

    let decrypted = decipher.update(encryptedText, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
}

export async function clearSession(sessionId: RefreshTokenSelect['sessionId'], userId: UserSelect['userId'], res: Response) {
    try {
        await db.delete(refreshTokens).where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))
        res.clearCookie('token')
    } catch (error) {
        if (error instanceof Error) {
            throw new Error(error.message)
        } else if (error instanceof DrizzleError) {
            throw new Error(error.message)
        } else {
            throw new Error('Something went wrong clearing the session')
        }
    }
}
/**
 * Create an access_token
 */
export function generateAccessToken(userId: UserSelect['userId'], role: UserSelect['role']) {
    return jwt.sign(
        {
            sub: userId,
            role: role,
        },
        process.env.ACCESS_TOKEN_SECRET as string,
        { expiresIn: Number(process.env.ACCESS_TOKEN_EXPIRY) ?? '10m' },
    )
}

/**
 * Create a session token
 */
export function generateRefreshToken(userId: UserSelect['userId'], sessionId: RefreshTokenSelect['sessionId']) {
    return jwt.sign(
        {
            sub: userId,
            sessionId,
        },
        process.env.REFRESH_TOKEN_SECRET as string,
        { expiresIn: Number(process.env.REFRESH_TOKEN_EXPIRY) ?? '7d' },
    )
}

/**
 * Set the refresh_token in the cookie
 */
export function setTokenCookie(res: Response, token: string) {
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: Number(process.env.REFRESH_TOKEN_EXPIRY ?? 7 * 60 * 60) * 1000,
    })
}
