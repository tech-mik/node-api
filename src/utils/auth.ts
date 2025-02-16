import { Request } from 'express'
import bcrypt from 'bcrypt'
import { verify, JwtPayload } from 'jsonwebtoken'
import crypto from 'node:crypto'

/**
 * Verify JWT and return null if it fails
 */
export function verifyJWT<T extends object = JwtPayload>(token: string, secret: string): T | null {
    try {
        return verify(token, secret) as T
    } catch {
        return null
    }
}

/**
 * Generate a device signature based on the user agent, os, platform, accept-encoding and country
 */
export function generateDeviceSignature(req: Request) {
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
export function createHashedDeviceSignature(req: Request) {
    const signature = generateDeviceSignature(req)
    return bcrypt.hashSync(signature, 10)
}

/**
 * Compare the device signature with the hashed signature
 */
export function compareDeviceSignature(req: Request, hashedSignature: string) {
    const signature = generateDeviceSignature(req)
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
