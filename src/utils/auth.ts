import { Request } from 'express'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { FingerprintResult } from 'express-fingerprint'

export function verifyJWT(token: string, secret: string) {
    try {
        return jwt.verify(token, secret)
    } catch {
        return null
    }
}

export function generateDeviceSignature(req: Request) {
    const browser = req.useragent?.browser ?? 'unknown'
    const os = req.useragent?.os ?? 'unknown'
    const platform = req.useragent?.platform ?? 'unknown'
    const acceptEncoding = req.headers['accept-encoding'] ?? 'unknown'
    const country = req.geo?.country ?? 'unknown'
    // const count = req.useragent?.geoIp?.

    return `${browser}${os}${platform}${acceptEncoding}${country}`
}

export function createHashedDeviceSignature(req: Request) {
    const signature = generateDeviceSignature(req)
    return bcrypt.hashSync(signature, 10)
}

export function compareDeviceSignature(req: Request, hashedSignature: string) {
    const signature = generateDeviceSignature(req)
    return bcrypt.compareSync(signature, hashedSignature)
}
