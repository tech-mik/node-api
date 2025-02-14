import { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { AuthOptions, SessionTokenJWT } from '../types/auth'
import { db } from '../db'
import { refreshTokens } from '../db/schema'
import { and, eq } from 'drizzle-orm'

export function authMiddlewareFactory({ role = null, strict = false }: AuthOptions) {
    return async function (req: Request, res: Response, next: NextFunction) {
        // 1. Check if there is a access_token
        const accessToken = req.headers['authorization']?.split('Bearer ')[1]
        if (!accessToken) {
            res.status(401).json({ message: 'Unauthorized!' })
            return
        }

        try {
            // 2. Verify the access_token
            jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET as string)

            if (strict || (role && role.length)) {
                const sessionToken = req.cookies?.session_token

                if (!sessionToken) {
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }

                const decodedSessionToken = jwt.verify(sessionToken, process.env.SESSION_TOKEN_SECRET as string) as SessionTokenJWT
                if (!decodedSessionToken.sub || !decodedSessionToken.sessionId) {
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }

                const refreshToken = await db
                    .select()
                    .from(refreshTokens)
                    .where(and(eq(refreshTokens.sessionId, decodedSessionToken.sessionId), eq(refreshTokens.userId, decodedSessionToken.sub)))

                if (!refreshToken.length) {
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }

                if (role) {
                }
            }

            next()
        } catch (error) {
            res.status(401).json({ message: 'Unauthorized' })
            return
        }
    }
}
