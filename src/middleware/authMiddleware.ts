import { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { AuthOptions, SessionTokenJWT } from '../types/auth'
import { db } from '../db'
import { refreshTokens } from '../db/schema'
import { and, eq } from 'drizzle-orm'
import { decryptToken, verifyJWT } from '../utils/auth'

export function authMiddlewareFactory({ roles, strict }: AuthOptions) {
    return async function (req: Request, res: Response, next: NextFunction) {
        /**
         * Check if the access_token is present in the Authorization header
         */
        const accessToken = req.headers['authorization']?.split('Bearer ')[1]
        if (!accessToken) {
            res.status(401).json({ message: 'Unauthorized' })
            return
        }

        try {
            /**
             * Verify the access_token
             */
            const veryfiedAccessToken = verifyJWT(accessToken, process.env.ACCESS_TOKEN_SECRET as string)
            if (!veryfiedAccessToken) {
                res.status(401).json({ message: 'Unauthorized' })
                return
            }

            /**
             * Check if request is strict or if roles are needed
             */
            if (strict || (roles && roles.length)) {
                const sessionToken = req.cookies?.session_token

                /**
                 * Check for session_token in cookies, decrypt and verify it
                 */
                if (!sessionToken) {
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }

                const decryptedSessionToken = decryptToken(sessionToken)

                const decodedSessionToken = jwt.decode(decryptedSessionToken) as SessionTokenJWT
                /**
                 * Check if the session_token is present and has the required fields
                 */
                if (decodedSessionToken) {
                    if (!decodedSessionToken.sub || !decodedSessionToken.sessionId) {
                        logging.warn('Possible fake session token detected')
                        res.clearCookie('session_token')
                        res.status(401).json({ message: 'Unauthorized' })
                        return
                    }

                    // TODO: Nadenken over of session_token wel een exp moet hebben van 24h, omdat hij toch altijd gecheckt wordt met de db en de db de enige bron van waarheid is. Plus de session_token wordt vernieuwd bij elke refresh

                    const refreshToken = await db
                        .select()
                        .from(refreshTokens)
                        .where(and(eq(refreshTokens.sessionId, decodedSessionToken.sessionId), eq(refreshTokens.userId, decodedSessionToken.sub)))

                    if (!refreshToken.length) {
                        res.status(401).json({ message: 'Unauthorized' })
                        return
                    }

                    if (refreshToken.length > 1) {
                        /**
                         * If there are more than one refresh tokens for the same user and session, it is possible that the token is being replayed
                         */
                        logging.warn(`Possible token replay attack for user with id ${decodedSessionToken.sub}`)

                        /**
                         * Delete session_token from cookies
                         */
                        res.clearCookie('session_token')

                        /**
                         * Delete all refresh_tokens for the user and session from db
                         */
                        await db
                            .delete(refreshTokens)
                            .where(and(eq(refreshTokens.sessionId, decodedSessionToken.sessionId), eq(refreshTokens.userId, decodedSessionToken.sub)))

                        res.status(401).json({ message: 'Unauthorized' })
                        return
                    }

                    // TODO: implement role check
                    if (roles) {
                    }
                } else {
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }
            }

            next()
        } catch (error) {
            res.status(401).json({ message: 'Unauthorized' })
            return
        }
    }
}
