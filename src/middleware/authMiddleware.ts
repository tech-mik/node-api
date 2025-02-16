import { NextFunction, Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { AuthOptions, RefreshTokenJWT } from '../types/auth'
import { db } from '../db'
import { refreshTokens } from '../db/schema'
import { and, eq } from 'drizzle-orm'
import { decryptToken, verifyJWT } from '../utils/auth'

export function authMiddlewareFactory({ role, strict }: AuthOptions) {
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
            if (strict || role) {
                const refreshToken = req.cookies?.token

                /**
                 * Check for refresh_token in cookies, decrypt and verify it
                 */
                if (!refreshToken) {
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }

                const decryptedRefreshToken = decryptToken(refreshToken)

                const decodedRefreshToken = jwt.decode(decryptedRefreshToken) as RefreshTokenJWT
                /**
                 * Check if the refresh_token is present and has the required fields
                 */
                if (decodedRefreshToken) {
                    if (!decodedRefreshToken.sub || !decodedRefreshToken.sessionId) {
                        logging.warn('Possible fake session token detected')
                        res.clearCookie('refresh_token')
                        res.status(401).json({ message: 'Unauthorized' })
                        return
                    }

                    // TODO: Nadenken over of refresh_token wel een exp moet hebben van 24h, omdat hij toch altijd gecheckt wordt met de db en de db de enige bron van waarheid is. Plus de refresh_token wordt vernieuwd bij elke refresh

                    const dbRefreshToken = await db
                        .select()
                        .from(refreshTokens)
                        .where(and(eq(refreshTokens.sessionId, decodedRefreshToken.sessionId), eq(refreshTokens.userId, decodedRefreshToken.sub)))

                    if (!dbRefreshToken.length) {
                        res.status(401).json({ message: 'Unauthorized' })
                        return
                    }

                    if (dbRefreshToken.length > 1) {
                        /**
                         * If there are more than one refresh tokens for the same user and session, it is possible that the token is being replayed
                         */
                        logging.warn(`Possible token replay attack for user with id ${decodedRefreshToken.sub}`)

                        /**
                         * Delete refresh_token from cookies
                         */
                        res.clearCookie('refresh_token')

                        /**
                         * Delete all refresh_tokens for the user and session from db
                         */
                        await db
                            .delete(refreshTokens)
                            .where(and(eq(refreshTokens.sessionId, decodedRefreshToken.sessionId), eq(refreshTokens.userId, decodedRefreshToken.sub)))

                        res.status(401).json({ message: 'Unauthorized' })
                        return
                    }

                    // TODO: implement role check
                    if (role) {
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
