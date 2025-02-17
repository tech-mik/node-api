import bcrypt from 'bcrypt'
import { randomUUID } from 'crypto'
import { eq } from 'drizzle-orm'
import { Request, Response } from 'express'
import { db } from '../db'
import { refreshTokens, UserInsert, userLoginSchema, users } from '../db/schema'
import { Controller } from '../decorators/controller'
import { Route } from '../decorators/route'
import { selectUserByEmail } from '../lib/db'
import { RefreshTokenJWT } from '../types/auth'
import {
    clearSession,
    decryptToken,
    encryptToken,
    generateAccessToken,
    generateHashedSessionSignature,
    generateRefreshToken,
    setTokenCookie,
    verifyJWT,
    verifySessionSignature,
} from '../utils/auth'

@Controller('/auth')
class AuthController {
    /**
     * Add a new user to the database
     */
    @Route('post', '/user')
    async postUser(req: Request, res: Response) {
        if (!req.body.email) {
            res.status(400).json({ message: 'Email is required' })
            return
        }
        if (!req.body.password) {
            res.status(400).json({ message: 'Password is required' })
            return
        }

        try {
            const user: UserInsert = {
                email: req.body.email,
                password: bcrypt.hashSync(req.body.password, 10),
            }

            const newUser = await db.insert(users).values(user).returning()

            res.status(201).json({ message: 'User created', user: newUser })
        } catch (error) {
            res.status(500).json({ message: 'Internal Server Error' })
        }
    }

    /**
     * Login a user and issue an access_token and refresh_token
     */
    @Route('post', '/login')
    async postLogin(req: Request, res: Response) {
        /**
         * Validate the request body
         */
        const { success, data } = userLoginSchema.safeParse(req.body)
        if (!success) return res.status(401).json({ message: 'Invalid credentials' })

        try {
            /**
             * Check if the user exists in the database
             */
            const user = await selectUserByEmail(data.email)
            if (!user) return res.status(401).json({ message: 'Invalid credentials' })

            /**
             * Validate password
             */
            const { password, userId, role } = user

            if (!bcrypt.compareSync(data.password, password)) return res.status(401).json({ message: 'Invalid credentials' })

            /**
             * Prepare the session and create tokens
             */
            const sessionId = randomUUID()
            const signature = generateHashedSessionSignature(req)
            const ipAddress = bcrypt.hashSync(req.ip ?? 'unknown', 10)

            // Generate tokens
            const accessToken = generateAccessToken(userId, role)
            const refreshToken = generateRefreshToken(userId, sessionId)
            const encryptedRefreshToken = encryptToken(refreshToken)

            // Set the refresh token in the cookie
            setTokenCookie(res, encryptedRefreshToken)

            /**
             * Insert refresh_token into the database
             */
            await db.insert(refreshTokens).values({
                sessionId,
                userId,
                signature,
                ip: ipAddress,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
            })

            res.status(200).json({ accessToken })
        } catch (error) {
            res.status(500).json({ message: 'Internal Server Error' })
            logging.error(error)
        }
    }

    /**
     * Refresh the access_token
     */
    @Route('post', '/refresh')
    async postRefresh(req: Request, res: Response) {
        /**
         * Check if the refresh token is present
         */
        const refreshToken = req.cookies?.token
        if (!refreshToken) return res.status(401).json({ message: 'Unauthorized' })

        try {
            /**
             * Decrypt the refresh token
             */
            const decryptedRefreshToken = decryptToken(refreshToken)

            /**
             * Verify the refresh token
             */
            const {
                valid: validToken,
                payload,
                expired: expiredToken,
            } = verifyJWT<RefreshTokenJWT>(decryptedRefreshToken, process.env.REFRESH_TOKEN_SECRET as string)

            /**
             * Check if the payload is valid
             */
            if (!payload.sub || !payload.sessionId) {
                res.clearCookie('token')
                logging.warn('Possible fake session token detected')
                return res.status(401).json({ message: 'Unauthorized' })
            }

            /**
             * Check if the token is invalid but not expired
             */
            if (!validToken && !expiredToken) {
                await clearSession(payload.sessionId, payload.sub, res)
                return res.status(401).json({ message: 'Unauthorized' })
            }

            /**
             * Get session data from the database
             */
            const session = await db
                .select({
                    user: {
                        role: users.role,
                        userId: users.userId,
                    },
                    refreshToken: {
                        signature: refreshTokens.signature,
                        sessionId: refreshTokens.sessionId,
                        expiresAt: refreshTokens.expiresAt,
                    },
                })
                .from(refreshTokens)
                .innerJoin(users, eq(refreshTokens.userId, users.userId))
                .where(eq(refreshTokens.sessionId, payload.sessionId))

            /**
             * If the session is deleted from the database, clear the session
             */
            if (session.length === 0) {
                await clearSession(payload.sessionId, payload.sub, res)
                return res.status(401).json({ message: 'Unauthorized' })
            }

            /**
             * If multiple sessions are found for the same session id, there is a possible hack attempt
             * Clear the session and return unauthorized
             */
            if (session.length > 1) {
                logging.error('Multiple sessions found for the same session id')
                await clearSession(payload.sessionId, payload.sub, res)
                return res.status(401).json({ message: 'Unauthorized' })
            }

            const {
                refreshToken: { sessionId, signature, expiresAt },
                user: { userId, role },
            } = session[0]

            /**
             * Check if the token was invalid and expired
             * and check db if the session is still valid
             */
            if (!validToken && expiredToken) {
                if (expiresAt < new Date()) {
                    await clearSession(payload.sessionId, payload.sub, res)
                    return res.status(401).json({ message: 'Unauthorized' })
                }
            }

            /**
             * Check if the device signature is the same
             */
            if (!verifySessionSignature(req, signature)) {
                await clearSession(sessionId, userId, res)
                return res.status(401).json({ message: 'Unauthorized' })
            }

            /**
             * If everything is valid, issue new tokens
             */
            const newSessionId = randomUUID()
            const newAccessToken = generateAccessToken(userId, role)
            const newRefreshToken = generateRefreshToken(userId, newSessionId)
            const encryptedNewRefreshToken = encryptToken(newRefreshToken)

            /**
             * Refresh the refresh token in the cookie
             */
            setTokenCookie(res, encryptedNewRefreshToken)

            /**
             * Update the session id in the database
             */
            await db
                .update(refreshTokens)
                .set({
                    sessionId: newSessionId,
                })
                .where(eq(refreshTokens.sessionId, sessionId))

            /**
             * Return the new access token
             */
            return res.status(200).json({ accessToken: newAccessToken })
        } catch (error) {
            logging.error(error)
            res.status(501).json({ message: 'Internal server error' })
        }
    }
}

export default AuthController
