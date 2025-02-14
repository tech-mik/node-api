import bcrypt from 'bcrypt'
import { randomUUID } from 'crypto'
import { and, eq } from 'drizzle-orm'
import { Request, Response } from 'express'
import jwt from 'jsonwebtoken'
import { db } from '../db'
import { refreshTokens, UserInsert, userLoginSchema, users } from '../db/schema'
import { Controller } from '../decorators/controller'
import { Route } from '../decorators/route'
import { selectUserByEmail } from '../lib/db'
import { SessionTokenJWT } from '../types/auth'
import { compareDeviceSignature, createHashedDeviceSignature, verifyJWT } from '../utils/auth'

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
     * Login a user and issue an access_token and session_token
     */
    @Route('post', '/login')
    async postLogin(req: Request, res: Response) {
        // Get the email and password from the request body and validate them
        const { success, data } = userLoginSchema.safeParse(req.body)
        if (!success) {
            res.status(400).json({ message: 'Invalid credentials' })
            return
        }

        try {
            /**
             * Check if the user exists in the database
             */
            const user = await selectUserByEmail(data.email)
            if (!user) {
                res.status(400).json({ message: 'Invalid credentials' })
                return
            }

            /**
             * Validate password
             */
            const { password, userId } = user

            if (!bcrypt.compareSync(data.password, password)) {
                res.status(400).json({ message: 'Invalid credentials' })
                return
            }

            /**
             * Prepare the session and create tokens
             */
            const sessionId = randomUUID()
            const signature = createHashedDeviceSignature(req)

            const accessToken = jwt.sign(
                {
                    sub: userId,
                    role: user.role || '',
                },
                process.env.ACCESS_TOKEN_SECRET as string,
                { expiresIn: Number(process.env.ACCESS_TOKEN_EXPIRY) || '15m' },
            )

            const sessionToken = jwt.sign(
                {
                    sub: userId,
                    sessionId,
                },
                process.env.SESSION_TOKEN_SECRET as string,
                { expiresIn: Number(process.env.SESSION_TOKEN_EXPIRY) || '24h' },
            )

            /**
             * Insert refresh_token into the database
             */
            await db.insert(refreshTokens).values({
                sessionId,
                userId,
                signature,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
            })

            res.cookie('session_token', sessionToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000, // 24h
            })

            res.status(200).json({ accessToken })
        } catch (error) {
            res.status(500).json({ message: 'Internal Server Error' })
            logging.error(error)
        }
    }

    /**
     * Refresh the access_token and session_token
     */
    @Route('get', '/refresh')
    async getRefresh(req: Request, res: Response) {
        const sessionToken = req.cookies?.session_token

        if (!sessionToken) {
            res.status(401).json({ message: 'Unauthorized' })
            return
        }

        try {
            // First check if session_token is still valid
            const validSessionToken = verifyJWT(sessionToken, process.env.SESSION_TOKEN_SECRET as string) as SessionTokenJWT | null
            if (!validSessionToken) {
                // If not valid, check for a refresh_token in db
                const { sessionId, sub: userId } = jwt.decode(sessionToken) as SessionTokenJWT
                const refreshToken = await db
                    .select()
                    .from(refreshTokens)
                    .where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))

                if (!refreshToken.length) {
                    res.clearCookie('session_token')
                    res.status(401).json({ message: 'Unauthorized' })
                    return
                }

                // If refresh_token exists, check expiry and validate signature
                const { signature, expiresAt } = refreshToken[0]
                // Expiry check
                if (new Date(expiresAt) < new Date()) {
                    await db.delete(refreshTokens).where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))
                    res.clearCookie('session_token')
                    res.status(401).json({ message: 'Unauthorized' })

                    return
                }

                // Signature check
                if (!compareDeviceSignature(req, signature)) {
                    await db.delete(refreshTokens).where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))
                    res.clearCookie('session_token')
                    res.status(401).json({ message: 'Unauthorized' })

                    return
                }
            }
        } catch (error) {
            res.status(501).json({ message: 'Internal server error' })
        }

        // 1. Verify session token
        // 2. Check if corresponding refreshToken in database exists and is not expired
        // 3. Check if the device signature matches
        // 4. Issue a new access token
        // 5. Issue a new session token
        // 6. Update the refresh token in the database
    }
}

export default AuthController
