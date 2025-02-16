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
import { RefreshTokenJWT } from '../types/auth'
import { compareDeviceSignature, createHashedDeviceSignature, decryptToken, encryptToken, verifyJWT } from '../utils/auth'
import { Auth } from '../decorators/auth'

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
            const { password, userId } = user

            if (!bcrypt.compareSync(data.password, password)) return res.status(401).json({ message: 'Invalid credentials' })

            /**
             * Prepare the session and create tokens
             */
            const sessionId = randomUUID()
            const signature = createHashedDeviceSignature(req)
            const ipAddress = bcrypt.hashSync(req.ip ?? 'unknown', 10)

            /**
             * Create an access_token
             */
            const accessToken = jwt.sign(
                {
                    sub: userId,
                    role: user.role || '',
                },
                process.env.ACCESS_TOKEN_SECRET as string,
                { expiresIn: Number(process.env.ACCESS_TOKEN_EXPIRY) ?? '10m' },
            )

            /**
             * Create a session token
             */
            const refreshToken = jwt.sign(
                {
                    sub: userId,
                    sessionId,
                },
                process.env.REFRESH_TOKEN_SECRET as string,
                { expiresIn: Number(process.env.REFRESH_TOKEN_EXPIRY) ?? '7d' },
            )

            const encryptedRefreshToken = encryptToken(refreshToken)

            /**
             * Set the refresh_token in the cookie
             */
            res.cookie('token', encryptedRefreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000, // 24h
            })

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
     * Refresh the access_token and refresh_token
     */
    @Route('post', '/refresh')
    async postRefresh(req: Request, res: Response) {
        const refreshToken = req.cookies?.token

        if (!refreshToken) return res.status(401).json({ message: 'Unauthorized' })

        try {
            /**
             * Decrypt the session token
             */
            const decryptedRefreshToken = decryptToken(refreshToken)

            /**
             * Verify the session token
             */
            const validRefreshToken = verifyJWT(decryptedRefreshToken, process.env.REFRESH_TOKEN_SECRET as string) as RefreshTokenJWT | null
            if (!validRefreshToken) {
                // If not valid, check for a refresh_token in db
                const { sessionId, sub: userId } = jwt.decode(refreshToken) as RefreshTokenJWT
                const dbRefreshToken = await db
                    .select()
                    .from(refreshTokens)
                    .where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))

                if (!dbRefreshToken.length) {
                    res.clearCookie('refresh_token')
                    return res.status(401).json({ message: 'Unauthorized' })
                }

                // If refresh_token exists, check expiry and validate signature
                const { signature, expiresAt } = dbRefreshToken[0]
                // Expiry check
                if (new Date(expiresAt) < new Date()) {
                    await db.delete(refreshTokens).where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))
                    res.clearCookie('refresh_token')
                    return res.status(401).json({ message: 'Unauthorized' })
                }

                // Signature check
                if (!compareDeviceSignature(req, signature)) {
                    await db.delete(refreshTokens).where(and(eq(refreshTokens.sessionId, sessionId), eq(refreshTokens.userId, userId)))
                    res.clearCookie('refresh_token')
                    return res.status(401).json({ message: 'Unauthorized' })
                }
            } else {
                console.log(decryptedRefreshToken)
            }
        } catch (error) {
            logging.error(error)
            res.status(501).json({ message: 'Internal server error' })
        }
    }
}

export default AuthController
