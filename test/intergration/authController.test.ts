import supertest from 'supertest'
import { app, Shutdown } from '../../src/server' // Assuming your Express app is exported from this file

describe('AuthController', () => {
    describe('POST /auth/user', () => {
        it('should create a new user', async () => {
            const { statusCode } = await supertest(app).post('/auth/user').send({ email: 'test@example.com', password: 'password123' })

            expect(statusCode).toBe(201)
        })
    })
})
