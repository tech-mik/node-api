import dotenv from 'dotenv'

dotenv.config()

export const DEVELOPMENT = process.env.NODE_ENV === 'development'
export const TEST = process.env.NODE_ENV === 'test'

const SERVER_HOSTNAME = process.env.SERVER_HOSTNAME || 'localhost'
const SERVER_PORT = process.env.SERVER_PORT ? Number(process.env.SERVER_PORT) : 1337

export const SERVER = {
    SERVER_HOSTNAME,
    SERVER_PORT,
}
