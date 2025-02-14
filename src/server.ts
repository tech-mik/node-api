import cookieParser from 'cookie-parser'
import express from 'express'
import expressFingerprint from 'express-fingerprint'
import userAgent from 'express-useragent'
import helmet from 'helmet'
import http from 'http'
import 'reflect-metadata'

import { SERVER } from './config/config'
import './config/logging'

import AuthController from './controllers/auth'
import MainController from './controllers/main'

import { corsHandler } from './middleware/corsHandler'
import { loggingHandler } from './middleware/loggingHandler'
import { routeNotFound } from './middleware/routeNotFound'
import { defineRoutes } from './modules/routes'
import { geoIpMiddleware } from './middleware/geoIpMiddleware'
import { hostname } from 'os'

export const app = express()
export let httpServer: ReturnType<typeof http.createServer>

export const Main = () => {
    /**
     * Trusting the proxy (reverse proxy from nginx)
     */
    app.set('trust proxy', true)
    /**
     * Defining Middleware
     */
    app.use(helmet())
    app.use(cookieParser())
    app.use(express.urlencoded({ extended: true }))
    app.use(express.json())
    app.use(userAgent.express())
    app.use(expressFingerprint())
    app.use(loggingHandler)
    app.use(corsHandler)
    app.use(geoIpMiddleware)

    /**
     * Defining Route Controllers
     */
    defineRoutes([MainController, AuthController], app)

    /**
     * Defining Error Handlers
     */
    app.use(routeNotFound)

    /**
     * Start the server
     */
    httpServer = http.createServer(app)
    httpServer.listen({ port: SERVER.SERVER_PORT }, () => {
        logging.info(`Server is running on http://localhost:${SERVER.SERVER_PORT}`)
    })
}

export const Shutdown = (callback: any) => httpServer && httpServer.close(callback)

Main()
