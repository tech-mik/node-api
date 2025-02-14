import { Express, RequestHandler } from 'express'

export type RouteHandlers = Map<string, Map<keyof Express, RequestHandler[]>>
