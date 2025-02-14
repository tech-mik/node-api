import { NextFunction, Request, Response } from 'express'
import geoip from 'geoip-lite'

export function geoIpMiddleware(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip ?? ''
    req.geo = geoip.lookup(ip)

    next()
}
