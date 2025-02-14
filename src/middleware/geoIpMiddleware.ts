import { NextFunction, Request, Response } from 'express'
import geoip from 'geoip-lite'

export function geoIpMiddleware(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip ?? ''
    // const ip = `80.61.194.72`
    req.geo = geoip.lookup(ip)
    console.log('geoIpMiddleware', req.geo)

    next()
}
