import { Request, Response } from 'express'
import { Controller } from '../decorators/controller'
import { Route } from '../decorators/route'
import { Auth } from '../decorators/auth'
import { Roles } from '../types/auth'

@Controller()
class MainController {
    @Auth({ strict: true })
    @Route('get', '/')
    getIndex(req: Request, res: Response) {
        res.status(200).json({ userAgent: req.useragent, ip: req.ip, geoip: req.geo })
    }
}

export default MainController
