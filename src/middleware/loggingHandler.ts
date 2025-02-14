import { Request, Response, NextFunction } from 'express'

export function loggingHandler(req: Request, res: Response, next: NextFunction) {
    logging.log(`Incoming - METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.ip}]`)

    res.on('finish', () => {
        logging.log(`Incoming - METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.ip}] - STATUS: [${res.statusCode}]`)
        return
    })

    next()
}
