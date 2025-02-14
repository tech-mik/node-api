import { Request, Response, NextFunction } from 'express';

export function corsHandler(req: Request, res: Response, next: NextFunction) {
    res.header('Access-Control-Allow-Origin', req.header('origin'));
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Acces-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        res.header('access-control-allow-methods', 'GET, POST, PUT, DELETE, PATCH');
        res.sendStatus(204);
        return;
    }

    next();
}
