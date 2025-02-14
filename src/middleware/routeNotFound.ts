import { Request, Response, NextFunction } from 'express';

export function routeNotFound(req: Request, res: Response, next: NextFunction) {
    const error = new Error(`Route not found`);

    logging.error(error);

    res.status(404).json({ error: error.message });
}
