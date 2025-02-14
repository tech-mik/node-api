import { Express, RequestHandler } from 'express'
import { RouteHandlers } from '../types/routes'

type Controller<T = any> = new (...args: any[]) => T

export function defineRoutes(controllers: Controller[], app: Express) {
    for (const ControllerClass of controllers) {
        const controller = new ControllerClass()

        const routeHandlers: RouteHandlers = Reflect.getMetadata('routeHandlers', controller)
        const controllerBaseRoute: String = Reflect.getMetadata('baseRoute', controller.constructor)

        for (const route of routeHandlers.keys()) {
            const methodsKeys = routeHandlers.get(route)?.keys()
            if (methodsKeys) {
                for (const methodKey of methodsKeys) {
                    const handlers = routeHandlers.get(route)?.get(methodKey)
                    app[methodKey](controllerBaseRoute + route, handlers)
                }
            }
        }
    }
}
