import { Express, RequestHandler } from 'express'
import { RouteHandlers } from '../types/routes'

export function Route(HTTPMethod: keyof Express, path: string = '', ...middleware: RequestHandler[]) {
    return (controller: any, key: string | symbol, descriptor: PropertyDescriptor) => {
        const routeHandlers: RouteHandlers = Reflect.getMetadata('routeHandlers', controller) || new Map()

        if (!routeHandlers.has(path)) {
            routeHandlers.set(path, new Map())
        }

        routeHandlers.get(path)?.forEach((methods) => {
            methods.forEach((handler) => {
                if (handler === descriptor.value)
                    throw new Error(`Only one routehandler per HTTP method allowed. Handler ${key.toString()} has two methods attached.`)
            })
        })

        routeHandlers.get(path)?.set(HTTPMethod, [...middleware, descriptor.value])

        Reflect.defineMetadata('routeHandlers', routeHandlers, controller)
    }
}
