import { RouteHandlers } from '../types/routes'
import { authMiddlewareFactory } from '../middleware/authMiddleware'
import { AuthOptions } from '../types/auth'

/**
 * Auth decorator
 *
 * This decorator adds the authentication middleware to the middleware stack of the route handler.
 * This makes sure the user can only perform this action, if it is authenticated or authorized
 *
 * Important: Make sure the Auth decorator is always defined before Route Decorators, otherwise it wil throw an error.
 *
 * @param [authorization=null]
 * @param [strict=false]
 */
export function Auth(authOptions: AuthOptions = { strict: true }) {
    return function (controller: object, propertyKey: string, descriptor: PropertyDescriptor) {
        const error = `Route decorator for handler [${propertyKey}] not defined yet. Make sure the Auth decorator is defined above the Route decorators.`
        const routeHandlersMap: RouteHandlers = Reflect.getMetadata('routeHandlers', controller)

        if (!routeHandlersMap) throw new Error(error)

        let i = 0
        for (const routes of routeHandlersMap.values()) {
            routes.forEach((handler) => {
                if (handler.includes(descriptor.value)) {
                    handler.unshift(authMiddlewareFactory(authOptions))
                    i++
                }
            })
        }

        if (!i) throw new Error(error)
    }
}
