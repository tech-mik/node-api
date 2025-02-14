export function Controller(baseRoute: string = '') {
    return (constructor: Function) => {
        Reflect.defineMetadata('baseRoute', baseRoute, constructor)
    }
}
