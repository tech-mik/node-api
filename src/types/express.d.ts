import { Lookup } from 'geoip-lite'

declare module 'express' {
    export interface Request {
        geo?: Lookup | null
    }
}
