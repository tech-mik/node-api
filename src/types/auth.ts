import { JwtPayload } from 'jsonwebtoken'

export enum Roles {
    ADMIN = 1058,
    USER = 5896,
}

export enum AccountStatus {
    INACTIVE,
    ACTIVE,
    SUSPENDED,
}

export interface AuthOptions {
    role?: Roles | null
    strict?: boolean
}

export interface AccessTokenJWT extends JwtPayload {
    sub?: string
    role?: string
}

export interface RefreshTokenJWT extends JwtPayload {
    sessionId?: string
    sub?: string
}

export interface ValidatedToken<T> {
    valid: boolean
    payload: T
    expired?: boolean
}
