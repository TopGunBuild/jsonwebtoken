import { JsonWebTokenError } from './json-web-token-error';

export class TokenExpiredError extends JsonWebTokenError
{
    expiredAt: number;

    constructor(message: string, expiredAt: number)
    {
        super(message);
        this.name      = 'TokenExpiredError';
        this.expiredAt = expiredAt;
    }
}
