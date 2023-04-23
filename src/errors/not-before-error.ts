import { JsonWebTokenError } from './json-web-token-error';

export class NotBeforeError extends JsonWebTokenError
{
    date: number;

    constructor(message: string, date: number)
    {
        super(message);
        this.name = 'NotBeforeError';
        this.date = date;
    }
}
