export class JsonWebTokenError extends Error
{
    inner: Error;

    constructor(message: string, error?: Error)
    {
        super(message);
        Object.setPrototypeOf(this, JsonWebTokenError.prototype);
        if (Error.captureStackTrace)
        {
            Error.captureStackTrace(this, this.constructor);
        }
        this.name    = 'JsonWebTokenError';
        this.message = message;
        if (error)
        {
            this.inner = error;
        }
    }
}
