import { JwtHeader, JwtPayload } from '../types';

export function decodePayload(raw: string): JwtHeader|JwtPayload|null
{
    switch (raw.length % 4)
    {
        case 0:
            break;
        case 2:
            raw += '==';
            break;
        case 3:
            raw += '=';
            break;
        default:
            throw new Error('Illegal base64url string!');
    }

    try
    {
        return JSON.parse(decodeURIComponent(escape(atob(raw))));
    }
    catch
    {
        return null;
    }
}
