import { DecodeOptions, Jwt, JwtPayload } from './types';
import { jwsDecode } from './utils/jws-decode';

export function decode(token: string, options: DecodeOptions&{complete: true}): null|Jwt;
export function decode(token: string, options: DecodeOptions&{json: true}): null|JwtPayload;
export function decode(token: string, options?: DecodeOptions): null|JwtPayload|string
{
    options       = options || {};
    const decoded = jwsDecode(token, options);
    if (!decoded)
    {
        return null;
    }
    let payload = decoded.payload;

    //try parse the payload
    if (typeof payload === 'string')
    {
        try
        {
            const obj = JSON.parse(payload);
            if (obj !== null && typeof obj === 'object')
            {
                payload = obj;
            }
        }
        catch (e)
        {
        }
    }

    // return header if `complete` option is enabled.  header includes claims
    // such as `kid` and `alg` used to select the key within a JWKS needed to
    // verify the signature
    if (options.complete === true)
    {
        return {
            header   : decoded.header,
            payload  : payload,
            signature: decoded.signature
        };
    }
    return payload;
}
