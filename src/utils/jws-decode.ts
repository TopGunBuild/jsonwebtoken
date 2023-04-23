import Buffer from 'topgun-buffer';
import { toString } from './to-string'
import { DecodeOptions, Jwt, JwtHeader } from '../types';

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

function isObject(thing: any): boolean
{
    return Object.prototype.toString.call(thing) === '[object Object]';
}

function safeJsonParse(thing: any): any
{
    if (isObject(thing))
    {
        return thing;
    }
    try
    {
        return JSON.parse(thing);
    }
    catch (e)
    {
        return undefined;
    }
}

function isValidJws(string: string): boolean
{
    return JWS_REGEX.test(string) && !!headerFromJWS(string);
}

function headerFromJWS(jwsSig: string): JwtHeader
{
    const encodedHeader = jwsSig.split('.', 1)[0];
    return safeJsonParse(Buffer.from(encodedHeader, 'base64').toString('binary'));
}

function payloadFromJWS(jwsSig: string, encoding?: string): any
{
    encoding      = encoding || 'utf8';
    const payload = jwsSig.split('.')[1];
    return Buffer.from(payload, 'base64').toString(encoding);
}

function signatureFromJWS(jwsSig: string): string
{
    return jwsSig.split('.')[2];
}

export function jwsDecode(
    jwsSig: string,
    opts?: DecodeOptions&{encoding?: (this: any, key: string, value: any) => any}
): Jwt
{
    opts   = opts || {};
    jwsSig = toString(jwsSig);

    if (!isValidJws(jwsSig))
    {
        return null;
    }

    const header = headerFromJWS(jwsSig);

    if (!header)
    {
        return null;
    }

    let payload = payloadFromJWS(jwsSig);
    if (header.typ === 'JWT' || opts.json)
    {
        payload = JSON.parse(payload, opts.encoding);
    }

    return {
        header   : header,
        payload  : payload,
        signature: signatureFromJWS(jwsSig)
    };
}

