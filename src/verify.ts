import crypto from 'topgun-webcrypto';
import { base64UrlParse } from './utils/base64-url-parse';
import { utf8ToUint8Array } from './utils/utf8-to-uint8array';
import { str2ab } from './utils/str2ab';
import { decode } from './decode';
import {
    Jwt,
    JwtAlgorithm,
    JwtPayload,
    JwtVerifyOptions,
    SubtleCryptoImportKeyAlgorithm,
    VerifyCallback
} from './types';
import { algorithms } from './utils/algorithms';

/**
 * Verifies the integrity of the token and returns a boolean value.
 */
export async function verify(
    token: string,
    secret: string|JsonWebKey,
    options: JwtVerifyOptions|JwtAlgorithm = {
        algorithm : 'HS256',
        throwError: false,
    },
    callback?: VerifyCallback<Jwt>
): Promise<JwtPayload|false>
{
    if (typeof options === 'string')
    {
        options = { algorithm: options, throwError: false };
    }

    options = { algorithm: 'HS256', throwError: false, ...options };

    if (typeof token !== 'string')
    {
        throw new Error('AuthTokenInvalidError');
    }

    if (typeof secret !== 'string' && typeof secret !== 'object')
    {
        throw new Error('secret must be a string or a JWK object');
    }

    if (typeof options.algorithm !== 'string')
    {
        throw new Error('options.algorithm must be a string');
    }

    const tokenParts = token.split('.');

    if (tokenParts.length !== 3)
    {
        throw new Error('token must consist of 3 parts');
    }

    const algorithm: SubtleCryptoImportKeyAlgorithm = algorithms[options.algorithm];

    if (!algorithm)
    {
        throw new Error('algorithm not found');
    }

    const { payload } = decode(token);

    if (!payload)
    {
        if (options.throwError)
        {
            throw new AuthTokenError('ParseError');
        }

        return false;
    }

    if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000))
    {
        if (options.throwError)
        {
            throw new AuthTokenError('NotYetValid');
        }

        return false;
    }

    if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000))
    {
        if (options.throwError)
        {
            throw new AuthTokenError('TokenExpiredError');
        }

        return false;
    }
    let keyFormat: any = 'raw';
    let keyData: any;

    if (typeof secret === 'object')
    {
        keyFormat = 'jwk';
        keyData   = secret;
    }
    else if (typeof secret === 'string' && secret.startsWith('-----BEGIN'))
    {
        keyFormat = 'spki';
        keyData   = str2ab(
            secret
                .replace(/-----BEGIN.*?-----/g, '')
                .replace(/-----END.*?-----/g, '')
                .replace(/\s/g, '')
        );
    }
    else
    {
        keyData = utf8ToUint8Array(secret);
    }

    const key = await crypto.subtle.importKey(
        keyFormat,
        keyData,
        algorithm,
        false,
        ['verify']
    );

    return (await crypto.subtle.verify(
        algorithm,
        key,
        base64UrlParse(tokenParts[2]),
        utf8ToUint8Array(`${tokenParts[0]}.${tokenParts[1]}`)
    )) ? payload : false;
}
