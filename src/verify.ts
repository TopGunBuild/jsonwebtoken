import crypto from '@topgunbuild/webcrypto';
import { base64UrlParse } from './utils/base64-url-parse';
import { utf8ToUint8Array } from './utils/utf8-to-uint8array';
import { str2ab } from './utils/str2ab';
import { decode } from './decode';
import {
    JwtAlgorithm,
    JwtPayload,
    JwtVerifyOptions,
    SubtleCryptoImportKeyAlgorithm,
    JwtVerifyCallback, JwtSecret
} from './types';
import { algorithms } from './utils/algorithms';

/**
 * Verifies the integrity of the token and returns a boolean value.
 */
export async function verify(
    token: string,
    secret: JwtSecret,
    options: JwtVerifyOptions|JwtAlgorithm = {
        algorithm : 'HS256',
        throwError: false,
    },
    callback?: JwtVerifyCallback<JwtPayload|false>
): Promise<JwtPayload|false>
{
    if (typeof options === 'string')
    {
        options = { algorithm: options, throwError: false };
    }

    options = { algorithm: 'HS256', throwError: false, ...options };

    function failure(err)
    {
        if (callback)
        {
            return callback(null, err);
        }
        throw err;
    }

    if (typeof token !== 'string')
    {
        failure(new Error('AuthTokenInvalidError'));
    }

    if (typeof secret !== 'string' && typeof secret !== 'object')
    {
        failure(new Error('secret must be a string or a JWK object'));
    }

    if (typeof options.algorithm !== 'string')
    {
        failure(new Error('options.algorithm must be a string'));
    }

    const tokenParts = token.split('.');

    if (tokenParts.length !== 3)
    {
        failure(new Error('token must consist of 3 parts'));
    }

    const algorithm: SubtleCryptoImportKeyAlgorithm = algorithms[options.algorithm];

    if (!algorithm)
    {
        failure(new Error('algorithm not found'));
    }

    const { payload } = decode(token);

    if (!payload)
    {
        if (options.throwError)
        {
            failure(new Error('ParseError'));
        }

        return false;
    }

    if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000))
    {
        if (options.throwError)
        {
            failure(new Error('NotYetValid'));
        }

        return false;
    }

    if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000))
    {
        if (options.throwError)
        {
            failure(new Error('TokenExpiredError'));
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

    const result = (await crypto.subtle.verify(
        algorithm,
        key,
        base64UrlParse(tokenParts[2]),
        utf8ToUint8Array(`${tokenParts[0]}.${tokenParts[1]}`)
    )) ? payload : false;

    if (typeof callback === 'function')
    {
        callback(null, result);
    }

    return result;
}
