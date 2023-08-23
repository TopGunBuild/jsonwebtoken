import crypto from '@topgunbuild/webcrypto';
import { isString } from './utils/is-string';
import { isNumber } from './utils/is-number';
import { isBoolean } from './utils/is-boolean';
import { isPlainObject } from './utils/is-plain-object';
import { JwtPayload, JwtSecret, JwtSignCallback, JwtSignOptions, JwtSubtleCryptoImportKeyAlgorithm } from './types';
import { timespan } from './utils/timespan';
import { base64UrlStringify } from './utils/base64-url-stringify';
import { utf8ToUint8Array } from './utils/utf8-to-uint8array';
import { str2ab } from './utils/str2ab';
import { algorithms } from './utils/algorithms';

const SUPPORTED_ALGS = ['ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'none'];

const sign_options_schema = {
    expiresIn                     : {
        isValid   : (value) =>
        {
            return isNumber(value) || (isString(value) && value);
        }, message: '"expiresIn" should be a number of seconds or string representing a timespan'
    },
    notBefore                     : {
        isValid   : (value) =>
        {
            return isNumber(value) || (isString(value) && value);
        }, message: '"notBefore" should be a number of seconds or string representing a timespan'
    },
    audience                      : {
        isValid   : (value) =>
        {
            return isString(value) || Array.isArray(value);
        }, message: '"audience" must be a string or array'
    },
    algorithm                     : {
        isValid   : (value) =>
        {
            return SUPPORTED_ALGS.includes(value)
        }, message: '"algorithm" must be a valid string enum value'
    },
    header                        : { isValid: isPlainObject, message: '"header" must be an object' },
    issuer                        : { isValid: isString, message: '"issuer" must be a string' },
    subject                       : { isValid: isString, message: '"subject" must be a string' },
    jwtid                         : { isValid: isString, message: '"jwtid" must be a string' },
    noTimestamp                   : { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
    keyid                         : { isValid: isString, message: '"keyid" must be a string' },
    mutatePayload                 : { isValid: isBoolean, message: '"mutatePayload" must be a boolean' },
};

const registered_claims_schema = {
    iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
    exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
    nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
};

function validate(schema, allowUnknown, object, parameterName): void
{
    if (!isPlainObject(object))
    {
        throw new Error('Expected "' + parameterName + '" to be a plain object.');
    }
    Object.keys(object)
        .forEach(function (key)
        {
            const validator = schema[key];
            if (!validator)
            {
                if (!allowUnknown)
                {
                    throw new Error('"' + key + '" is not allowed in "' + parameterName + '"');
                }
                return;
            }
            if (!validator.isValid(object[key]))
            {
                throw new Error(validator.message);
            }
        });
}

function validateOptions(options): void
{
    return validate(sign_options_schema, false, options, 'options');
}

function validatePayload(payload): void
{
    return validate(registered_claims_schema, true, payload, 'payload');
}

const options_to_payload = {
    'audience': 'aud',
    'issuer'  : 'iss',
    'subject' : 'sub',
    'jwtid'   : 'jti'
};

const options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/**
 * Sign the given payload into a JSON Web Token string
 * payload - Payload to sign, could be an literal, buffer or string
 * secretOrPrivateKey - Either the secret for HMAC algorithms, or the PEM encoded private key for RSA and ECDSA.
 * [options] - Options for the signature
 * callback - Callback to get the encoded token on
 */
export async function sign(
    payload: string|JwtPayload,
    secretOrPrivateKey: JwtSecret,
    callback: JwtSignOptions|JwtSignCallback,
): Promise<string>;
export async function sign(
    payload: string|JwtPayload,
    secretOrPrivateKey: JwtSecret,
    options: JwtSignOptions,
    callback: JwtSignCallback,
): Promise<string>;
export async function sign(
    payload: string|JwtPayload,
    secretOrPrivateKey: JwtSecret,
    options: JwtSignOptions|JwtSignCallback,
    callback?: JwtSignCallback,
): Promise<string>
{
    if (typeof options === 'function')
    {
        callback = options;
        options  = {};
    }
    else
    {
        options = options || {};
    }

    options = { algorithm: 'HS256', ...options };

    const isObjectPayload = typeof payload === 'object';

    const header = Object.assign({
        alg: options.algorithm,
        typ: isObjectPayload ? 'JWT' : undefined
    }, options.header);

    function failure(err)
    {
        if (callback)
        {
            return callback(err);
        }
        throw err;
    }

    if (!secretOrPrivateKey && options.algorithm !== 'none')
    {
        failure(new Error('secretOrPrivateKey must have a value'));
    }

    if (typeof payload === 'undefined')
    {
        failure(new Error('payload is required'));
    }
    else if (isObjectPayload)
    {
        try
        {
            validatePayload(payload);
        }
        catch (error)
        {
            failure(error);
        }
        if (!options.mutatePayload)
        {
            payload = Object.assign({}, payload);
        }
    }
    else
    {
        const invalid_options = options_for_objects.filter(function (opt)
        {
            return typeof options[opt] !== 'undefined';
        });

        if (invalid_options.length > 0)
        {
            failure(new Error('invalid ' + invalid_options.join(',') + ' option for ' + (typeof payload) + ' payload'));
        }
    }

    if (typeof payload['exp'] !== 'undefined' && typeof options.expiresIn !== 'undefined')
    {
        failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
    }

    if (typeof payload['nbf'] !== 'undefined' && typeof options.notBefore !== 'undefined')
    {
        failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
    }

    try
    {
        validateOptions(options);
    }
    catch (error)
    {
        failure(error);
    }

    const timestamp = payload['iat'] || Math.floor(Date.now() / 1000);

    if (options.noTimestamp)
    {
        delete payload['iat'];
    }
    else if (isObjectPayload)
    {
        payload['iat'] = timestamp;
    }

    if (typeof options.notBefore !== 'undefined')
    {
        try
        {
            payload['nbf'] = timespan(options.notBefore as number, timestamp);
        }
        catch (err)
        {
            failure(err);
        }
        if (typeof payload['nbf'] === 'undefined')
        {
            failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
        }
    }

    if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object')
    {
        try
        {
            payload['exp'] = timespan(options.expiresIn as number, timestamp);
        }
        catch (err)
        {
            failure(err);
        }
        if (typeof payload['exp'] === 'undefined')
        {
            failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
        }
    }

    Object.keys(options_to_payload).forEach(function (key)
    {
        const claim = options_to_payload[key];
        if (typeof options[key] !== 'undefined')
        {
            if (typeof payload[claim] !== 'undefined')
            {
                return failure(new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.'));
            }
            payload[claim] = options[key];
        }
    });

    const payloadAsJSON = JSON.stringify(payload);
    const partialToken  = `${base64UrlStringify(
        utf8ToUint8Array(
            JSON.stringify({ ...header })
        )
    )}.${base64UrlStringify(utf8ToUint8Array(payloadAsJSON))}`;

    let keyFormat: any = 'raw';
    let keyData: any;

    if (typeof secretOrPrivateKey === 'object')
    {
        keyFormat = 'jwk';
        keyData   = secretOrPrivateKey;
    }
    else if (typeof secretOrPrivateKey === 'string' && secretOrPrivateKey.startsWith('-----BEGIN'))
    {
        keyFormat = 'pkcs8';
        keyData   = str2ab(
            secretOrPrivateKey
                .replace(/-----BEGIN.*?-----/g, '')
                .replace(/-----END.*?-----/g, '')
                .replace(/\s/g, '')
        );
    }
    else
    {
        keyData = utf8ToUint8Array(secretOrPrivateKey);
    }

    const algorithm: JwtSubtleCryptoImportKeyAlgorithm = algorithms[options.algorithm];

    if (!algorithm)
    {
        failure(new Error('algorithm not found'));
    }

    const key       = await crypto.subtle.importKey(
        keyFormat,
        keyData,
        algorithm,
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign(
        algorithm,
        key,
        utf8ToUint8Array(partialToken)
    );

    const result = `${partialToken}.${base64UrlStringify(new Uint8Array(signature))}`;

    if (typeof callback === 'function')
    {
        callback(null, result);
    }

    return result;
}