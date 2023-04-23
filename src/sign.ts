import Buffer from 'topgun-buffer';
import { isString } from './utils/is-string';
import { isNumber } from './utils/is-number';
import { isBoolean } from './utils/is-boolean';
import { isPlainObject } from './utils/is-plain-object';
import { Secret, SignCallback, SignOptions } from './types';
import { timespan } from './utils/timespan';

const SUPPORTED_ALGS = ['ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'none'];

const sign_options_schema = {
    expiresIn                     : {
        isValid   : value =>
        {
            return isNumber(value) || (isString(value) && value);
        }, message: '"expiresIn" should be a number of seconds or string representing a timespan'
    },
    notBefore                     : {
        isValid   : value =>
        {
            return isNumber(value) || (isString(value) && value);
        }, message: '"notBefore" should be a number of seconds or string representing a timespan'
    },
    audience                      : {
        isValid   : value =>
        {
            return isString(value) || Array.isArray(value);
        }, message: '"audience" must be a string or array'
    },
    algorithm                     : {
        isValid   : value =>
        {
            return SUPPORTED_ALGS.includes(value)
        }, message: '"algorithm" must be a valid string enum value'
    },
    header                        : { isValid: isPlainObject, message: '"header" must be an object' },
    encoding                      : { isValid: isString, message: '"encoding" must be a string' },
    issuer                        : { isValid: isString, message: '"issuer" must be a string' },
    subject                       : { isValid: isString, message: '"subject" must be a string' },
    jwtid                         : { isValid: isString, message: '"jwtid" must be a string' },
    noTimestamp                   : { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
    keyid                         : { isValid: isString, message: '"keyid" must be a string' },
    mutatePayload                 : { isValid: isBoolean, message: '"mutatePayload" must be a boolean' },
    allowInsecureKeySizes         : { isValid: isBoolean, message: '"allowInsecureKeySizes" must be a boolean' },
    allowInvalidAsymmetricKeyTypes: {
        isValid: isBoolean,
        message: '"allowInvalidAsymmetricKeyTypes" must be a boolean'
    }
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
export function sign(
    payload: string|object,
    secretOrPrivateKey: Secret,
    callback: SignCallback,
): void;
export function sign(
    payload: string|object,
    secretOrPrivateKey: Secret,
    options: SignOptions,
    callback: SignCallback,
): void;
export function sign(
    payload: string|object,
    secretOrPrivateKey: Secret,
    options: SignOptions|SignCallback,
    callback?: SignCallback,
): void
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

    const isObjectPayload = typeof payload === 'object';

    const header = Object.assign({
        alg: options.algorithm || 'HS256',
        typ: isObjectPayload ? 'JWT' : undefined,
        kid: options.keyid
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
        return failure(new Error('secretOrPrivateKey must have a value'));
    }

    if (secretOrPrivateKey != null && !(secretOrPrivateKey instanceof KeyObject))
    {
        try
        {
            secretOrPrivateKey = createPrivateKey(secretOrPrivateKey)
        }
        catch (_)
        {
            try
            {
                secretOrPrivateKey = createSecretKey(typeof secretOrPrivateKey === 'string' ? Buffer.from(secretOrPrivateKey) : secretOrPrivateKey)
            }
            catch (_)
            {
                return failure(new Error('secretOrPrivateKey is not valid key material'));
            }
        }
    }

    if (header.alg.startsWith('HS') && secretOrPrivateKey.type !== 'secret')
    {
        return failure(new Error((`secretOrPrivateKey must be a symmetric key when using ${header.alg}`)))
    }
    else if (/^(?:RS|PS|ES)/.test(header.alg))
    {
        if (secretOrPrivateKey.type !== 'private')
        {
            return failure(new Error((`secretOrPrivateKey must be an asymmetric key when using ${header.alg}`)))
        }
        if (!options.allowInsecureKeySizes &&
            !header.alg.startsWith('ES') &&
            secretOrPrivateKey.asymmetricKeyDetails !== undefined && //KeyObject.asymmetricKeyDetails is supported in Node 15+
            secretOrPrivateKey.asymmetricKeyDetails.modulusLength < 2048)
        {
            return failure(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
        }
    }

    if (typeof payload === 'undefined')
    {
        return failure(new Error('payload is required'));
    }
    else if (isObjectPayload)
    {
        try
        {
            validatePayload(payload);
        }
        catch (error)
        {
            return failure(error);
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
            return failure(new Error('invalid ' + invalid_options.join(',') + ' option for ' + (typeof payload) + ' payload'));
        }
    }

    if (typeof payload['exp'] !== 'undefined' && typeof options.expiresIn !== 'undefined')
    {
        return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
    }

    if (typeof payload['nbf'] !== 'undefined' && typeof options.notBefore !== 'undefined')
    {
        return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
    }

    try
    {
        validateOptions(options);
    }
    catch (error)
    {
        return failure(error);
    }

    if (!options.allowInvalidAsymmetricKeyTypes)
    {
        try
        {
            validateAsymmetricKey(header.alg, secretOrPrivateKey);
        }
        catch (error)
        {
            return failure(error);
        }
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
            return failure(err);
        }
        if (typeof payload['nbf'] === 'undefined')
        {
            return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
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
            return failure(err);
        }
        if (typeof payload['exp'] === 'undefined')
        {
            return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
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

    const encoding = options.encoding || 'utf8';

    if (typeof callback === 'function')
    {
        callback = callback && once(callback);

        jws.createSign({
            header    : header,
            privateKey: secretOrPrivateKey,
            payload   : payload,
            encoding  : encoding
        }).once('error', callback)
            .once('done', function (signature)
            {
                callback(null, signature);
            });
    }
    else
    {
        let signature = jws.sign({ header: header, payload: payload, secret: secretOrPrivateKey, encoding: encoding });
        // TODO: Remove in favor of the modulus length check before signing once node 15+ is the minimum supported version
        if (!options.allowInsecureKeySizes && /^(?:RS|PS)/.test(header.alg) && signature.length < 256)
        {
            throw new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`)
        }
        return signature
    }
}