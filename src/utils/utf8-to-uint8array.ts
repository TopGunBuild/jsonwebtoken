import { base64UrlParse } from './base64-url-parse';

export function utf8ToUint8Array(str: string): Uint8Array
{
    return base64UrlParse(btoa(unescape(encodeURIComponent(str))));
}
