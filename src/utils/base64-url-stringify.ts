export function base64UrlStringify(a: Uint8Array): string
{
    return btoa(String.fromCharCode.apply(0, Array.from(a)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}
