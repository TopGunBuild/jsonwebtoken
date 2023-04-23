export function base64UrlParse(s: string): Uint8Array
{
    return new Uint8Array(
        Array.prototype.map.call(
            atob(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '')),
            c => c.charCodeAt(0)
        ) as any[]
    );
}

