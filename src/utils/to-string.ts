export function toString(obj: any): string
{
    if (typeof obj === 'string')
    {
        return obj;
    }
    if (typeof obj === 'number' || (obj && typeof obj.toString === 'function'))
    {
        return obj.toString();
    }
    return JSON.stringify(obj);
}