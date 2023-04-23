// Payload
import { sign } from '../src/sign';

describe('when mutatePayload is not set', () =>
{
    it('should not apply claims to the original payload object (mutatePayload defaults to false)', async () =>
    {
        const originalPayload = { foo: 'bar' };

        await sign(originalPayload, 'secret', {
            notBefore: 60,
            expiresIn: 600,
        });

        expect(originalPayload).not.toHaveProperty('nbf');
        expect(originalPayload).not.toHaveProperty('exp');
    });

    it('should not apply claims to the original payload object (mutatePayload defaults to false)', async () =>
    {
        const originalPayload = { foo: 'bar' };

        await sign(originalPayload, 'secret', {
            notBefore: 60,
            expiresIn: 600,
            mutatePayload: true
        });

        expect(originalPayload).toHaveProperty('nbf');
        expect(originalPayload).toHaveProperty('exp');
    });
});

// describe('Asymmetric Algorithms', () =>
// {
//     it('should not apply claims to the original payload object (mutatePayload defaults to false)', async () =>
//     {
//
//     });
// });