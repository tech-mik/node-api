import request from 'supertest';
import { app, Shutdown } from '../../src/server';

describe('Our Application', () => {
    afterAll((done) => {
        Shutdown(done);
    });

    it('Starts and has the proper test environment', async () => {
        expect(process.env.NODE_ENV).toBe('test');
        expect(app).toBeDefined();
    }, 100000);

    it('Returns all options allowed to be called', async () => {
        const response = await request(app).options('/');

        expect(response.status).toBe(204);
        expect(response.headers['access-control-allow-methods']).toBe('GET, POST, PUT, DELETE, PATCH');
    });
});
