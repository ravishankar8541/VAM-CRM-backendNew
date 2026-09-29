const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup(overrides = {}, passwordMatches = true) {
  const user = { _id: 'user-id', username: 'admin', name: 'Admin', role: 'admin',
    isActive: true, password: 'existing-hash', ...overrides };
  const calls = { compare: 0, signed: 0, lean: 0, metadata: [] };
  const context = vm.createContext({ exports: {}, console,
    process: { env: { JWT_SECRET: 'test-only' } },
    setImmediate: callback => calls.metadata.push(callback),
    require(name) {
      if (name === '../models/User') return {
        findOne() { return { select(fields) { calls.fields = fields; return this; },
          async lean() { calls.lean++; return user; } }; }
      };
      if (name === 'bcryptjs') return { async compare(password, hash) {
        calls.compare++; assert.equal(password, 'entered-password');
        assert.equal(hash, 'existing-hash'); return passwordMatches;
      } };
      if (name === 'jsonwebtoken') return { sign(payload, secret, options) {
        calls.signed++; assert.equal(payload.id, 'user-id');
        assert.equal(options.expiresIn, '1d'); return 'signed-token';
      } };
      return {};
    }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../controllers/authController.js'), 'utf8'), context);
  const res = { status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
  return { login: context.exports.login, calls, res };
}

test('login verifies existing password hash and returns profile without awaiting metadata writes', async () => {
  const s = setup();
  await s.login({ body: { username: 'admin', password: 'entered-password', role: 'admin' } }, s.res);
  assert.equal(s.res.code, 200);
  assert.equal(s.calls.lean, 1);
  assert.equal(s.calls.compare, 1);
  assert.equal(s.calls.signed, 1);
  assert.equal(s.calls.metadata.length, 1);
  assert.equal(s.res.body.user.password, undefined);
  assert.equal(s.res.body.token, 'signed-token');
});

test('invalid password cannot create a session', async () => {
  const s = setup({}, false);
  await s.login({ body: { username: 'admin', password: 'entered-password', role: 'admin' } }, s.res);
  assert.equal(s.res.code, 401);
  assert.equal(s.calls.signed, 0);
  assert.equal(s.calls.metadata.length, 0);
});

test('disabled accounts and incorrect roles remain blocked', async () => {
  for (const overrides of [{ isActive: false }, { role: 'sales' }]) {
    const s = setup(overrides);
    await s.login({ body: { username: 'admin', password: 'entered-password', role: 'admin' } }, s.res);
    assert.equal(s.res.code, 403);
    assert.equal(s.calls.signed, 0);
  }
});
