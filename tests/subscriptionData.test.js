const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function setup() {
  const queries = [];
  const service = { _id: 'service', clientId: 'visible', totalAmount: 1000,
    serviceName: 'Plan', duration: '1 Month', payments: [{ amount: 200, billNumber: 'B1' }], bills: [] };
  const records = { Client: [{ _id: 'visible' }, { _id: 'empty' }], Bill: [], User: [],
    ServiceBill: [service, { ...service, _id: 'second' }, { ...service, clientId: 'hidden' }] };
  const context = vm.createContext({ exports: {}, console,
    require: name => ({ find: filter => {
      const model = name.split('/').pop();
      const call = { model, filter };
      queries.push(call);
      const query = {
        select(fields) { call.fields = fields; return this; },
        sort() { return this; },
        lean() { return Promise.resolve(records[model]); },
        then(resolve, reject) { return Promise.resolve(records[model]).then(resolve, reject); }
      };
      return query;
    } }) });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../controllers/serviceBillController.js'), 'utf8'), context);
  const res = { status(code) { this.code = code; return this; }, set() {}, json(body) { this.body = body; return this; } };
  return { api: context.exports, res, queries };
}

test('subscription response preserves payment totals and excludes inaccessible/empty clients', async () => {
  const s = setup();
  await s.api.getSubscriptionData({ user: { role: 'employee', id: 'owner' } }, s.res);
  assert.equal(s.res.code, 200);
  const { data } = s.res.body;
  assert.equal(data.clients.length, 1);
  assert.equal(data.serviceBills.hidden, undefined);
  assert.equal(data.serviceBills.visible[0].paidAmount, 200);
  assert.equal(data.serviceBills.visible[0].dueAmount, 800);
  assert.equal(data.serviceBills.visible[0].installmentBills, undefined);
  for (const query of s.queries.filter(q => q.model !== 'User')) {
    assert.equal(query.filter[query.model === 'Bill' ? 'createdById' : 'createdBy'], 'owner');
    assert.ok(query.fields);
  }
});

test('per-client billing keeps full installment data for every record', async () => {
  const s = setup();
  await s.api.getClientServiceBilling({ user: { role: 'admin' }, params: { clientId: 'visible' } }, s.res);
  assert.equal(s.res.code, 200);
  for (const service of s.res.body.data.services) assert.equal(service.installmentBills.length, 1);
});

test('unsupported roles and missing owners are rejected before querying', async () => {
  for (const user of [{ role: 'guest' }, { role: 'sales' }]) {
    const s = setup();
    await s.api.getSubscriptionData({ user }, s.res);
    assert.equal(s.res.code, 403);
    assert.equal(s.queries.length, 0);
  }
});
