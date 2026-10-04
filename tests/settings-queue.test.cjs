const assert = require('node:assert/strict');
const {test} = require('node:test');
const {createSettingsQueue} = require('../static/settings-queue.js');
test('slow first write finishes before the newest snapshot is sent', async () => {
  let release; const writes=[];
  const queue=createSettingsQueue(async value => {
    if(value.n===1) await new Promise(r=>release=r);
    writes.push(value.n); return value.n;
  });
  const first=queue({n:1}); const value={n:2}; const last=queue(value); value.n=99;
  await Promise.resolve(); assert.deepEqual(writes,[]); release();
  assert.equal(await first,1); assert.equal(await last,2); assert.deepEqual(writes,[1,2]);
});
test('a failed save does not block a newer save or explicit retry', async () => {
  const queue=createSettingsQueue(async value=>{if(value.n===1) throw new Error('offline'); return value.n;});
  const failure=queue({n:1}); const newer=queue({n:2});
  await assert.rejects(failure,/offline/); assert.equal(await newer,2);
});
