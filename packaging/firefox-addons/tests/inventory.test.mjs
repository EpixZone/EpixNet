import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../manager.sys.mjs',import.meta.url),'utf8');
const body=source.slice(source.indexOf('async function inventory()'),source.indexOf('async function connect()'));
function fixture(addons,managed=[]){const context=vm.createContext({Set,Error,mirror:()=>({managed,pending:null}),consent:()=>false,managedDigest:()=>{throw Error('foreign archive must not be read')},AddonManager:{getAllAddons:async()=>addons,getAllInstalls:async()=>[]}});vm.runInContext(body,context);return context.inventory()}
test('unavailable Firefox GMP plugin remains occupied without invented version or digest',async()=>{
 const result=await fixture([{id:'gmp-gmpopenh264',version:null,isActive:true}]);
 assert.equal(JSON.stringify(result),JSON.stringify({addons:[{addon_id:'gmp-gmpopenh264',version:'',archive_sha256:null,enabled:true}],has_pending_installs:false}));
});
test('managed missing or malformed versions stop reconciliation',async()=>{
 for(const version of [null,undefined,'',123])await assert.rejects(fixture([{id:'managed@example.invalid',version,isActive:true}],[{addon_id:'managed@example.invalid'}]),/identify/);
 await assert.rejects(fixture([{id:'foreign@example.invalid',version:123}]),/identify/);
});
