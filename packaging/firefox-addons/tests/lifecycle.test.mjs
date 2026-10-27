import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { validateCandidate } from '../policy.sys.mjs';
const source=fs.readFileSync(new URL('../manager.sys.mjs',import.meta.url),'utf8');
const body=source.slice(source.indexOf('function current(op)'),source.indexOf('function status(view,'));
const consentBody=source.slice(source.indexOf('async function recordConsent(op)'),source.indexOf('function engineAccepted('));
const h='a'.repeat(64);
const candidate={operation_id:h,source_url:'https://publisher.epix/addon.xpi',publisher:'publisher',inner_path:'addon.xpi',governing_manifest:'content.json',archive_sha256:h,byte_length:100,addon_id:'test@example.invalid',version:'1',name:'Test',manifest_version:2,required_permissions:[],optional_permissions:[],host_permissions:[],optional_host_permissions:[],expires_at_ms:Date.now()+300000,engine:'Gecko'};
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject}}
function setup({factory,installThrows=false,consentWait,consentPatch={}}={}){
 const requests=[],timers=[],observers=new Map(),browser={currentURI:{spec:'https://publisher.epix/'}};
 const tabs={addEventListener(){},removeEventListener(){}};
 const win={closed:false,gBrowser:{selectedBrowser:browser,tabContainer:tabs,addTabsProgressListener(){},removeTabsProgressListener(){}},addEventListener(){},removeEventListener(){},focus(){}};
 const view={closed:false,opener:null};let revoked=0,cancelled=0,authorized=0,marker=false,nativeAllowed=false,nativeCompletion;
 const allow=deferred();
 const install={file:'stage.xpi',cancel(){cancelled++},addListener(){},removeListener(){}};
 const context=vm.createContext({console,Date,JSON,Error,Set,validateCandidate,setTimeout(fn){timers.push(fn);return timers.length},clearTimeout(){},
  browserWindows:new Map([[view,win]]),profileId:h,session:{session_id:h,needs_reconciliation:false},connection:null,operation:null,unavailable:null,Ci:{nsIWebProgressListener:{STATE_START:1}},
  guard:{ids:new Set(),prepare(){},clearTicket(){},receipt(){return candidate},revoke(){revoked++},authorize(){authorized++}},
  renderAll(){},status(){},refreshGuard(){},checkClean:async()=>{},connect:async()=>{},file:x=>x,consent:()=>marker,
  engineAccepted:()=>true,digest:()=>({sha256:h}),inventory:async()=>({addons:[],has_pending_installs:false}),
  AddonManager:{getInstallForFile:()=>factory?factory(install):Promise.resolve(install),installAddonFromAOM(_browser,_uri,i){if(installThrows)throw new Error('native prompt failure');i.promptHandler=async()=>{await allow.promise;nativeAllowed=true};observers.get('addon-install-started')?.observe({wrappedJSObject:{browser,installs:[i]}});nativeCompletion=i.promptHandler({install:i});nativeCompletion.catch(()=>{})},AUTOUPDATE_DISABLE:0},
  Services:{io:{newURI:x=>x},obs:{addObserver(o,t){observers.set(t,o)},removeObserver(o,t){if(observers.get(t)===o)observers.delete(t)}}},
  request:async v=>{requests.push(v.command);if(v.command==='prepare')return candidate;if(v.command==='stage')return{candidate,path:'stage.xpi'};if(v.command==='consent'){assert.equal(nativeAllowed,true);if(consentWait)await consentWait.promise;marker=true;return{protocol:1,profile_id:h,operation_id:h,addon_id:candidate.addon_id,version:candidate.version,archive_sha256:h,...consentPatch}}return{needs_reconciliation:false}},
 });
 vm.runInContext(consentBody+body,context);
 return{context,view,install,requests,timers,allow,completion:()=>nativeCompletion,counts:()=>({cancelled,revoked,authorized}),marker:()=>marker};
}
test('late factory result is cancelled and revoked after manager close',async()=>{
 const entering=deferred(),factory=deferred(),s=setup({factory:()=>{entering.resolve();return factory.promise}});
 const p=s.context.prepare(s.view,candidate.source_url).catch(()=>{});await entering.promise;await s.context.cancelOperation(s.context.operation);factory.resolve(s.install);await p;
 assert.equal(s.counts().cancelled,1);assert.equal(s.counts().revoked,1);assert.deepEqual(s.requests,['prepare','stage','cancel','reconcile']);assert.equal(s.context.operation,null);
});
test('pre-handoff cancellation uses cancel and then reconciliation',async()=>{
 const s=setup();const op={candidate,cancelled:false,finished:false,view:s.view};s.context.operation=op;await s.context.cancelOperation(op);
 assert.deepEqual(s.requests,['cancel','reconcile']);assert.equal(s.context.operation,null);
});
test('only the privately bound live browser window can begin a review',async()=>{
 const s=setup();s.view.opener=s.context.browserWindows.get(s.view);s.context.browserWindows.delete(s.view);
 await assert.rejects(s.context.prepare(s.view,candidate.source_url),/Open this manager/);assert.deepEqual(s.requests,[]);
 const closed=setup();closed.context.browserWindows.get(closed.view).closed=true;
 await assert.rejects(closed.context.prepare(closed.view,candidate.source_url),/Open this manager/);assert.deepEqual(closed.requests,[]);
});
test('synchronous native prompt failure removes current operation and cancels exact object',async()=>{
 const s=setup({installThrows:true});await s.context.prepare(s.view,candidate.source_url);await assert.rejects(()=>s.context.approve(s.view),/native prompt failure/);
 assert.equal(s.context.operation,null);assert.equal(s.counts().cancelled,1);assert.equal(s.counts().revoked,1);
});
test('native Allow and durable acknowledgement both precede authorization',async()=>{
 const saved=deferred(),s=setup({consentWait:saved});await s.context.prepare(s.view,candidate.source_url);await s.context.approve(s.view);
 assert.equal(s.requests.includes('consent'),false);assert.equal(s.counts().authorized,0);
 s.allow.resolve();await new Promise(r=>setImmediate(r));assert.equal(s.requests.includes('consent'),true);assert.equal(s.counts().authorized,0);
 saved.resolve();await s.completion();assert.equal(s.counts().authorized,1);assert.equal(s.marker(),true);
 await s.context.cancelOperation(s.context.operation);
});
test('closing during durable consent write rejects continuation and reconciles afterward',async()=>{
 const saved=deferred(),s=setup({consentWait:saved});await s.context.prepare(s.view,candidate.source_url);await s.context.approve(s.view);s.allow.resolve();await new Promise(r=>setImmediate(r));
 const cancel=s.context.cancelOperation(s.context.operation);assert.equal(s.requests.includes('cancel'),false);saved.resolve();await cancel;await assert.rejects(s.completion(),/closed|changed/);
 assert.equal(s.counts().authorized,0);assert.deepEqual(s.requests.slice(-3),['consent','cancel','reconcile']);
});
test('expiry timer cancels native consent wait and never writes approval',async()=>{
 const s=setup();await s.context.prepare(s.view,candidate.source_url);await s.context.approve(s.view);await s.timers[0]();await new Promise(r=>setImmediate(r));s.allow.resolve();await assert.rejects(s.completion(),/closed|changed/);
 assert.equal(s.counts().authorized,0);assert.equal(s.requests.includes('consent'),false);assert.equal(s.context.operation,null);
});
test('an authenticated acknowledgement for a different review does not authorize the install',async()=>{
 const s=setup({consentPatch:{version:'other'}});await s.context.prepare(s.view,candidate.source_url);await s.context.approve(s.view);s.allow.resolve();await assert.rejects(s.completion(),/does not match/);
 assert.equal(s.counts().authorized,0);await s.context.cancelOperation(s.context.operation);
});
