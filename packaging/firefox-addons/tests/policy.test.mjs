import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { validateCandidate, parseMirror, validateClient, signatureAccepted, macInput, InstallGuard } from '../policy.sys.mjs';
const h = 'a'.repeat(64), profile = 'b'.repeat(64);
const candidate = () => ({ operation_id:h, source_url:'https://publisher.epix/addon.xpi', publisher:'publisher', inner_path:'addon.xpi', governing_manifest:'content.json', archive_sha256:h,byte_length:123,addon_id:'ordinary@example.invalid',version:'1.0',name:'Ordinary',manifest_version:2,required_permissions:['storage'],optional_permissions:[],host_permissions:['https://*/*'],optional_host_permissions:[],expires_at_ms:Date.now()+300000,engine:'Gecko' });
const mirror = c => ({ protocol:1, profile_id:profile, managed:[], pending:{operation_id:h,phase:'HandedOff',candidate:c,uninstall_id:null,message:null} });
const api={signed:2,downloaded:3,notBlocked:0,modern:[1,2],known:[0,1,2]};
const install=c=>({error:0,state:3,file:'stage.xpi',addon:{id:c.addon_id,version:c.version,type:'extension',isWebExtension:true,isCompatible:true,appDisabled:false,blocklistState:0,signedState:2,signedTypes:[2,1]},cancel(){this.cancelled=true}});
test('HMAC matches independent native broker vectors using exact UTF8 body bytes',()=>{
 const fields=['2'.repeat(64),'3'.repeat(64),'1793055000000']; const key='1'.repeat(64);
 const hash=(domain,body,status)=>createHmac('sha256',key).update(macInput(domain,[...fields,body],status)).digest('hex');
 assert.equal(hash('EpixNet addon broker request v1\0','{"command":"status"}'),'c3eb00558bb43f3b629c3d0b0aa3fed50fba220446451b808c5ca12ec236165c');
 assert.equal(hash('EpixNet addon broker response v1\0','{"ok":true,"result":null}',200),'7628e26d50fb7fb0cfbeddd504d4fde18109ec19263c3ac4fa34c44046cfcb77');
 assert.notEqual(hash('EpixNet addon broker request v1\0','{ "command":"status"}'),hash('EpixNet addon broker request v1\0','{"command":"status"}'));
});
test('candidate schema rejects reserved IDs, optional native privileges and excessive permissions',()=>{
 assert.equal(validateCandidate(candidate()).version,'1.0');
 for (const id of ['wallet@epix.zone','ANY@EPIX.ZONE','zone.epix.nmh','bad/id']) assert.throws(()=>validateCandidate({...candidate(),addon_id:id}));
 for(const permission of ['management','nativeMessaging','nativeMessagingFromContent','nativeMessagingFromAddon','experiment_apis'])assert.throws(()=>validateCandidate({...candidate(),optional_permissions:[permission]}));
 assert.throws(()=>validateCandidate({...candidate(),host_permissions:Array(40).fill('x'.repeat(2048))}));
});
test('mirror identity is strict, active receipts protected and secret never comes from disk',()=>{
 const c=candidate();assert.equal(parseMirror(JSON.stringify(mirror(c)),profile).pending.candidate.addon_id,c.addon_id);
 assert.throws(()=>parseMirror(JSON.stringify(mirror(c)),h));assert.throws(()=>parseMirror(JSON.stringify({...mirror(c),pending:{...mirror(c).pending,operation_id:profile}}),profile));
 const client={protocol:1,profile_id:profile,client_id:h,endpoint:'http://127.0.0.1:42111/EpixNet-Internal/AddonBroker'};
 assert.equal(validateClient(client,profile),client);assert.throws(()=>validateClient({...client,secret:h},profile));assert.throws(()=>validateClient({...client,endpoint:'https://example.org/'},profile));
});
test('Mozilla gate requires ordinary, compatible, unblocked signed package and modern known signature',()=>{
 const c=candidate(),good=install(c);assert.equal(signatureAccepted(good,c,api),true);
 for(const patch of [{signedState:0},{signedState:-2},{signedState:3},{signedTypes:[0]},{signedTypes:[2,999]},{signedTypes:[]},{type:'theme'},{isWebExtension:false},{appDisabled:true},{isCompatible:false},{blocklistState:1},{id:'other@example.invalid'}])assert.equal(signatureAccepted({...good,addon:{...good.addon,...patch}},c,api),false,JSON.stringify(patch));
 assert.equal(signatureAccepted(good,c,{...api,modern:[]}),false);
});
function guard(c,overrides={}){return new InstallGuard({mirror:mirror(c),inspectFile:()=>({sha256:c.archive_sha256,bytes:c.byte_length}),sameFile:(a,b)=>a===b,signature:(i,r)=>signatureAccepted(i,r,api),...overrides})}
test('factory ticket admits exact single object and cannot authorize same-path replacement',()=>{
 const c=candidate(),g=guard(c),first=install(c);g.prepare(c,'stage.xpi');g.onNewInstall(first);assert.equal(g.receipt(first),c);g.authorize(first);assert.equal(g.onInstallStarted(first),true);
 const second=install(c);g.onNewInstall(second);assert.equal(second.cancelled,true);assert.equal(g.onInstallStarted(second),false);
});
test('a verified factory object still needs native consent, and consent expires with its receipt',()=>{
 const c=candidate(),g=guard(c),unapproved=install(c);g.prepare(c,'stage.xpi');g.onNewInstall(unapproved);assert.equal(g.onInstallStarted(unapproved),false);assert.equal(unapproved.cancelled,true);
 const approved=install(c);g.prepare(c,'stage.xpi');g.onNewInstall(approved);g.authorize(approved);c.expires_at_ms=1;assert.equal(g.onInstallStarted(approved),false);assert.equal(approved.cancelled,true);
});
test('managed remote/update staging is denied before install start while unrelated extensions remain unaffected',()=>{
 const c=candidate(),g=guard(c);for(const method of ['onNewInstall','onDownloadStarted','onDownloadEnded','onInstallStarted']){const i=install(c);assert.equal(g[method](i),false);assert.equal(i.cancelled,true)}
 const unrelated=install({...c,addon_id:'other@example.invalid'});assert.equal(g.onNewInstall(unrelated),true);assert.equal(unrelated.cancelled,undefined);
});
test('tampered, unsigned or expired factory candidates never receive approval',()=>{
 const c=candidate();for(const opt of [{inspectFile:()=>({sha256:profile,bytes:c.byte_length})},{inspectFile:()=>({sha256:h,bytes:1})},{signature:()=>false}]){const g=guard(c,opt),i=install(c);g.prepare(c,'stage.xpi');g.onNewInstall(i);assert.equal(i.cancelled,true);assert.equal(g.receipt(i),null)}
 assert.throws(()=>guard(c).prepare({...c,expires_at_ms:1},'stage.xpi'));
});
test('guard failure denies all later objects and clears the outstanding factory ticket',()=>{
 const c=candidate(),g=guard(c),i=install(c);g.prepare(c,'stage.xpi');g.fail();g.onNewInstall(i);assert.equal(g.ticket,null);assert.equal(i.cancelled,true);assert.equal(g.receipt(i),null);
});
