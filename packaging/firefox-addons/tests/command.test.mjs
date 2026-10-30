import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../manager.sys.mjs',import.meta.url),'utf8');
const body=source.slice(source.indexOf('function browserWindowForCommand('),source.indexOf('function openManager('));
const context=vm.createContext({});vm.runInContext(body,context);
function fixture(){const window={closed:false,gBrowser:{},document:{nodePrincipal:{isSystemPrincipal:true},documentElement:{getAttribute:()=> 'navigator:browser'}}};return{window,event:{isTrusted:true,target:{ownerDocument:{defaultView:window}}}}}
test('toolbar command binds the actual document window without removed ownerGlobal property',()=>{const {window,event}=fixture();assert.equal(event.target.ownerGlobal,undefined);assert.equal(context.browserWindowForCommand(event),window)});
test('synthetic, content, nonbrowser and closed windows cannot open the trusted manager',()=>{
 const a=fixture();a.event.isTrusted=false;assert.equal(context.browserWindowForCommand(a.event),null);
 const b=fixture();b.window.document.nodePrincipal.isSystemPrincipal=false;assert.equal(context.browserWindowForCommand(b.event),null);
 const c=fixture();c.window.document.documentElement.getAttribute=()=> 'other';assert.equal(context.browserWindowForCommand(c.event),null);
 const d=fixture();d.window.closed=true;assert.equal(context.browserWindowForCommand(d.event),null);
 assert.equal(context.browserWindowForCommand({isTrusted:true,target:{ownerGlobal:fixture().window}}),null);
});
