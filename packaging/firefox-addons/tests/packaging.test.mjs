import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
const root=fileURLToPath(new URL('../',import.meta.url));
const pythonOptions={env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'},stdio:'pipe'};
test('fixed local anchors are staged for Linux/Windows and macOS without changing original precomplete',()=>{
 const temporary=mkdtempSync(join(tmpdir(),'epix-addon-package-'));
 try{for(const relative of ['firefox','Firefox.app/Contents/Resources']){
  const dir=join(temporary,relative);mkdirSync(dir,{recursive:true});const original='remove "browser/omni.ja"\n';writeFileSync(join(dir,'precomplete'),original);
  execFileSync('python3',[join(root,'install.py'),dir],pythonOptions);
  assert.equal(readFileSync(join(dir,'precomplete'),'utf8'),original);
  for(const name of ['epix-addons.cfg','defaults/pref/epix-addons.js','distribution/epix-addon-installer/manager.sys.mjs','distribution/epix-addon-installer/policy.sys.mjs','distribution/epix-addon-installer/manager.xhtml'])assert.ok(existsSync(join(dir,name)),name);
  assert.equal(readFileSync(join(dir,'epix-addons.cfg'),'utf8'),readFileSync(join(root,'epix-addons.cfg'),'utf8'));
 }}finally{rmSync(temporary,{recursive:true,force:true})}
});
test('packaging refuses a precomplete that would remove the custom guard during Mozilla update',()=>{
 const temporary=mkdtempSync(join(tmpdir(),'epix-addon-package-'));try{writeFileSync(join(temporary,'precomplete'),'remove "epix-addons.cfg"\n');assert.throws(()=>execFileSync('python3',[join(root,'install.py'),temporary],pythonOptions));}finally{rmSync(temporary,{recursive:true,force:true})}
});
