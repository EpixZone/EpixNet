#!/usr/bin/env python3
"""Official Windows MAR preservation and exact native cache-reader QA only."""
import argparse,ctypes,hashlib,hmac,http.server,importlib.util,json,os,shutil,socket,struct,subprocess,sys,tempfile,threading,time,traceback,urllib.parse,urllib.request
from pathlib import Path
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
def module(name,file):
 s=importlib.util.spec_from_file_location(name,file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
joblib=module('owned',HERE/'issue-646-owned-job.py');driver=module('driver',HERE/'issue-646-marionette.py')
def check(v,m):
 if not v:raise RuntimeError(m)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
def version(root):
 return next(x.split('=',1)[1] for x in (root/'application.ini').read_text().splitlines() if x.startswith('Version='))
def download(url,path,expected):
 n=0
 with urllib.request.urlopen(url,timeout=45) as r,path.open('wb') as f:
  while b:=r.read(1024*1024):
   n+=len(b);check(n<=180*1024**2,'download size bound');f.write(b)
 check(sha(path)==expected,'official artifact digest mismatch')
def frame(fields):return b''.join(struct.pack('>Q',len(b))+b for b in fields)
def main():
 a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--metadata-reader',type=Path,required=True);args=a.parse_args()
 check(sys.platform=='win32','native Windows required');out=args.output.resolve();out.mkdir(exist_ok=True)
 root=Path(tempfile.mkdtemp(prefix='epix646-update-',dir=os.environ['RUNNER_TEMP']));check(shutil.disk_usage(root).free>30*1024**3,'30GiB floor')
 jobs=[];logs=[];browser=None;server=None;proc=None;profile=None;report={'scope':'Official Windows complete MAR with unmodified updater signature verification, exact production adapter resources and isolated synthetic authenticated broker. Native AOM addon/cache fixture and actual production Rust preflight modules. Not the complete EpixNet launcher or xite-download integration.','root':str(root),'headless':True,'diagnostics':'Marionette chrome context is enabled only for this disposable profile. Production adapter files are unchanged. Toolbar manager opens through its real command handler; addon permission uses a WebDriver native element click with isTrusted assertion.','passed':False,'cases':{},'errors':[]}
 def result():save(out/'result.json',report)
 def stop_all():
  for j in jobs:j.close()
 timer=threading.Timer(600,stop_all);timer.daemon=True;timer.start()
 def run(argv,label,env=None,timeout=90):
  log=(out/(label+'.log')).open('wb');logs.append(log);job=joblib.WindowsJob();jobs.append(job);p=job.launch([str(x) for x in argv],cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
  try:return p.wait(timeout=timeout)
  finally:job.close();log.flush()
 def authsign(path):
  env=os.environ.copy();env['EPIX_QA_SIGNATURE_PATH']=str(path)
  r=subprocess.run(['pwsh','-NoProfile','-Command','$s=Get-AuthenticodeSignature -LiteralPath $env:EPIX_QA_SIGNATURE_PATH; @{Status=$s.Status.ToString();Subject=$s.SignerCertificate.Subject;Thumbprint=$s.SignerCertificate.Thumbprint}|ConvertTo-Json -Compress'],env=env,capture_output=True,text=True,timeout=30,check=True)
  value=json.loads(r.stdout);check(value['Status']=='Valid' and 'Mozilla Corporation' in value['Subject'],'official executable signature invalid');return value
 try:
  info=json.loads((HERE/'issue-646-mozilla.json').read_text());artifacts={}
  for label,v,path in [('old','153.3.0esr','win64/en-US/Firefox Setup 153.3.0esr.exe'),('new','153.4.0esr','win64/en-US/Firefox Setup 153.4.0esr.exe'),('mar','153.4.0esr','update/win64/en-US/firefox-153.4.0esr.complete.mar')]:
   entry=next(x for x in info[v]['entries'] if x.endswith('  '+path));expected=entry.split('  ',1)[0];url='https://archive.mozilla.org/pub/firefox/releases/'+v+'/'+urllib.parse.quote(path)
   dest=root/(label+('.mar' if label=='mar' else '.exe'));download(url,dest,expected);artifacts[label]={'url':url,'sha256':expected,'bytes':dest.stat().st_size}
   if label!='mar':
    artifacts[label]['authenticode']=authsign(dest);check(run(['7z','x',dest,'-o'+str(root/label),'-y'],'extract-'+label)==0,'7z extraction failed')
  report['artifacts']=artifacts;ff=root/'old/core';control=root/'new/core';check(version(ff)=='153.3.0' and version(control)=='153.4.0','official version mismatch')
  report['old_updater_authenticode']=authsign(ff/'updater.exe');before_pre=sha(ff/'precomplete');control_pre=sha(control/'precomplete');control_firefox=sha(control/'firefox.exe')
  check(run([sys.executable,REPO/'packaging/firefox-addons/install.py',ff],'stage-adapter')==0,'adapter staging failed');check(sha(ff/'precomplete')==before_pre,'original precomplete modified by adapter injection')
  paths=['epix-addons.cfg','defaults/pref/epix-addons.js']+['distribution/epix-addon-installer/'+p.name for p in (ff/'distribution/epix-addon-installer').iterdir() if p.is_file()]
  adapter={p:sha(ff/p) for p in paths};report['adapter_sha256']=adapter;report['precomplete']={'before_injection':before_pre,'after_injection':sha(ff/'precomplete'),'new_official':control_pre};old_firefox=sha(ff/'firefox.exe')
  env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','SYSTEMDRIVE','COMSPEC','PATHEXT','PATH','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS','OS'}}
  for name in ['home','appdata','localappdata','tmp']:(root/name).mkdir()
  env.update(HOME=str(root/'home'),USERPROFILE=str(root/'home'),APPDATA=str(root/'appdata'),LOCALAPPDATA=str(root/'localappdata'),TEMP=str(root/'tmp'),TMP=str(root/'tmp'),MOZ_APP_SILENT_START='1',MOZ_CRASHREPORTER_DISABLE='1')
  for label,tamper in [('tampered-signature',True),('official-update',False)]:
   patch=root/label;patch.mkdir();shutil.copyfile(root/'mar.mar',patch/'update.mar')
   if tamper:
    with (patch/'update.mar').open('r+b') as f:
     head=f.read(28);check(head[:4]==b'MAR1' and int.from_bytes(head[16:20],'big')==1 and int.from_bytes(head[24:28],'big')==512,'unexpected signed MAR layout');b=f.read(1);f.seek(28);f.write(bytes([b[0]^1]))
   code=run([ff/'updater.exe','3',patch,ff,ff,'first','0'],label,env,180)
   status=(patch/'update.status').read_text().strip();report['cases'][label]={'returncode':code,'status':status,'version':version(ff),'archive_sha256':sha(patch/'update.mar')}
   for name in ['update.status','update.log','last-update.log']:
    if (patch/name).exists():shutil.copyfile(patch/name,out/(label+'-'+name.replace('/','-')))
   result()
   if tamper:check(code!=0 and status=='failed: 19' and version(ff)=='153.3.0' and sha(ff/'firefox.exe')==old_firefox,'corrupted MAR signature was not conclusively rejected')
   else:check(code==0 and status=='succeeded' and version(ff)=='153.4.0' and sha(ff/'firefox.exe')==control_firefox,'official MAR did not produce exact new Firefox')
   check(all(sha(ff/p)==h for p,h in adapter.items()),'update changed or removed trusted adapter file');(patch/'update.mar').unlink()
  check(sha(ff/'precomplete')==control_pre,'new precomplete differs from official build');report['precomplete']['after_update']=sha(ff/'precomplete');report['updated_firefox_authenticode']=authsign(ff/'firefox.exe');result()
  profile=root/'profile space é 雪 ;#literal%20';profile.mkdir();(profile/'epix-addons').mkdir();pid='3'*64;client='2'*64;secret=os.urandom(32).hex();requests=[]
  def current_session():
   mirror=json.loads((profile/'epix-addons/mirror.json').read_text());return {'session_id':'4'*64,'profile_id':pid,'engine':'Gecko','needs_reconciliation':False,'managed':mirror['managed'],'operation':None}
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_POST(self):
    length=int(self.headers.get('Content-Length','0'));check(0<length<=65536,'request bound');body=self.rfile.read(length);nonce=self.headers.get('X-Epix-Addon-Nonce','');stamp=self.headers.get('X-Epix-Addon-Time','');who=self.headers.get('X-Epix-Addon-Client','');mac=self.headers.get('X-Epix-Addon-Mac','');expected=hmac.new(secret.encode(),b'EpixNet addon broker request v1\0'+frame([who.encode(),nonce.encode(),stamp.encode(),body]),hashlib.sha256).hexdigest();valid=hmac.compare_digest(mac,expected) and who==client and self.path=='/EpixNet-Internal/AddonBroker' and not self.headers.get('Origin');command=json.loads(body).get('command') if valid else None;requests.append({'command':command,'authenticated':valid});status=200 if valid and command in ['open','reconcile','status'] else 400;raw=json.dumps({'ok':True,'result':current_session()} if status==200 else {'ok':False,'error':{'code':'InvalidRequest','message':'Synthetic updater probe only'}}).encode();signature=hmac.new(secret.encode(),b'EpixNet addon broker response v1\0'+frame([who.encode(),nonce.encode(),stamp.encode()])+struct.pack('>H',status)+frame([raw]),hashlib.sha256).hexdigest();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('X-Epix-Addon-Mac',signature);self.end_headers();self.wfile.write(raw)
   def log_message(self,*args):pass
  server=http.server.HTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  for name,value in {'profile.json':{'protocol':1,'profile_id':pid},'client.json':{'protocol':1,'profile_id':pid,'client_id':client,'endpoint':f'http://127.0.0.1:{server.server_port}/EpixNet-Internal/AddonBroker'},'mirror.json':{'protocol':1,'profile_id':pid,'managed':[],'pending':None}}.items():save(profile/'epix-addons'/name,value)
  sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
  prefs={'marionette.port':port,'browser.shell.checkDefaultBrowser':False,'browser.aboutwelcome.enabled':False,'termsofuse.bypassNotification':True,'browser.startup.homepage_override.mstone':'ignore','network.proxy.type':1,'network.proxy.http':'127.0.0.1','network.proxy.http_port':9,'network.proxy.ssl':'127.0.0.1','network.proxy.ssl_port':9,'network.proxy.no_proxies_on':'127.0.0.1, localhost','datareporting.policy.dataSubmissionEnabled':False,'extensions.update.enabled':False}
  (profile/'user.js').write_text(''.join('user_pref('+json.dumps(k)+','+json.dumps(v)+');\n' for k,v in prefs.items()))
  env.pop('MOZ_APP_SILENT_START',None)  # Updater-only environment must not suppress a normal browser window.
  env.update(EPIX_ADDON_BROKER_CLIENT=client,EPIX_ADDON_BROKER_SECRET=secret,MOZ_MARIONETTE='1',MOZ_HEADLESS='1')
  log=(out/'firefox.log').open('wb');logs.append(log);job=joblib.WindowsJob();jobs.append(job);extended='\\\\?\\'+str(profile.resolve());proc=job.launch([str(ff/'firefox.exe'),'--no-remote','--profile',extended,'--marionette','--remote-allow-system-access','--width','1280','--height','900','about:blank'],cwd=ff,env=env,stdout=log,stderr=subprocess.STDOUT)
  connection_errors=[]
  def connect():
   try:return driver.Marionette(port)
   except (OSError,RuntimeError) as error:
    text=str(error)
    if text not in connection_errors:connection_errors.append(text)
    return None
  browser=driver.wait(connect,60);report['marionette_initial_connection_errors']=connection_errors;browser.cmd('Marionette:SetContext',{'value':'chrome'})
  def js(script,args=[]):return browser.cmd('WebDriver:ExecuteScript',{'script':script,'args':args,'newSandbox':False,'sandbox':'default'})['value']
  state=driver.wait(lambda:js("const w=Services.wm.getMostRecentWindow('navigator:browser');const b=w?.document.getElementById('epix-xite-extensions');return b?{version:Services.appinfo.version,profile:Services.dirsvc.get('ProfD',Ci.nsIFile).path,widget:b.getAttribute('label'),appUpdatesAllowed:Services.policies.isAllowed('appUpdate'),errors:Services.console.getMessageArray().map(x=>x.message).filter(x=>/EpixNet extension manager unavailable/.test(x))}:null;"),45);report['native_startup']=state;check(state['version']=='153.4.0' and state['appUpdatesAllowed'] and not state['errors'],'updated native bootstrap failed or updater policy disabled');browser.screenshot(out/'updated-browser.png');result()
  js("const w=Services.wm.getMostRecentWindow('navigator:browser');w.document.getElementById('epix-xite-extensions').doCommand();return true;")
  ready=driver.wait(lambda:js("const m=Array.from(Services.wm.getEnumerator(null)).find(w=>w.document.documentURI.includes('manager.xhtml'));const text=m?.document.getElementById('status')?.textContent;return text?.startsWith('Ready.')?{status:text,systemPrincipal:Services.scriptSecurityManager.isSystemPrincipal(m.document.nodePrincipal)}:null;"),35);check(ready['systemPrincipal'],'manager is not privileged chrome');report['manager_ready']=ready
  js("for(const m of Services.wm.getEnumerator(null)){if(m.document.documentURI.includes('manager.xhtml'))m.close()}Services.wm.getMostRecentWindow('navigator:browser').focus();return true;")
  xpi=root/'public-signed.xpi';xpi_hash='175756d74468c9ba45863f7fc333d3be670f82d5b066314e915814dd547d1652';download('https://addons.mozilla.org/firefox/downloads/file/4981431/ublock_origin-1.74.0.xpi',xpi,xpi_hash)
  # Ordinary public AOM install solely creates an authentic engine cache fixture.
  # This is not enrollment by the shared xite broker and is recorded as such.
  js("window.__qaInstall={};(async()=>{try{const {AddonManager}=ChromeUtils.importESModule('resource://gre/modules/AddonManager.sys.mjs');const f=Cc['@mozilla.org/file/local;1'].createInstance(Ci.nsIFile);f.initWithPath(arguments[0]);const i=await AddonManager.getInstallForFile(f);window.__qaInstall.signature={state:i.addon.signedState,types:i.addon.signedTypes,id:i.addon.id,version:i.addon.version};i.addListener({onInstallEnded(_i,a){window.__qaInstall.done={id:a.id,version:a.version}},onInstallFailed(){window.__qaInstall.error='install failed'},onInstallCancelled(){window.__qaInstall.error='cancelled'}});const w=Services.wm.getMostRecentWindow('navigator:browser');AddonManager.installAddonFromAOM(w.gBrowser.selectedBrowser,Services.io.newURI('https://addons.mozilla.org/'),i)}catch(e){window.__qaInstall.error=String(e)}})();return true;",[str(xpi)])
  prompt=driver.wait(lambda:js("const w=Services.wm.getMostRecentWindow('navigator:browser');const n=w.document.getElementById('addon-webext-permissions-notification');const b=n?.button;if(!b||!b.getBoundingClientRect().width)return null;window.__qaPromptButton=b;b.addEventListener('click',e=>window.__qaTrusted=e.isTrusted,{once:true});return {label:b.label||b.textContent,text:n.textContent};"),30);report['native_prompt']=prompt;browser.screenshot(out/'native-permission-prompt.png');time.sleep(3)
  button=browser.cmd('WebDriver:ExecuteScript',{'script':'return window.__qaPromptButton;','args':[],'newSandbox':False,'sandbox':'default'})['value'];browser.cmd('WebDriver:ElementClick',{'id':button['element-6066-11e4-a52e-4f735466cecf']})
  installed=driver.wait(lambda:js('return window.__qaInstall?.error?{error:window.__qaInstall.error}:window.__qaInstall?.done?{...window.__qaInstall,trusted:window.__qaTrusted}:null;'),40);report['native_addon']=installed;check(not installed.get('error') and installed['trusted'] is True and installed['signature']['state']==2 and any(t in [1,2] for t in installed['signature']['types']),'ordinary signed native install failed');browser.screenshot(out/'installed-browser.png');js("setTimeout(()=>Services.startup.quit(Ci.nsIAppStartup.eAttemptQuit),100);return true;");proc.wait(timeout=30);browser.s.close();browser=None;job.close()
  owner={'addon_id':'uBlock0@raymondhill.net','version':'1.74.0','archive_sha256':xpi_hash,'publisher':'epix1ktlpswgz7swur406lurtq9u4argvwtkgzmr97x','inner_path':'addons/extension.xpi','source_url':'https://epix1ktlpswgz7swur406lurtq9u4argvwtkgzmr97x.epix/addons/extension.xpi','engine':'Gecko'};save(profile/'epix-addons/mirror.json',{'protocol':1,'profile_id':pid,'managed':[owner],'pending':None})
  archive=profile/'extensions/uBlock0@raymondhill.net.xpi';check(sha(archive)==xpi_hash,'native installed archive bytes changed');report['metadata_fixture']={'source':'Actual normal AOM native Allow, followed by a QA-only expected ownership receipt for isolated production reader validation. Not shared-core enrollment.','native_profile':state['profile'],'launcher_profile':extended,'archive_sha256':sha(archive)}
  for name in ['extensions.json','addonStartup.json.lz4']:
   check((profile/name).stat().st_size<16*1024**2,'cache evidence bound');shutil.copyfile(profile/name,out/name)
  report['metadata_reader_returncode']=run([args.metadata_reader,ff/'firefox.exe',profile,pid],'production-metadata-reader',timeout=30);check(report['metadata_reader_returncode']==0,'production Windows metadata preflight rejected actual cache')
  report['requests']=requests;report['passed']=True;result()
 except Exception as e:
  report['errors'].append(str(e))
  if proc is not None:report['browser_returncode']=proc.poll()
  if 'connection_errors' in locals():report['marionette_initial_connection_errors']=connection_errors
  if profile is not None and profile.exists():
   report['profile_file_inventory']=[{'path':str(p.relative_to(profile)),'bytes':p.stat().st_size} for p in list(profile.rglob('*'))[:4096] if p.is_file()]
  (out/'exception.log').write_text(traceback.format_exc());result();raise
 finally:
  if browser:
   try:browser.close()
   except Exception:pass
  stop_all();time.sleep(2)
  if server:server.shutdown();server.server_close()
  for log in logs:log.close()
  timer.cancel();shutil.rmtree(root);save(out/'cleanup.json',{'owned_root_removed':not root.exists(),'jobs_closed':all(j.handle is None for j in jobs)});check(not root.exists(),'owned cleanup incomplete')
if __name__=='__main__':main()
