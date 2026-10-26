#!/usr/bin/env python3
"""Bounded Windows baseline evidence. No production changes or external identities."""
import argparse, base64, ctypes, datetime, hashlib, http.client, importlib.util, json, os
from pathlib import Path
import re, shutil, socket, subprocess, sys, tempfile, threading, time
from urllib.parse import urlencode, urlsplit, unquote

SOURCE = 'b5353fb1ab2440652b2bff23cbb99c819df783f6'
RELEASE_SHA = 'ed18f5dd2c2e6935b30d4bc36d3b3fda53581f88d93c923690c591d1b80f1bba'
DASHBOARD = 'epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g'

def check(value, message):
    if not value: raise RuntimeError(message)

def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def extract_function(source, name):
    start = source.index('fn '+name+'(')
    opening = source.index('{', start)
    depth = 1
    for end in range(opening+1,len(source)):
        if source[end] == '{': depth += 1
        if source[end] == '}': depth -= 1
        if depth == 0: return source[start:end+1]
    raise ValueError(name)

def request(port, path, body=None):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        headers = {'Origin':f'http://127.0.0.1:{port}', 'Referer':f'http://127.0.0.1:{port}{path}'}
        if body is not None: headers['Content-Type']='application/x-www-form-urlencoded'
        c.request('POST' if body is not None else 'GET',path,body,headers)
        r=c.getresponse(); data=r.read(4*1024*1024)
        return r.status,dict(r.getheaders()),data
    finally: c.close()

def wait(fn, seconds=60):
    end=time.monotonic()+seconds; last=None
    while time.monotonic()<end:
        try:
            value=fn()
            if value:return value
        except (OSError,ValueError,KeyError,http.client.HTTPException) as e:last=str(e)
        time.sleep(.3)
    raise TimeoutError('readiness deadline: '+str(last))

class Marionette:
    def __init__(self, port):
        self.s=socket.create_connection(('127.0.0.1',port),timeout=5);self.s.settimeout(35);self.n=0
        check(self.recv().get('marionetteProtocol')==3,'unexpected Marionette protocol')
        session=self.cmd('WebDriver:NewSession',{'acceptInsecureCerts':False,'pageLoadStrategy':'normal'})
        check(session['capabilities']['acceptInsecureCerts'] is False,'certificate verification bypassed')
        self.cmd('WebDriver:SetTimeouts',{'pageLoad':20000,'script':20000,'implicit':0})
    def recv(self):
        prefix=b''
        while not prefix.endswith(b':'):
            chunk=self.s.recv(1);check(chunk,'Marionette closed');prefix+=chunk
            check(len(prefix)<20,'invalid Marionette header')
        size=int(prefix[:-1]);check(size<8*1024*1024,'response too large');body=b''
        while len(body)<size:
            chunk=self.s.recv(size-len(body));check(chunk,'Marionette closed');body+=chunk
        return json.loads(body)
    def cmd(self,name,args):
        self.n+=1;body=json.dumps([0,self.n,name,args]).encode()
        self.s.sendall(str(len(body)).encode()+b':'+body);r=self.recv()
        check(r[:2]==[1,self.n],'unexpected Marionette sequence')
        if r[2] is not None:raise RuntimeError(name+': '+json.dumps(r[2])[:700])
        return r[3]
    def page(self,url):
        error=None
        try:self.cmd('WebDriver:Navigate',{'url':url})
        except Exception as e:error=str(e)
        try:
            state=self.cmd('WebDriver:ExecuteScript',{'script':"return {url:location.href,uri:document.documentURI,title:document.title,secure:isSecureContext,text:document.body?.innerText?.slice(0,500),frame:document.querySelector('iframe')?.src};",'args':[],'newSandbox':True,'sandbox':'default'})['value']
        except Exception as e:state={'inspection_error':str(e)}
        if error:state['navigation_error']=error
        return state
    def screenshot(self,path):
        try:
            result=self.cmd('WebDriver:TakeScreenshot',{'id':None,'full':False,'highlights':[]})
            if isinstance(result,dict):result=result['value']
            path.write_bytes(base64.b64decode(result))
        except Exception as e:return str(e)
    def close(self):
        try:self.cmd('WebDriver:DeleteSession',{})
        except Exception:pass
        self.s.close()

def volume(root):
    serial=ctypes.c_ulong();fs=ctypes.create_unicode_buffer(256);name=ctypes.create_unicode_buffer(256)
    api=ctypes.windll.kernel32.GetVolumeInformationW
    api.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_ulong,ctypes.POINTER(ctypes.c_ulong),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_ulong]
    ok=api(str(root),name,256,ctypes.byref(serial),None,None,fs,256)
    return {'root':str(root),'serial':serial.value if ok else None,'filesystem':fs.value,'label':name.value}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--package',type=Path,required=True);parser.add_argument('--installer',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    check(sys.platform=='win32','native Windows only')
    check(sha(a.installer)==RELEASE_SHA,'release installer digest mismatch')
    actual=subprocess.check_output(['git','-C',str(a.source),'rev-parse','HEAD'],text=True).strip();check(actual==SOURCE,'source revision mismatch')
    spec=importlib.util.spec_from_file_location('owned',Path(__file__).with_name('issue-649-owned-job.py'));owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    root=Path(tempfile.mkdtemp(prefix='epix-issue649-',dir=os.environ['RUNNER_TEMP']))
    roots=[root];jobs=[];handles=[];browser=None;timer=None
    report={'source':SOURCE,'runtime_release':'v0.5.23','runtime_release_revision':'f298e0a002be1b20007d7898a01749cde8a6a582','installer_sha256':RELEASE_SHA,'scope':'Native Windows Server baseline. Current source helper plus packaged release Config migration and bundled Firefox. Not reporter Windows 10 or v0.5.3. Built-in dashboard xite only; no downloaded hubs or public publishing.','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'cases':[],'errors':[],'owned_roots':[str(root)]}
    def save(): (out/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    def stop():
        nonlocal browser
        if browser:browser.close();browser=None
        for j in jobs:j.close()
        jobs.clear();time.sleep(2)
        for h in handles:h.close()
        handles.clear()
    def expire():
        for j in jobs:j.close()
    timer=threading.Timer(600,expire);timer.daemon=True;timer.start()
    try:
        check(shutil.disk_usage(root).free>8*1024**3,'need 8 GiB free for bounded runtime')
        sources={n:(a.source/p).read_text() for n,p in [('browser','crates/epix-browser/src/main.rs'),('paths','crates/epix-ui/src/paths.rs')]}
        f=extract_function(sources['browser'],'file_url');resolve=extract_function(sources['paths'],'resolve_data_directory')
        helper=root/'path_probe.rs';helper.write_text('use std::path::{Path,PathBuf,Component};\n'+f+'\n'+resolve+'\nfn main(){let a:Vec<String>=std::env::args().collect();let p=PathBuf::from(&a[2]);let q=match a[1].as_str(){"canonical"=>p.canonicalize().unwrap(),"resolved"=>resolve_data_directory(&p).unwrap(),_=>p};println!("{}",q.display());println!("{}",file_url(&q));}\n')
        exe=root/'path_probe.exe'
        subprocess.run(['rustc','--edition=2021',str(helper),'-o',str(exe)],check=True,timeout=60,capture_output=True)
        report['helper']={'sha256':sha(helper),'file_url_sha256':hashlib.sha256(f.encode()).hexdigest(),'resolver_sha256':hashlib.sha256(resolve.encode()).hexdigest()}
        (out/'path_probe.rs').write_bytes(helper.read_bytes())
        for label in ('ordinary','has space','has#fragment','literal%20escape'):
            p=root/label/'epix.pac';p.parent.mkdir();p.write_text('function FindProxyForURL(url, host) { return "DIRECT"; }\n')
            for mode in ('plain','canonical'):
                lines=subprocess.check_output([str(exe),mode,str(p)],text=True).splitlines();parts=urlsplit(lines[1])
                report['cases'].append({'label':label,'mode':mode,'native_path':lines[0],'file_url':lines[1],'url_query':parts.query,'url_fragment':parts.fragment,'decoded_url_path':unquote(parts.path),'expected_file_exists':p.exists()})
        # Existing root resolution is the exact setter path before appending the PAC file.
        lines=subprocess.check_output([str(exe),'resolved',str(root/'future')],text=True).splitlines();report['resolved_missing_suffix']={'native_path':lines[0],'url':lines[1]}
        save()
        # Select another actual volume, if present. No SUBST alias is used.
        origin=volume(Path(root.anchor));report['origin_volume']=origin
        alternate=None
        for drive in ('C:\\','D:\\','E:\\'):
            if not Path(drive).exists():continue
            info=volume(Path(drive))
            if info['serial'] is not None and info['serial']!=origin['serial']:
                try:alternate=Path(tempfile.mkdtemp(prefix='epix-issue649-',dir=drive));roots.append(alternate);report['destination_volume']=info;break
                except OSError:pass
        if alternate is None:alternate=root/'same-volume';alternate.mkdir();report['destination_volume']=origin
        report['distinct_volume']=report['origin_volume']['serial']!=report['destination_volume']['serial'];report['owned_roots']=[str(p) for p in roots]
        candidates=[p for p in a.package.rglob('epix-browser.exe') if (p.parent/'firefox/firefox.exe').exists()]
        check(len(candidates)==1,'expected one extracted launcher with bundled Firefox')
        launcher=candidates[0].resolve();report['launcher_sha256']=sha(launcher);report['firefox_sha256']=sha(launcher.parent/'firefox/firefox.exe')
        env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','SYSTEMDRIVE','COMSPEC','PATHEXT','PATH','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS','OS'}}
        for name in ('home','appdata','localappdata','tmp'): (root/name).mkdir()
        env.update(HOME=str(root/'home'),USERPROFILE=str(root/'home'),APPDATA=str(root/'appdata'),LOCALAPPDATA=str(root/'localappdata'),TEMP=str(root/'tmp'),TMP=str(root/'tmp'),EPIX_TOR='disable',TOKIO_WORKER_THREADS='2',MOZ_MARIONETTE='1',MOZ_HEADLESS='1')
        policy=launcher.parent/'firefox/distribution/policies.json'
        original_policy=sha(policy);policy_value=json.loads(policy.read_text(encoding='utf-8-sig'))
        install=policy_value.setdefault('policies',{}).setdefault('Certificates',{}).setdefault('Install',[])
        install.append(str(root/'localappdata/Mozilla/Certificates/epix-ca.pem'))
        policy.write_text(json.dumps(policy_value),encoding='utf8')
        report['fixture_certificate_policy']={'original_sha256':original_policy,'fixture_sha256':sha(policy),'change':'Add absolute path to the disposable QA CA; Windows known-folder lookup ignores isolated APPDATA. No trust bypass; acceptInsecureCerts=false.'}
        default=root/'appdata/EpixNet';(default/'private').mkdir(parents=True)
        (default/'private/config.json').write_text(json.dumps({'offline':True,'xid_lc_enabled':False,'chain_rpc_url':'http://127.0.0.1:9','chain_evm_rpc_url':'http://127.0.0.1:9'}))
        # Public harmless data is copied alongside the generated identity without exposing either identity or its keys.
        (default/'data/qa-copy-marker').mkdir(parents=True);(default/'data/qa-copy-marker/marker.txt').write_text('issue-649 disposable copy marker\n')
        def launch(data,label):
            profile=data/'firefox-profile';profile.mkdir(parents=True,exist_ok=True)
            (profile/'prefs.js').write_text('user_pref("marionette.port", 2828);\n')
            log=(root/(label+'.raw.log')).open('wb');handles.append(log);job=owned.WindowsJob();jobs.append(job)
            proc=job.launch([str(launcher),'dashboard.epix'],env=env,cwd=launcher.parent,stdout=log,stderr=subprocess.STDOUT)
            def ready():
                if proc.poll() is not None:raise RuntimeError('launcher exited '+str(proc.returncode))
                port=int((data/'ui_port').read_text().strip());code,_,body=request(port,'/EpixNet-Internal/Status')
                if code!=200:return None
                status=json.loads(body)
                return port,status
            port,status=wait(ready,90)
            detail={'pid':proc.pid,'port':port,'status':{k:status.get(k) for k in ('serving','tor_enabled','i2p_enabled','mesh_enabled','connections')}}
            check(status.get('connections',{}).get('total')==0,'unexpected peer connection')
            check(json.loads((data/'private/config.json').read_text()).get('offline') in (True,'true'),'offline config lost')
            detail['direct_config_http']=request(port,'/Config')[0]
            detail['direct_dashboard_http']=request(port,'/'+DASHBOARD+'/')[0]
            return port,detail
        port,report['before']=launch(default,'before')
        def connect():
            try:return Marionette(2828)
            except (OSError,RuntimeError):return None
        browser=wait(connect,60)
        report['before']['page']=browser.page('https://dashboard.epix/')
        report['before']['screenshot_error']=browser.screenshot(out/'before-dashboard.png')
        report['tls_scope']='Disposable absolute certificate policy path compensates Windows known-folder lookup; actual bundled Firefox verifies the QA local CA with acceptInsecureCerts=false.'
        for case in report['cases']:
            blank=browser.page('about:blank')
            check(blank.get('uri')=='about:blank' and not blank.get('navigation_error'),'failed to clear prior case document')
            case['firefox']=browser.page(case['file_url'])
            case['firefox_file_loaded']=not case['firefox'].get('navigation_error') and 'function FindProxyForURL' in (case['firefox'].get('text') or '')
        save()
        prefs=(default/'firefox-profile/user.js').read_text();report['before']['pac_url']=re.search(r'user_pref\("network.proxy.autoconfig_url", (.+)\);',prefs)[1]
        # Read Config token only in memory, never place the page or token in artifacts.
        code,_,body=request(port,'/Config');check(code==200,'Config not reachable')
        match=re.search(r"name=['\"]csrf['\"]\s+value=['\"]([^'\"]+)",body.decode());check(match,'Config CSRF field missing')
        target=alternate/'EpixNet moved';body=urlencode({'csrf':match[1],'data_dir':str(target),'offline':'on','xid_lc_enabled':'false'}).encode()
        code,headers,_=request(port,'/Config',body);report['move']={'http_status':code,'location':headers.get('location') or headers.get('Location'),'requested':str(target)}
        check(code in (302,303),'Config move not redirected')
        if '/Config?error=' in (report['move']['location'] or ''):
            # Preserve the actual active-copy failure, then isolate the independent
            # PAC restart behavior using the supported existing-identity switch.
            report['active_copy_failure']=dict(report['move']);save()
            # Read source files only; a throwaway destination identifies the
            # first Windows sharing lock without overwriting the partial move.
            copy_probe=root/'copy-probe';copy_probe.mkdir()
            probe={'scanned_files':0,'failures':[],'scope':'Read/copy active disposable source into an owned scratch destination; no source edits'}
            for part in ('private','data'):
                for source_file in (default/part).rglob('*'):
                    if not source_file.is_file():continue
                    probe['scanned_files']+=1
                    check(probe['scanned_files']<=20000,'copy probe file bound reached')
                    dest=copy_probe/'one-file'
                    try:shutil.copyfile(source_file,dest)
                    except OSError as error:probe['failures'].append({'source_relative_path':str(source_file.relative_to(default)),'winerror':getattr(error,'winerror',None),'errno':error.errno,'message':str(error)})
                    finally:dest.unlink(missing_ok=True)
            report['active_copy_probe']=probe;save();stop()
            target.mkdir(parents=True,exist_ok=True)
            for part in ('private','data'):
                if (default/part).exists():shutil.copytree(default/part,target/part,dirs_exist_ok=True)
            report['stopped_copy_control']={'identity_present':(target/'private/users.json').exists(),'scope':'Only disposable fixture data, copied after all owned app processes stop. This does not repair or pass the failing live Config copy.'}
            check(report['stopped_copy_control']['identity_present'],'copied target has no fixture identity')
            port,report['control_default_restart']=launch(default,'control-default')
            code,_,body=request(port,'/Config');check(code==200,'Config control not reachable')
            match=re.search(r"name=['\"]csrf['\"]\s+value=['\"]([^'\"]+)",body.decode());check(match,'control CSRF missing')
            code,headers,_=request(port,'/Config',urlencode({'csrf':match[1],'data_dir':str(target),'offline':'on','xid_lc_enabled':'false'}).encode())
            report['move_existing_identity']={'http_status':code,'location':headers.get('location') or headers.get('Location')}
            check(code in (302,303) and '/Config?done=' in (report['move_existing_identity']['location'] or ''),'existing identity Config switch failed')
        conf=(default/'epixnet.conf').read_text();value=re.search(r'^data_dir\s*=\s*(.+)$',conf,re.M);check(value,'Config omitted new data root')
        report['move']['persisted_data_dir']=value[1];report['move']['copy_marker_matches']=(target/'data/qa-copy-marker/marker.txt').read_bytes()==(default/'data/qa-copy-marker/marker.txt').read_bytes()
        report['move']['identity_copy_present']=(target/'private/users.json').exists();save();stop()
        moved=Path(value[1]);port,report['after']=launch(moved,'after');save()
        browser=wait(connect,60);report['after']['page']=browser.page('https://dashboard.epix/');report['after']['screenshot_error']=browser.screenshot(out/'after-dashboard.png')
        prefs=(moved/'firefox-profile/user.js').read_text();report['after']['pac_url']=re.search(r'user_pref\("network.proxy.autoconfig_url", (.+)\);',prefs)[1]
        report['after']['pac_exists']=(moved/'firefox-profile/epix.pac').exists()
        report['after']['direct_node_config_page']=browser.page('http://127.0.0.1:'+str(port)+'/Config');browser.screenshot(out/'after-direct-config.png')
        report['completed']=True
    except Exception as e:
        report['errors'].append(type(e).__name__+': '+str(e)[:1000]);report['completed']=False
    finally:
        if timer:timer.cancel()
        stop()
        # Keep only redacted diagnostic tails, never profiles, keys, cookies, or Config HTML.
        for path in list(root.glob('*.raw.log'))+list(root.rglob('epix-browser.log')):
            text=path.read_bytes()[-512*1024:].decode('utf8',errors='replace')
            lines=['[redacted]' if re.search('private.?key|secret|mnemonic|master.?seed|authorization|password|token|cookie',line,re.I) else line for line in text.splitlines()]
            (out/(path.stem+'.log')).write_text('\n'.join(lines),encoding='utf8')
        report['cleanup']={'removed':[],'errors':[]}
        for p in reversed(roots):
            try:shutil.rmtree(p);report['cleanup']['removed'].append(str(p))
            except OSError as e:report['cleanup']['errors'].append(str(e))
        report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
    print(json.dumps({'completed':report.get('completed'),'case_count':len(report['cases']),'errors':report['errors'],'distinct_volume':report.get('distinct_volume')}))
    return 0 if report.get('completed') else 1

if __name__=='__main__':sys.exit(main())
