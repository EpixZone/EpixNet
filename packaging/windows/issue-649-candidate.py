#!/usr/bin/env python3
"""Actual Windows candidate acceptance using only disposable, offline data."""
import argparse, datetime, hashlib, importlib.util, json, os
from html.parser import HTMLParser
from pathlib import Path
import re, shutil, socket, sqlite3, subprocess, sys, tempfile, threading, time
from urllib.parse import urlencode, urlsplit, unquote

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('baseline',HERE/'issue-649-baseline.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
check,sha,request,wait,volume,Marionette=b.check,b.sha,b.request,b.wait,b.volume,b.Marionette
DASHBOARD=b.DASHBOARD
MARKER='issue-649-current-content-after-queue-\u00e9-#-%20\n'


def chart(path, write=None):
    # Python's supported SQLite transaction API is used only on the owned fixture.
    db=sqlite3.connect(str(path) if write else path.as_uri()+'?mode=ro',uri=not bool(write),timeout=10)
    try:
        if write:
            db.execute('PRAGMA wal_autocheckpoint=0')
            row=db.execute('SELECT type_id FROM type WHERE name=?',('qa_relocation_sentinel',)).fetchone()
            type_id=row[0] if row else db.execute('INSERT INTO type(name) VALUES(?)',('qa_relocation_sentinel',)).lastrowid
            db.execute('INSERT INTO data(type_id,site_id,value,date_added) VALUES(?,NULL,?,?)',(type_id,write,int(time.time())))
            db.commit()
        integrity=[x[0] for x in db.execute('PRAGMA integrity_check')]
        rows=[list(x) for x in db.execute('SELECT data.value,data.date_added FROM data JOIN type USING(type_id) WHERE type.name=? ORDER BY data_id',('qa_relocation_sentinel',))]
        return {'integrity':integrity,'sentinel_rows':rows,'data_rows':db.execute('SELECT COUNT(*) FROM data').fetchone()[0]}
    finally:db.close()


def inventory(data):
    result=[]
    for part in ('private','data'):
        for path in sorted((data/part).rglob('*')):
            if path.is_file():
                check(len(result)<20000,'fixture file inventory exceeds bound')
                result.append({'path':str(path.relative_to(data)),'size':path.stat().st_size})
    return result


def config_data_dir(port):
    class Field(HTMLParser):
        value=None
        def handle_starttag(self,tag,attributes):
            attrs=dict(attributes)
            if tag=='input' and attrs.get('name')=='data_dir':self.value=attrs.get('value')
    code,_,body=request(port,'/Config');check(code==200,'Config unavailable for root verification')
    parser=Field();parser.feed(body.decode());check(parser.value,'Config data_dir input missing');return parser.value


def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--installer',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--expected-revision',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    check(sys.platform=='win32','native Windows required');check(sha(a.installer)==b.RELEASE_SHA,'baseline installer digest mismatch');check(re.fullmatch('[0-9a-f]{40}',a.expected_revision),'exact candidate commit required')
    actual=subprocess.check_output(['git','-C',str(a.source),'rev-parse','HEAD'],text=True).strip();check(actual==a.expected_revision,'source revision mismatch')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('owned',HERE/'issue-649-owned-job.py');owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    root=Path(tempfile.mkdtemp(prefix='epix-issue649-candidate-',dir=os.environ['RUNNER_TEMP']));roots=[root];jobs=[];handles=[];browser=None
    report={'source_revision':actual,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Actual Rust candidate and SHA-verified baseline Firefox, offline disposable identity, no external publishing. Native Windows Server is not the reporter Windows 10. Headless Firefox and supported EPIX_NO_SPLASH exercise profile/PAC/CA and normal launcher IPC; this is not visible-window or native tray interaction proof.','owned_roots':[str(root)],'checks':{},'errors':[]}
    def save():(out/'candidate-result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    def stop():
        nonlocal browser
        if browser:browser.close();browser=None
        for job in jobs:job.close()
        jobs.clear();time.sleep(2)
        restarted=report.get('restarted_process')
        if restarted:
            pid=int(restarted['ProcessId'])
            try:
                current=subprocess.check_output(['powershell','-NoProfile','-Command',"(Get-CimInstance Win32_Process -Filter 'ProcessId = "+str(pid)+"').ExecutablePath"],text=True,timeout=10).strip()
                if current and os.path.normcase(current)==os.path.normcase(restarted['ExecutablePath']):
                    # Fallback only for the previously verified disposable path,
                    # including a failure while assigning the restarted process.
                    result=subprocess.run(['taskkill','/PID',str(pid),'/T','/F'],capture_output=True,timeout=15)
                    report.setdefault('cleanup_restart_fallback',[]).append({'pid':pid,'code':result.returncode})
            except Exception as error:report.setdefault('cleanup_restart_errors',[]).append(str(error))
        for handle in handles:handle.close()
        handles.clear()
    timer=threading.Timer(840,lambda:[job.close() for job in jobs]);timer.daemon=True;timer.start()
    try:
        origin=volume(Path(root.anchor));check(origin['filesystem']=='NTFS','origin must be NTFS')
        alternate=None
        for drive in ('C:\\','D:\\'):
            if not Path(drive).exists():continue
            info=volume(Path(drive))
            if info['filesystem']=='NTFS' and info['serial']!=origin['serial']:
                alternate=Path(tempfile.mkdtemp(prefix='epix-issue649-candidate-',dir=drive));roots.append(alternate);report['destination_volume']=info;break
        check(alternate is not None,'need distinct native C/D NTFS volumes; no SUBST fallback')
        check(shutil.disk_usage(root).free>8*1024**3 and shutil.disk_usage(alternate).free>8*1024**3,'runtime disk floor')
        report.update(origin_volume=origin,distinct_volume=True,owned_roots=[str(x) for x in roots])
        candidates=[x for x in a.package.rglob('epix-browser.exe') if (x.parent/'firefox/firefox.exe').exists()];check(len(candidates)==1,'expected one packaged Firefox install tree')
        launcher=candidates[0].resolve();original=sha(launcher)
        for name in ('epix-browser.exe','epix-nmh.exe'):
            check((a.candidate/name).is_file(),'missing newly built '+name);shutil.copy2(a.candidate/name,launcher.parent/name)
        for dll in a.candidate.glob('epix_snowflake-*.dll'):shutil.copy2(dll,launcher.parent/dll.name)
        check(sha(launcher)!=original,'released launcher was not replaced by candidate')
        report['runtime']={'baseline_installer_sha256':b.RELEASE_SHA,'launcher_sha256':sha(launcher),'nmh_sha256':sha(launcher.parent/'epix-nmh.exe'),'baseline_launcher_sha256':original,'firefox_sha256':sha(launcher.parent/'firefox/firefox.exe'),'candidate_binaries':{x.name:sha(x) for x in a.candidate.iterdir() if x.is_file()}}
        env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','SYSTEMDRIVE','COMSPEC','PATHEXT','PATH','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS','OS'}}
        for name in ('home','appdata','localappdata','tmp'):(root/name).mkdir()
        env.update(HOME=str(root/'home'),USERPROFILE=str(root/'home'),APPDATA=str(root/'appdata'),LOCALAPPDATA=str(root/'localappdata'),TEMP=str(root/'tmp'),TMP=str(root/'tmp'),EPIX_TOR='disable',TOKIO_WORKER_THREADS='2',MOZ_MARIONETTE='1',MOZ_HEADLESS='1',EPIX_NO_SPLASH='1')
        report['browser_environment']={'MOZ_HEADLESS':'1','EPIX_NO_SPLASH':'1','scope':'Supported headless fixture configuration; no production rendering or browser logic changes.'}
        policy=launcher.parent/'firefox/distribution/policies.json';policy_before=sha(policy);value=json.loads(policy.read_text(encoding='utf-8-sig'));value.setdefault('policies',{}).setdefault('Certificates',{}).setdefault('Install',[]).append(str(root/'localappdata/Mozilla/Certificates/epix-ca.pem'));policy.write_text(json.dumps(value),encoding='utf8')
        report['certificate_policy']={'original_sha256':policy_before,'fixture_sha256':sha(policy),'change':'Absolute disposable CA install path only. acceptInsecureCerts=false; no trust bypass.'}
        source=root/'appdata/EpixNet';(source/'private').mkdir(parents=True);(source/'data'/DASHBOARD).mkdir(parents=True)
        (source/'private/config.json').write_text(json.dumps({'offline':True,'xid_lc_enabled':False,'chain_rpc_url':'http://127.0.0.1:9','chain_evm_rpc_url':'http://127.0.0.1:9'}))
        marker=source/'data'/DASHBOARD/'qa-move-marker.txt';marker.write_text('before queue\n',encoding='utf8')
        target=alternate/'EpixNet moved \u00e9 \u96ea # literal%20';target_name=str(target)
        conf=source/'epixnet.conf';pending=source/'.epixnet-relocation.json'
        def runtime_ready(data):
            port=int((data/'ui_port').read_text());code,_,body=request(port,'/EpixNet-Internal/Status')
            if code!=200:return None
            # The node starts serving before profile setup/browser launch and
            # shell restart registration complete. Do not mistake that early
            # readiness for a fully started desktop shell.
            config_code,_,config=request(port,'/Config')
            if config_code!=200 or b"id='restart-btn'" not in config:return None
            return port,json.loads(body)
        def describe_runtime(port,status,pid=None):
            check(status.get('connections',{}).get('total')==0,'unexpected peer connection')
            detail={'pid':pid,'port':port,'status':{k:status.get(k)for k in ('serving','tor_enabled','i2p_enabled','mesh_enabled','connections')},'direct_config_http':request(port,'/Config')[0],'direct_stats_http':request(port,'/Stats')[0],'stats_json':json.loads(request(port,'/StatsJson')[2])}
            check(detail['direct_config_http']==detail['direct_stats_http']==200,'native routes failed');check('issue649-qa' in detail['stats_json'].get('version',''),'running node lacks candidate build version');return detail
        def launch(data,label):
            profile=data/'firefox-profile';profile.mkdir(parents=True,exist_ok=True);(profile/'prefs.js').write_text('user_pref("marionette.port", 2828);\n')
            log=(root/(label+'.raw.log')).open('wb');handles.append(log);job=owned.WindowsJob();jobs.append(job)
            proc=job.launch([str(launcher),'dashboard.epix'],env=env,cwd=launcher.parent,stdout=log,stderr=subprocess.STDOUT)
            def ready():
                if proc.poll() is not None:raise RuntimeError('candidate exited '+str(proc.returncode))
                return runtime_ready(data)
            port,status=wait(ready,120);check(json.loads((data/'private/config.json').read_text(encoding='utf8')).get('offline') in (True,'true'),'offline config lost')
            return port,describe_runtime(port,status,proc.pid),proc
        def connect():
            try:return Marionette(2828)
            except (OSError,RuntimeError):return None
        def browser_check(label,data,port):
            nonlocal browser
            browser=wait(connect,60);page=browser.page('https://dashboard.epix/');report[label]['page']=page
            check(not page.get('navigation_error') and page.get('secure') and page.get('frame'),'HTTPS .epix wrapper did not load with verified TLS')
            report[label]['screenshot_error']=browser.screenshot(out/(label+'-dashboard.png'))
            payload=browser.page('https://dashboard.epix/qa-move-marker.txt');report[label]['content_page']=payload
            check(not payload.get('navigation_error') and ('after-queue' in (payload.get('text')or'') if label!='before' else 'before queue' in (payload.get('text')or'')),'local .epix content not served')
            prefs=(data/'firefox-profile/user.js').read_text(encoding='utf8');pac=json.loads(re.search(r'user_pref\("network.proxy.autoconfig_url", (.+)\);',prefs)[1]);parts=urlsplit(pac)
            report[label]['pac']={'url':pac,'query':parts.query,'fragment':parts.fragment,'decoded_path':unquote(parts.path),'exists':(data/'firefox-profile/epix.pac').exists()}
            check(not parts.query and not parts.fragment and parts.scheme=='file','PAC URL split or malformed')
            check(not pac.startswith('file:////?/'),'verbatim path became PAC URL query')
            stats_url='http://127.0.0.1:'+str(port)+'/Stats';stats_page=browser.page(stats_url);report[label]['stats_page']=stats_page
            check(not stats_page.get('navigation_error') and stats_page.get('uri')==stats_url and 'Stats' in (stats_page.get('title')or''),'browser Stats document did not load')
            browser.screenshot(out/(label+'-stats.png'));save()
        port,report['before'],initial_process=launch(source,'before');browser_check('before',source,port)
        chart_path=source/'private/chart.db';wait(lambda:chart_path.exists());report['before']['chart']=chart(chart_path,649001)
        before_conf=conf.read_bytes() if conf.exists() else None
        code,_,body=request(port,'/Config');match=re.search(r"name=['\"]csrf['\"]\s+value=['\"]([^'\"]+)",body.decode());check(match,'Config CSRF missing')
        code,headers,_=request(port,'/Config',urlencode({'csrf':match[1],'data_dir':target_name,'offline':'on','xid_lc_enabled':'false'}).encode());location=headers.get('location')or headers.get('Location')
        report['queued']={'http_status':code,'location':location,'requested_target':target_name};check(code in (302,303) and '/Config?done=' in (location or ''),'Config request did not queue successfully')
        check(pending.exists(),'pending migration plan missing');check((conf.read_bytes() if conf.exists() else None)==before_conf,'Config switched effective root while node was live')
        check(not (target/'private/users.json').exists(),'Config copied live identity before restart')
        report['queued'].update(pending_plan_sha256=sha(pending),effective_conf_unchanged=True,target_identity_absent=True)
        # These late committed writes prove snapshotting occurs after the old process exits.
        marker.write_text(MARKER,encoding='utf8');(source/'private/qa-late-state.json').write_text('{"value":"after queue"}\n')
        report['after_queue_chart']=chart(chart_path,649002);check(report['after_queue_chart']['integrity']==['ok'],'source Stats failed integrity check')
        report['before_restart_users_sha256']=sha(source/'private/users.json')
        # The supported Config restart is exercised, not replaced with taskkill.
        # Its detached relaunch helper inherits our kill-on-close Windows Job.
        restart_page=browser.page('http://127.0.0.1:'+str(port)+'/Config')
        check(not restart_page.get('navigation_error'),'Config restart page inaccessible')
        note=browser.cmd('WebDriver:ExecuteScript',{'script':'return document.body.innerText;','args':[],'newSandbox':True,'sandbox':'default'})['value']
        check(all(word in note.lower() for word in ('browser','wallet','original')),'storage setting does not explain browser-profile scope')
        button=browser.cmd('WebDriver:FindElement',{'using':'css selector','value':'#restart-btn'})['value']
        browser.cmd('WebDriver:ElementClick',{'id':button['element-6066-11e4-a52e-4f735466cecf']})
        instruction_script="return {text:document.body.innerText,metaRefresh:!!document.querySelector('meta[http-equiv=refresh i]'),configPolling:Array.from(document.scripts).some(s=>s.textContent.includes('setInterval')&&s.textContent.includes('/Config'))};"
        instruction=browser.cmd('WebDriver:ExecuteScript',{'script':instruction_script,'args':[],'newSandbox':True,'sandbox':'default'})['value']
        check(all(word in instruction['text'].lower() for word in ('close','open','tray')),'move restart page lacks guided browser reopening instructions')
        check(not instruction['metaRefresh'] and not instruction['configPolling'],'move restart page still redirects old profile automatically')
        report['guided_reopen_instruction']=instruction;browser.screenshot(out/'guided-reopen-instruction.png');save()
        initial_process.wait(timeout=30);check(initial_process.returncode==0,'normal Config shutdown failed')
        port,status=wait(lambda:runtime_ready(target),120)
        # Verify the background process is still bounded by our cleanup Job.
        # PowerShell launch behavior is measured rather than assumed.
        ps = "$ids=@(Get-NetTCPConnection -State Listen -LocalPort "+str(port)+" | Select-Object -ExpandProperty OwningProcess -Unique); @(Get-CimInstance Win32_Process | Where-Object {$_.ProcessId -in $ids} | Select-Object ProcessId,ExecutablePath,CommandLine) | ConvertTo-Json -Compress"
        processes=json.loads(subprocess.check_output(['powershell','-NoProfile','-Command',ps],text=True,timeout=15))
        if isinstance(processes,dict):processes=[processes]
        check(len(processes)==1,'expected one candidate node on target UI port')
        restarted=processes[0];check(os.path.normcase(str(Path(restarted['ExecutablePath']).resolve()))==os.path.normcase(str(launcher)),'target UI belongs to another executable')
        check('--background' in restarted['CommandLine'],'unexpected target relaunch arguments')
        active_root=config_data_dir(port);check(os.path.samefile(active_root,target),'restarted candidate uses another data environment')
        inherited=any(restarted['ProcessId'] in job.process_ids()for job in jobs)
        report['restarted_process']={**restarted,'verified_data_root':active_root,'inherited_job':inherited,'bounded_by_owned_job':False};save()
        if not inherited:
            # Only the exact disposable candidate executable can be adopted.
            jobs[0].adopt_verified_pid(restarted['ProcessId'])
        check(any(restarted['ProcessId'] in job.process_ids()for job in jobs),'restarted node is not owned')
        report['restarted_process']['bounded_by_owned_job']=True
        report['after']=describe_runtime(port,status,restarted['ProcessId'])
        retained_instruction=browser.cmd('WebDriver:ExecuteScript',{'script':instruction_script,'args':[],'newSandbox':True,'sandbox':'default'})['value']
        check(retained_instruction==instruction,'old window left its guided reopen page during relocation')
        report['normal_restart']={'trigger':'Native Config Restart button','original_exit_code':initial_process.returncode,'target_background_node_ready':True,'old_window_retained_instruction':True,'automatic_browser_migration':False}
        browser.screenshot(out/'normal-restart-old-window.png');save()
        # The relocation contract moves private/ and data/, not the old browser
        # profile. Reopen through ordinary launcher IPC to use the target profile.
        # Closing the last WebDriver window can leave a headless automation
        # process listening. Use Firefox's supported normal application quit,
        # equivalent to closing the browser application, without taskkill.
        quit_response=browser.cmd('Marionette:Quit',{})
        if isinstance(quit_response,dict) and 'value' in quit_response:quit_response=quit_response['value']
        check(quit_response.get('cause')=='shutdown' and quit_response.get('forced') is False,'old browser did not acknowledge an ordinary application quit')
        report['normal_restart']['old_browser_close']={'command':'Marionette:Quit (default eAttemptQuit)','response':quit_response};save()
        browser.s.close();browser=None
        def marionette_closed():
            try:
                with socket.create_connection(('127.0.0.1',2828),timeout=.3):return False
            except OSError:return True
        wait(marionette_closed,20)
        target_profile=target/'firefox-profile';target_profile.mkdir(parents=True,exist_ok=True);(target_profile/'prefs.js').write_text('user_pref("marionette.port", 2828);\n')
        reopen_log=(root/'reopen.raw.log').open('wb');handles.append(reopen_log);reopen_job=owned.WindowsJob();jobs.append(reopen_job)
        reopen=reopen_job.launch([str(launcher),'dashboard.epix'],env=env,cwd=launcher.parent,stdout=reopen_log,stderr=subprocess.STDOUT)
        reopen.wait(timeout=30);check(reopen.returncode==0,'normal launcher IPC reopen failed')
        report['normal_restart']['browser_reopened_through_launcher']=True
        report['normal_restart']['reopen_scope']='Followed visible instruction: close old window, then normal launcher IPC invokes the same target-profile reopen handler as the tray. No claim of automatic window migration.'
        report['stopped_source_inventory']=inventory(source);report['stopped_source_users_sha256']=sha(source/'private/users.json');report['stopped_source_chart']=chart(chart_path)
        report['stopped_source_sqlite_files']={x.name:x.stat().st_size for x in (source/'private').glob('chart.db*')};save();browser_check('after',target,port)
        report['after']['users_sha256']=sha(target/'private/users.json');check(report['after']['users_sha256']==report['stopped_source_users_sha256'],'identity bytes changed during migration')
        check((target/'data'/DASHBOARD/'qa-move-marker.txt').read_text(encoding='utf8')==MARKER,'latest content lost');check((target/'private/qa-late-state.json').read_bytes()==(source/'private/qa-late-state.json').read_bytes(),'late private state lost')
        report['after']['chart']=chart(target/'private/chart.db');check(report['after']['chart']['integrity']==['ok'],'moved Stats DB corrupt');check(report['after']['chart']['sentinel_rows']==report['stopped_source_chart']['sentinel_rows'],'Stats history lost')
        persisted=re.search(r'^data_dir\s*=\s*(.+)$',conf.read_text(encoding='utf8'),re.M);check(persisted,'committed conf missing data_dir');check(os.path.samefile(persisted[1],target),'conf points to wrong target')
        check(not pending.exists(),'completed relocation left pending marker');check(sha(source/'private/users.json')==report['stopped_source_users_sha256'],'source identity backup changed');check(marker.read_text(encoding='utf8')==MARKER,'source content backup changed')
        report['checks'].update(queue_without_live_copy=True,late_content_preserved=True,identity_preserved=True,stats_history_and_integrity=True,source_backup_retained=True,distinct_ntfs_volumes=True,special_path_characters=True,https_epix_navigation=True)
        save()
        # Exercise the supported --quit path before an ordinary second launch.
        quit_log=(root/'quit.raw.log').open('wb');handles.append(quit_log);quit_job=owned.WindowsJob();jobs.append(quit_job)
        quit_process=quit_job.launch([str(launcher),'--quit'],env=env,cwd=launcher.parent,stdout=quit_log,stderr=subprocess.STDOUT);quit_process.wait(timeout=40);check(quit_process.returncode==0,'normal --quit failed')
        report['normal_restart']['quit_exit_code']=quit_process.returncode
        wait(lambda:not any(restarted['ProcessId'] in job.process_ids()for job in jobs),30)
        report['normal_restart']['quit_node_exited_before_owned_cleanup']=True
        stop();port,report['second_restart'],_=launch(target,'second-restart');browser_check('second_restart',target,port)
        check(sha(target/'private/users.json')==report['stopped_source_users_sha256'],'second restart changed identity');check(chart(target/'private/chart.db')['sentinel_rows']==report['stopped_source_chart']['sentinel_rows'],'second restart lost Stats history')
        report['checks']['idempotent_second_restart']=True;report['completed']=True
    except Exception as e:
        report['errors'].append(type(e).__name__+': '+str(e)[:1600]);report['completed']=False
        for name in ('source','target'):
            data=locals().get(name)
            if isinstance(data,Path) and data.exists():
                try:report[name+'_failure_inventory']=inventory(data)
                except Exception as error:report[name+'_inventory_error']=str(error)
    finally:
        timer.cancel();stop()
        for path in list(root.glob('*.raw.log'))+[p for owned_root in roots for p in owned_root.rglob('epix-browser.log')]:
            text=path.read_bytes()[-512*1024:].decode('utf8',errors='replace');lines=['[redacted]' if re.search('private.?key|secret|mnemonic|master.?seed|authorization|password|token|cookie',line,re.I) else line for line in text.splitlines()];(out/(path.stem+'.log')).write_text('\n'.join(lines),encoding='utf8')
        report['cleanup']={'removed':[],'errors':[]}
        for path in reversed(roots):
            try:shutil.rmtree(path);report['cleanup']['removed'].append(str(path))
            except OSError as error:report['cleanup']['errors'].append(str(error))
        if report['cleanup']['errors'] or report.get('cleanup_restart_errors'):
            report['completed']=False;report['errors'].append('Owned runtime cleanup was incomplete; inspect cleanup diagnostics')
        report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
    print(json.dumps({'completed':report.get('completed'),'checks':report['checks'],'errors':report['errors']}));return 0 if report.get('completed')else 1

if __name__=='__main__':sys.exit(main())
