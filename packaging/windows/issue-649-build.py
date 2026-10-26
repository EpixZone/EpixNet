#!/usr/bin/env python3
"""Guard the native candidate build and retain only executables/provenance."""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,sys,time
from pathlib import Path

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--revision',required=True);p.add_argument('--acl-test-only',action='store_true');a=p.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(exist_ok=True,parents=True)
 actual=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip();assert actual==a.revision
 spec=importlib.util.spec_from_file_location('owned',Path(__file__).with_name('issue-649-owned-job.py'));owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
 target=Path(os.environ['RUNNER_TEMP'])/'issue-649-candidate-target';cargo_home=Path(os.environ['RUNNER_TEMP'])/'issue-649-candidate-cargo';target.mkdir(exist_ok=True);cargo_home.mkdir(exist_ok=True)
 env=os.environ.copy();env.update(CARGO_TARGET_DIR=str(target),CARGO_HOME=str(cargo_home),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_LTO='false',CARGO_PROFILE_RELEASE_OPT_LEVEL='1',CARGO_PROFILE_RELEASE_CODEGEN_UNITS='256',EPIX_VERSION='0.5.23-issue649-qa')
 acl_test='data_relocation::windows_permissions::tests::shared_parent_cannot_grant_other_users_access_to_staged_or_promoted_private_files'
 command=['cargo','test','--locked','--release','--target','x86_64-pc-windows-msvc','-p','epix-ui','--lib',acl_test,'--','--exact','--nocapture'] if a.acl_test_only else ['cargo','build','--locked','--release','--target','x86_64-pc-windows-msvc','-p','epix-browser','-p','epix-nmh']
 label='candidate-windows-acl' if a.acl_test_only else 'candidate-build';deadline_seconds=720 if a.acl_test_only else 3900
 report={'source_revision':actual,'command':command,'environment':{k:v for k,v in env.items()if k.startswith(('CARGO_','EPIX_VERSION'))},'started_epoch':time.time(),'status':'building','target_cap_bytes':20*1024**3,'target_volume_free_floor_bytes':30*1024**3,'system_volume_free_floor_bytes':10*1024**3,'build_timeout_seconds':deadline_seconds}
 def save():(out/(label+'.json')).write_text(json.dumps(report,indent=2)+'\n')
 def size(path):return sum(x.stat().st_size for x in path.rglob('*')if x.is_file())
 save();job=owned.WindowsJob();proc=None
 try:
  with (out/(label+'.log')).open('wb') as log:
   proc=job.launch(command,cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT);report['pid']=proc.pid;save();deadline=time.monotonic()+deadline_seconds
   while proc.poll()is None:
    free=shutil.disk_usage(target).free;system_free=shutil.disk_usage(Path(os.environ['SystemDrive']+'\\')).free;target_size=size(target)
    report.update(updated_epoch=time.time(),free_bytes=free,system_free_bytes=system_free,target_bytes=target_size);save()
    if free<report['target_volume_free_floor_bytes'] or system_free<report['system_volume_free_floor_bytes']:raise RuntimeError('candidate disk free floor reached')
    if target_size>report['target_cap_bytes']:raise RuntimeError('candidate target size cap reached')
    if time.monotonic()>deadline:raise RuntimeError('candidate build deadline reached')
    time.sleep(10)
   if proc.returncode:raise RuntimeError('cargo build exited '+str(proc.returncode))
  report['binaries']={}
  if a.acl_test_only:
   output=(out/(label+'.log')).read_text(errors='replace')
   if acl_test not in output or '1 passed; 0 failed' not in output:raise RuntimeError('exact Windows ACL test did not execute and pass')
   report['exact_test_passed']=acl_test
  else:
   dest=out/'candidate-binaries';dest.mkdir(exist_ok=True);bindir=target/'x86_64-pc-windows-msvc/release';files=[bindir/'epix-browser.exe',bindir/'epix-nmh.exe',*bindir.glob('epix_snowflake-*.dll')]
   for src in files:
    shutil.copy2(src,dest/src.name);report['binaries'][src.name]={'sha256':hashlib.file_digest(src.open('rb'),'sha256').hexdigest(),'bytes':src.stat().st_size}
  subprocess.run(['git','diff','--exit-code'],cwd=source,check=True,capture_output=True)
  report['tracked_source_unchanged']=True
  report['status']='passed'
 except BaseException as e:report.update(status='failed',error=repr(e));raise
 finally:
  job.close();report['finished_epoch']=time.time();save()
 print(json.dumps({'status':report['status'],'binaries':report['binaries']}))

if __name__=='__main__':main()
