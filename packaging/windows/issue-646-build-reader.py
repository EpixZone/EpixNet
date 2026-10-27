#!/usr/bin/env python3
"""Compile exact production launch/read modules without building EpixNet."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,tomllib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();repo=Path(__file__).resolve().parents[2];out=a.output.resolve();out.mkdir(exist_ok=True);root=Path(os.environ['RUNNER_TEMP'])/'epix646-metadata-reader';root.mkdir(exist_ok=True);(root/'src').mkdir(exist_ok=True)
locked=tomllib.loads((repo/'Cargo.lock').read_text())['package'];versions={}
for name in ['serde','serde_json','sha2','url','tempfile']:
 items=[x['version'] for x in locked if x['name']==name and (name!='sha2' or x['version'].startswith('0.11.'))];assert len(items)==1,(name,items);versions[name]=items[0]
(root/'Cargo.toml').write_text('[package]\nname="epix-addon-metadata-qa"\nversion="0.0.0"\nedition="2024"\n[dependencies]\n'+''.join(n+'="='+v+'"\n' for n,v in versions.items() if n!='tempfile')+'[dev-dependencies]\ntempfile="='+versions['tempfile']+'"\n')
modules={name:repo/'crates/epix-browser/src'/name for name in ['addons.rs','addons_metadata.rs']}
(root/'src/main.rs').write_text('\n'.join('#[path='+json.dumps(str(path))+']\nmod '+name.removesuffix('.rs')+';' for name,path in modules.items())+'\nfn main(){let a:Vec<String>=std::env::args().collect();assert_eq!(a.len(),4);let firefox=std::fs::canonicalize(&a[1]).unwrap();let profile=std::fs::canonicalize(&a[2]).unwrap();println!("canonical profile: {}",profile.display());match addons::preflight(&firefox,&profile,&a[3]){Ok(())=>println!("actual production preflight passed"),Err(e)=>{eprintln!("{e}");std::process::exit(1)}}}\n')
env=os.environ.copy();env.update(CARGO_TARGET_DIR=str(root/'target'),CARGO_HOME=str(root/'cargo'),CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',RUSTFLAGS='-D warnings')
with (out/'metadata-reader-build.log').open('wb') as log:subprocess.run(['cargo','build','--manifest-path',str(root/'Cargo.toml')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
with (out/'metadata-reader-tests.log').open('wb') as log:subprocess.run(['cargo','test','--locked','--manifest-path',str(root/'Cargo.toml'),'--','--nocapture'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
exe=root/'target/debug/epix-addon-metadata-qa.exe';assert exe.exists();(out/'metadata-reader.exe').write_bytes(exe.read_bytes());(out/'metadata-reader-Cargo.lock').write_bytes((root/'Cargo.lock').read_bytes());(out/'metadata-reader-provenance.json').write_text(json.dumps({'modules':{str(path.relative_to(repo)):hashlib.sha256(path.read_bytes()).hexdigest() for path in modules.values()},'dependencies':versions,'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'scope':'Exact production modules only; not full EpixNet executable'},indent=2)+'\n')
