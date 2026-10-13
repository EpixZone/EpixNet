#!/usr/bin/env python3
"""Run real Pulley/JNI regression tests, optionally typecheck Android adapters."""
import argparse,os,pathlib,subprocess,sys,tempfile
root=pathlib.Path(__file__).resolve().parents[3]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--android-jar',type=pathlib.Path)
parser.add_argument('--offline',action='store_true')
args=parser.parse_args()
locked=['--locked'] + (['--offline'] if args.offline else [])
env=os.environ.copy()
env.setdefault('CARGO_TARGET_DIR',str(root/'target/evx-android-runtime'))
def run(*command):subprocess.run(command,cwd=root,env=env,check=True)
run('cargo','test','-p','evx-android',*locked)
run('cargo','build','-p','evx-android',*locked)
with tempfile.TemporaryDirectory(prefix='evx-jni-') as temporary:
 directory=pathlib.Path(temporary);fixtures=directory/'fixtures';classes=directory/'classes'
 run('cargo','run','-p','evx-android','--example','fixtures',*locked,'--',str(fixtures))
 source=root/'packaging/android/evx-runtime'
 run('javac','--release','11','-Xlint:all','-Werror','-d',str(classes),str(source/'src/zone/epix/evx/NativeBridge.java'),str(source/'tests/JniTest.java'))
 suffix='.dylib' if sys.platform=='darwin' else '.so'
 library=pathlib.Path(env['CARGO_TARGET_DIR'])/'debug'/('libevx_android'+suffix)
 for case in ['score','call','loop','throws','oversized']:
  run('java','-Xmx128m','-cp',str(classes),'zone.epix.evx.JniTest',str(library),str(fixtures),case)
 if args.android_jar:
  run('javac','--release','11','-Xlint:all','-Werror','-classpath',str(args.android_jar.resolve()),'-d',str(directory/'android'),*[str(p) for p in sorted((source/'src').rglob('*.java'))])
  print('PASS Android API typecheck; native Android execution not run')
