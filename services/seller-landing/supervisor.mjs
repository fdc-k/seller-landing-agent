import {readFile,open,unlink} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {enrollment,sshArgs,supervise} from './runtime.mjs';
const dir=dirname(resolve(process.argv[2]));
let lock;
try{lock=await open(join(dir,'supervisor.lock'),'wx',0o600);await lock.writeFile(String(process.pid));}catch{try{const pid=Number(await readFile(join(dir,'supervisor.lock'),'utf8'));process.kill(pid,0);process.exit(0);}catch{await unlink(join(dir,'supervisor.lock')).catch(()=>{});lock=await open(join(dir,'supervisor.lock'),'wx',0o600);await lock.writeFile(String(process.pid));}}
try{const c=JSON.parse(await readFile(process.argv[2],'utf8'));enrollment(c,c.origin);const stop=supervise([[c.nodePath,[join(dir,'gateway.mjs'),join(dir,'gateway.json')]],[c.singBoxPath,['run','-c',join(dir,'sing-box.json')]],[c.sshPath,sshArgs(c,dir)],[c.nodePath,[join(dir,'reporter','reporter.mjs'),join(dir,'reporter.json')]]]);let stopped=false;for(const signal of ['SIGTERM','SIGINT'])process.on(signal,async()=>{if(stopped)return;stopped=true;stop();await lock.close();await unlink(join(dir,'supervisor.lock')).catch(()=>{});});}catch{await lock.close();await unlink(join(dir,'supervisor.lock')).catch(()=>{});console.error('Landing supervisor failed to start');process.exitCode=1;}
