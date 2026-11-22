import {readFile} from 'node:fs/promises';
import {realpathSync} from 'node:fs';
import {request} from 'node:https';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createMachineInfoReader} from './lib/machine-info.mjs';
import {makeEnvelope} from './lib/envelope.mjs';

export function validateConfig(config){
  const url=new URL(config.centralUrl);
  if(url.protocol!=='https:'||url.username||url.password||url.hash||url.search||url.pathname!=='/api/seller-center/machine-info')throw new Error('Invalid central endpoint');
  for(const field of ['accountId','machineId'])if(typeof config[field]!=='string'||!config[field]||config[field].length>200)throw new Error('Invalid binding');
  if(typeof config.privateKeyFile!=='string'||!config.privateKeyFile)throw new Error('Missing private key file');
  return config;
}
export function postEnvelope(url,envelope){
  const body=Buffer.from(JSON.stringify(envelope));
  return new Promise((resolve,reject)=>{
    const req=request(url,{method:'POST',agent:false,rejectUnauthorized:true,timeout:10000,signal:AbortSignal.timeout(10000),headers:{'content-type':'application/json','content-length':body.length}},res=>{res.on('error',reject);res.resume();res.on('end',()=>res.statusCode>=200&&res.statusCode<300?resolve():reject(new Error('Metadata report rejected')));});
    req.on('timeout',()=>req.destroy(new Error('Metadata report timed out')));req.on('error',reject);req.end(body);
  });
}
async function main(){
  const configPath=resolve(process.argv[2]||'config.json');
  const config=validateConfig(JSON.parse(await readFile(configPath,'utf8')));
  const privateKey=await readFile(resolve(dirname(configPath),config.privateKeyFile),'utf8');
  const read=createMachineInfoReader({cacheMs:0});
  let stopped=false;let wake;
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{stopped=true;wake?.();});
  while(!stopped){
    for(let attempt=0;attempt<3&&!stopped;attempt++){
      try{await postEnvelope(config.centralUrl,makeEnvelope(await read(),config,privateKey));break;}
      catch{console.error('Machine metadata report failed');if(attempt<2)await new Promise(r=>{const timer=setTimeout(r,2000*(attempt+1));wake=()=>{clearTimeout(timer);r();};});}
    }
    if(!stopped)await new Promise(r=>{const timer=setTimeout(r,60000);wake=()=>{clearTimeout(timer);r();};});
  }
}
// macOS /tmp and user-selected installation paths may be symbolic links.
// Node resolves the module URL to the real file, so resolve argv the same way.
function isMain(){try{return !!process.argv[1]&&realpathSync(process.argv[1])===fileURLToPath(import.meta.url);}catch{return false;}}
if(isMain())main().catch(()=>{console.error('Machine metadata reporter failed to start');process.exitCode=1;});
