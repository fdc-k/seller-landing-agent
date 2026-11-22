import {execFile} from 'node:child_process';

function validZone(value){
  if(typeof value!=='string'||value.length>100||!/^[A-Za-z][A-Za-z0-9_+-]*(?:\/[A-Za-z0-9_+.-]+)*$/.test(value))return false;
  try{new Intl.DateTimeFormat('en',{timeZone:value});return true;}catch{return false;}
}
/** Read the OS default in a fresh Node process, without the service's TZ override.
 * The child returns only a timezone, never usernames, hostnames or paths. */
export function createMachineInfoReader({run=execFile,now=()=>Date.now(),env=process.env,platform=process.platform,executable=process.execPath,cacheMs=60000}={}){
  let cached,until=0,pending;
  return async()=>{
    if(cached&&now()<until)return {...cached};
    if(pending)return pending;
    pending=(async()=>{
      const cleanEnv=Object.fromEntries(Object.entries(env).filter(([key])=>!['TZ','NODE_OPTIONS','NODE_PATH'].includes(key.toUpperCase())));
      const zone=await new Promise(resolve=>{
        try{run(executable,['--input-type=commonjs','-e','process.stdout.write(Intl.DateTimeFormat().resolvedOptions().timeZone || "")'],{env:cleanEnv,timeout:5000,maxBuffer:1024,windowsHide:true},(error,stdout)=>resolve(error?null:String(stdout).trim()));}catch{resolve(null);}
      });
      cached={timeZone:validZone(zone)?zone:null,observedAt:new Date(now()).toISOString(),platform};
      until=now()+Math.min(60000,Math.max(0,cacheMs));return {...cached};
    })();
    try{return await pending;}finally{pending=undefined;}
  };
}
