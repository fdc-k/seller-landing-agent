import {createHash} from 'node:crypto';
import {mkdir,readFile,writeFile,rename,unlink} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

// Exact versions and publisher SHA256 digests. Build time downloads only; landing
// machines fetch these verified, content-addressed files from Observer HTTPS.
const nodeVersion='22.23.3',singVersion='1.14.4';
const nodeAsset=(name,sha256)=>({url:`https://nodejs.org/dist/v${nodeVersion}/node-v${nodeVersion}-${name}`,sha256});
const singAsset=(name,sha256)=>({url:`https://github.com/SagerNet/sing-box/releases/download/v${singVersion}/sing-box-${singVersion}-${name}`,sha256});
const sshAsset=(name,sha256)=>({url:`https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/${name}.zip`,sha256});
export const PINNED_LANDING_BINARIES={
  'win32-x64':{
    node:nodeAsset('win-x64.zip','2b0ff57b049cda1bbcea2240eec20467018713c1efe1f7360c2681859b90ed71'),
    singBox:singAsset('windows-amd64.zip','99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'),
    ssh:sshAsset('OpenSSH-Win64','b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957'),
  },
  'win32-arm64':{
    node:nodeAsset('win-arm64.zip','33dad22e4cef5ee8f9fbb1b0d037fdacd0e56d12a4580f0d63f68b894deab535'),
    singBox:singAsset('windows-arm64.zip','8cd0a4d0cd8cd480be5731ac31f17038969a42d12add9feb6e031fd43d85bbae'),
    ssh:sshAsset('OpenSSH-ARM64','d2b1928225479fec9e0c938f527fdb5ed676446cca1bbcc5af84aca1f272842e'),
  },
  'darwin-x64':{
    node:nodeAsset('darwin-x64.tar.gz','8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8'),
    singBox:singAsset('darwin-amd64.tar.gz','eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25'),
  },
  'darwin-arm64':{
    node:nodeAsset('darwin-arm64.tar.gz','23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53'),
    singBox:singAsset('darwin-arm64.tar.gz','0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838'),
  },
};
export const LANDING_BUNDLE_FILES=[
  'seller-landing/install.mjs','seller-landing/runtime.mjs','seller-landing/supervisor.mjs',
  'seller-landing/gateway.mjs','seller-landing/certificate.mjs','seller-landing/operations.mjs',
  'seller-machine-info/reporter.mjs','seller-machine-info/lib/envelope.mjs','seller-machine-info/lib/machine-info.mjs',
];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function assetOrigin(value){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('Use the public Observer HTTPS origin');return u.origin;}

/** Public binaries only. Never accepts a Seller credential or a private key. */
export async function stageLandingAssets({directory,centralOrigin,platforms=Object.keys(PINNED_LANDING_BINARIES),fetchImpl=fetch,sourceDirectory=resolve(dirname(fileURLToPath(import.meta.url)),'../services')}){
  const origin=assetOrigin(centralOrigin);await mkdir(directory,{recursive:true,mode:0o700});
  const publish=async(bytes,suffix)=>{const hash=sha(bytes),name=hash+suffix,target=join(directory,name);try{const old=await readFile(target);if(sha(old)!==hash)throw Error('Corrupt staged asset');}catch(e){if(e.code!=='ENOENT')throw e;await writeFile(target,bytes,{flag:'wx',mode:0o600});}return {url:`${origin}/api/seller-center/landing/assets/${name}`,sha256:hash};};
  const bundle={version:1,files:await Promise.all(LANDING_BUNDLE_FILES.map(async path=>({path,content:(await readFile(join(sourceDirectory,path))).toString('base64')})))};
  const result={version:1,bundle:await publish(Buffer.from(JSON.stringify(bundle)),'.json'),binaries:{}};
  for(const platform of platforms){
    if(!Object.hasOwn(PINNED_LANDING_BINARIES,platform))throw Error('Unsupported landing platform');
    result.binaries[platform]={};
    for(const [kind,pin] of Object.entries(PINNED_LANDING_BINARIES[platform])){
      const suffix=pin.url.endsWith('.zip')?'.zip':'.tar.gz',name=pin.sha256+suffix,target=join(directory,name);
      let bytes;try{bytes=await readFile(target);}catch(e){if(e.code!=='ENOENT')throw e;const response=await fetchImpl(pin.url,{redirect:'follow',signal:AbortSignal.timeout(180_000)});if(!response.ok||new URL(response.url||pin.url).protocol!=='https:')throw Error('Publisher asset download failed');bytes=Buffer.from(await response.arrayBuffer());}
      if(sha(bytes)!==pin.sha256)throw Error('Publisher asset SHA256 mismatch');
      result.binaries[platform][kind]=await publish(bytes,suffix);
    }
  }
  const temp=join(directory,'manifest.pending.json');await writeFile(temp,JSON.stringify(result,null,2),{mode:0o600});await rename(temp,join(directory,'manifest.json'));return result;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{if(process.argv.length<4)throw Error();await stageLandingAssets({directory:resolve(process.argv[2]),centralOrigin:process.argv[3],...(process.argv[4]?{platforms:process.argv[4].split(',')}:{})});console.log('Landing assets staged and publisher hashes verified.');}
  catch{console.error('Asset preparation failed. Use: node scripts/seller-landing-assets.mjs PRIVATE_ASSET_DIRECTORY https://observer.example [win32-x64,darwin-arm64]');process.exitCode=1;}
}
