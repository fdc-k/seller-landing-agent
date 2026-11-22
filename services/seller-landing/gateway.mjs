import {createServer} from 'node:https';
import {request} from 'node:https';
import {createPrivateKey,createPublicKey,createHmac,timingSafeEqual} from 'node:crypto';
import {isIP} from 'node:net';
import {readFile} from 'node:fs/promises';
import {resolve,dirname,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createLandingCertificate} from './certificate.mjs';
import {buildOperation} from './operations.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const canonical=ip=>isIP(ip)===6?new URL(`http://[${ip}]/`).hostname:ip;
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value);
export const GATEWAY_AUTH_DOMAIN='wao-seller-landing-read-v1';
const key32=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value)&&Buffer.from(value,'base64url').length===32&&Buffer.from(value,'base64url').toString('base64url')===value;
const parse=body=>{try{return JSON.parse(body);}catch{fail('INVALID_RESPONSE');}};
const codes=new Set(['INVALID_REQUEST','BINDING_MISMATCH','INVALID_OPERATION','REQUEST_TOO_LARGE','REQUEST_TIMEOUT','UPSTREAM_NETWORK','RESPONSE_TOO_LARGE','INVALID_RESPONSE','EGRESS_MISMATCH','EGRESS_COUNTRY_MISMATCH','EGRESS_COUNTRY_UNKNOWN','SELLER_ID_MISMATCH','TOKEN_EXPIRED_OR_SCOPE_DENIED','RATE_LIMITED','UPSTREAM_STATUS','SECRET_IN_RESPONSE','REQUEST_REPLAY','BUSY']);

export function normalizeEgressPolicy(value){
 if(value===undefined)return undefined;
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['mode','country'].includes(k))||value.mode!=='country')fail('INVALID_REQUEST');
 const country=value.country==='UK'?'GB':value.country;
 if(!['US','GB','FR','DE','AU'].includes(country))fail('INVALID_REQUEST');
 return Object.freeze({mode:'country',country});
}
export function validateGatewayConfig(value){
 const egressPolicy=normalizeEgressPolicy(value?.egressPolicy);
 if(!value||!['accountId','machineId','sellerId'].every(k=>id(value[k]))||!key32(value.gatewayAuthKey)||!Number.isInteger(value.gatewayPort)||value.gatewayPort<1025||value.gatewayPort>65535||!Array.isArray(value.expectedEgressIPs)||(!egressPolicy&&!value.expectedEgressIPs.length)||value.expectedEgressIPs.length>16||value.expectedEgressIPs.some(ip=>typeof ip!=='string'||!isIP(ip)))fail('INVALID_REQUEST');
 return Object.freeze({accountId:value.accountId,machineId:value.machineId,sellerId:value.sellerId,gatewayPort:value.gatewayPort,gatewayAuthKey:value.gatewayAuthKey,...(egressPolicy?{egressPolicy}:{}),expectedEgressIPs:Object.freeze([...new Set(value.expectedEgressIPs.map(canonical))])});
}

// Node https.request ignores proxy environment variables. Hosts, paths, method,
// TLS verification, limits and redirect handling are fixed here, never in input.
export function directGet(host,path,token,signal){
 if((token&&host!=='api.whatnot.com')||!['api.ipify.org','api.whatnot.com','api.country.is'].includes(host)||!path.startsWith('/'))return Promise.reject(Object.assign(Error('INVALID_REQUEST'),{code:'INVALID_REQUEST'}));
 return new Promise((resolve,reject)=>{
  const req=request({hostname:host,port:443,path,method:'GET',agent:false,rejectUnauthorized:true,minVersion:'TLSv1.2',signal,headers:{accept:'application/json',...(token?{authorization:`Bearer ${token}`}:{})}},response=>{
   const chunks=[];let size=0;
   response.on('data',chunk=>{size+=chunk.length;if(size>4*1024*1024){response.destroy();req.destroy();reject(Object.assign(Error('RESPONSE_TOO_LARGE'),{code:'RESPONSE_TOO_LARGE'}));}else chunks.push(chunk);});
   response.on('error',()=>reject(Object.assign(Error('UPSTREAM_NETWORK'),{code:'UPSTREAM_NETWORK'})));
   response.on('end',()=>{const raw=response.headers['retry-after'],seconds=typeof raw==='string'?Number(raw):NaN;const retryAfterMs=Number.isFinite(seconds)&&seconds>=0?seconds*1000:typeof raw==='string'?Math.max(0,Date.parse(raw)-Date.now()):NaN;resolve({status:response.statusCode??0,body:Buffer.concat(chunks).toString('utf8'),...(Number.isFinite(retryAfterMs)?{retryAfterMs:Math.min(86400000,retryAfterMs)}:{})});});
  });
  req.on('error',()=>reject(Object.assign(Error(signal.aborted?'REQUEST_TIMEOUT':'UPSTREAM_NETWORK'),{code:signal.aborted?'REQUEST_TIMEOUT':'UPSTREAM_NETWORK'})));req.end();
 });
}

export function createGateway(config,{privateKey,get=directGet,now=Date.now}={}){
 const b=validateGatewayConfig(config),key=createPrivateKey(privateKey);if(key.asymmetricKeyType!=='ed25519')fail('INVALID_REQUEST');
 const certificate=createLandingCertificate(privateKey),seen=new Map();let active=0,paused,cooldown=0;
 function check(response){if(response.status===401||response.status===403){paused='TOKEN_EXPIRED_OR_SCOPE_DENIED';fail(paused);}if(response.status===429){cooldown=now()+Math.max(1000,response.retryAfterMs??60000);throw Object.assign(Error('RATE_LIMITED'),{code:'RATE_LIMITED',retryAfterMs:cooldown-now()});}if(response.status<200||response.status>=300)fail('UPSTREAM_STATUS');}
 const server=createServer({key:privateKey,cert:certificate,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',sessionTimeout:1,maxHeaderSize:8192,requestTimeout:10000,headersTimeout:10000},async(req,res)=>{
  res.setHeader('connection','close');res.setHeader('cache-control','no-store');res.setHeader('content-type','application/json');
  let acquired=false;
  try{
   if(req.method!=='POST'||!['/v1/read','/v1/egress'].includes(req.url)||req.headers['content-type']!=='application/json'||req.headers['content-encoding']||req.headers.expect||!key32(req.headers['x-wao-landing-auth']))fail('INVALID_REQUEST');
   if(active>=8)fail('BUSY');active++;acquired=true;
   const chunks=[];let size=0;
   for await(const chunk of req){size+=chunk.length;if(size>16384)fail('REQUEST_TOO_LARGE');chunks.push(chunk);}
   const bytes=Buffer.concat(chunks),mac=createHmac('sha256',Buffer.from(b.gatewayAuthKey,'base64url')).update(GATEWAY_AUTH_DOMAIN+'\n').update(bytes).digest();
   if(!timingSafeEqual(mac,Buffer.from(req.headers['x-wao-landing-auth'],'base64url')))fail('INVALID_REQUEST');
   const probe=req.url==='/v1/egress';
   let input;try{input=JSON.parse(bytes.toString('utf8'));}catch{fail('INVALID_REQUEST');}
   if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(k=>!(probe?['accountId','machineId','sellerId','requestId']:['accountId','machineId','sellerId','operation','args','token','requestId']).includes(k)))fail('INVALID_REQUEST');
   if(input.accountId!==b.accountId||input.machineId!==b.machineId||input.sellerId!==b.sellerId)fail('BINDING_MISMATCH');
   if(typeof input.requestId!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(input.requestId)||(!probe&&(typeof input.token!=='string'||input.token.length<1||input.token.length>4096||! /^[A-Za-z0-9._~+\/-]+=*$/.test(input.token))))fail('INVALID_REQUEST');
   const op=probe?undefined:buildOperation(input.operation,input.args);
   if(paused)fail(paused);if(cooldown>now())throw Object.assign(Error('RATE_LIMITED'),{code:'RATE_LIMITED',retryAfterMs:cooldown-now()});
   for(const [nonce,expires]of seen)if(expires<=now())seen.delete(nonce);
   if(seen.has(input.requestId))fail('REQUEST_REPLAY');if(seen.size>=4096)fail('BUSY');seen.set(input.requestId,now()+5*60000);
   const started=now(),requestedAt=new Date(started).toISOString(),controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
   const abort=()=>controller.abort();req.once('aborted',abort);res.once('close',abort);
   try{
    const ip=await get('api.ipify.org','/?format=json',undefined,controller.signal);let egressIp;
    if(b.egressPolicy){if(ip.status<200||ip.status>=300)fail('EGRESS_COUNTRY_UNKNOWN');try{egressIp=JSON.parse(ip.body)?.ip;}catch{fail('EGRESS_COUNTRY_UNKNOWN');}}else{check(ip);egressIp=parse(ip.body)?.ip;}
    let egressCountry;
    if(b.egressPolicy){
     if(typeof egressIp!=='string'||!isIP(egressIp))fail('EGRESS_COUNTRY_UNKNOWN');
     const geo=await get('api.country.is','/'+encodeURIComponent(egressIp),undefined,controller.signal);
     if(geo.status<200||geo.status>=300)fail('EGRESS_COUNTRY_UNKNOWN');
     let evidence;try{evidence=JSON.parse(geo.body);}catch{fail('EGRESS_COUNTRY_UNKNOWN');}
     if(!evidence||typeof evidence.ip!=='string'||!isIP(evidence.ip)||canonical(evidence.ip)!==canonical(egressIp)||typeof evidence.country!=='string'||! /^[A-Z]{2}$/.test(evidence.country))fail('EGRESS_COUNTRY_UNKNOWN');
     egressCountry=evidence.country==='UK'?'GB':evidence.country;
     const regionName=new Intl.DisplayNames(['en'],{type:'region'}).of(egressCountry);if(regionName===egressCountry||regionName==='Unknown Region')fail('EGRESS_COUNTRY_UNKNOWN');
     if(egressCountry!==b.egressPolicy.country)fail('EGRESS_COUNTRY_MISMATCH');
    }else if(typeof egressIp!=='string'||!isIP(egressIp)||!b.expectedEgressIPs.includes(canonical(egressIp))){paused='EGRESS_MISMATCH';fail(paused);}
    if(probe){res.writeHead(200);res.end(JSON.stringify({accountId:b.accountId,machineId:b.machineId,sellerId:b.sellerId,requestId:input.requestId,egressIp,...(egressCountry?{egressCountry}:{})}));return;}
    const identity=await get('api.whatnot.com','/seller-api/rest/v2/users/me',input.token,controller.signal);check(identity);
    if(parse(identity.body)?.id!==b.sellerId){paused='SELLER_ID_MISMATCH';fail(paused);}
    const response=op.path==='/users/me'?identity:await get('api.whatnot.com','/seller-api/rest/v2'+op.path,input.token,controller.signal);check(response);
    if(response.body.includes(input.token)){paused='SECRET_IN_RESPONSE';fail(paused);}
    const data=parse(response.body);const body=JSON.stringify({accountId:b.accountId,machineId:b.machineId,sellerId:b.sellerId,requestId:input.requestId,data,egressIp,...(egressCountry?{egressCountry}:{}),evidence:{requestedAt,durationMs:now()-started,status:response.status,body:response.body}});
    // Also scan wrapper-generated JSON: no echo through any reflected field.
    if(body.includes(input.token)){paused='SECRET_IN_RESPONSE';fail(paused);}res.writeHead(200);res.end(body);
   }finally{clearTimeout(timer);req.off('aborted',abort);res.off('close',abort);input.token='';}
  }catch(error){const code=codes.has(error?.code)?error.code:'UPSTREAM_NETWORK';const body={error:{code,...(code==='RATE_LIMITED'&&Number.isFinite(error.retryAfterMs)?{retryAfterMs:Math.max(0,Math.min(86400000,error.retryAfterMs))}:{})}};if(!res.headersSent)res.writeHead(code==='REQUEST_TOO_LARGE'?413:code==='RATE_LIMITED'?429:code==='BUSY'?503:400);res.end(JSON.stringify(body));}
  finally{if(acquired)active--;}
 });
 // Never expose exception text, TLS errors, request bodies, keys or credentials.
 server.on('tlsClientError',()=>{});server.on('clientError',(_error,socket)=>socket.destroy());
 server.keepAliveTimeout=1;server.maxRequestsPerSocket=1;server.setTimeout(25000,socket=>socket.destroy());
 return {server,certificate,publicKey:createPublicKey(key).export({type:'spki',format:'pem'}).toString(),listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(b.gatewayPort,'127.0.0.1',()=>{server.off('error',reject);resolve();});})};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 try{if(process.argv.length!==3)fail('INVALID_REQUEST');const file=resolve(process.argv[2]),config=JSON.parse(await readFile(file,'utf8'));const privateKey=await readFile(join(dirname(file),'metadata.pem'),'utf8');const gateway=createGateway(config,{privateKey});await gateway.listen();for(const event of ['SIGTERM','SIGINT'])process.once(event,()=>gateway.server.close(()=>process.exit(0)));}
 catch{console.error('Landing gateway failed.');process.exitCode=1;}
}
