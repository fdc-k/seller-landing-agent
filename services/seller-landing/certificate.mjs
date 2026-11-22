import {createPrivateKey,createPublicKey,randomBytes,sign,X509Certificate} from 'node:crypto';

const der=(tag,...parts)=>{const body=Buffer.concat(parts);let length=body.length;const octets=[];do{octets.unshift(length&255);length=Math.floor(length/256);}while(length);return Buffer.concat([Buffer.from([tag,...(body.length<128?[body.length]:[128+octets.length,...octets])]),body]);};
const seq=(...v)=>der(0x30,...v),oid=(...bytes)=>der(6,Buffer.from(bytes));
const ed25519=seq(oid(0x2b,0x65,0x70));
const name=seq(der(0x31,seq(oid(0x55,4,3),der(12,Buffer.from('wao-seller-landing.invalid')))));
const time=date=>der(0x18,Buffer.from(date.toISOString().replace(/[-:T]/g,'').replace(/\.\d{3}Z$/,'Z')));

// A deliberately small, self-signed Ed25519 leaf. Trust is the enrollment SPKI,
// never this self-signature or a public CA. No external process or dependency.
export function createLandingCertificate(privateKey,{now=new Date()}={}){
 const key=createPrivateKey(privateKey);if(key.asymmetricKeyType!=='ed25519')throw Error('Invalid machine key');
 const publicKey=createPublicKey(key),serial=randomBytes(16);serial[0]&=0x7f;serial[0]|=1;
 const extension=(id,value,critical=false)=>seq(oid(0x55,0x1d,id),...(critical?[der(1,Buffer.from([255]))]:[]),der(4,value));
 const extensions=der(0xa3,seq(
  extension(19,seq(),true),
  extension(15,der(3,Buffer.from([7,128])),true),
  extension(37,seq(oid(0x2b,6,1,5,5,7,3,1))),
  extension(17,seq(der(0x82,Buffer.from('wao-seller-landing.invalid')))),
 ));
 const tbs=seq(der(0xa0,der(2,Buffer.from([2]))),der(2,serial),ed25519,name,
  seq(time(new Date(now.getTime()-300000)),time(new Date(now.getTime()+365*86400000))),name,
  publicKey.export({type:'spki',format:'der'}),extensions);
 const bytes=seq(tbs,ed25519,der(3,Buffer.from([0]),sign(null,tbs,key)));
 const pem='-----BEGIN CERTIFICATE-----\n'+bytes.toString('base64').match(/.{1,64}/g).join('\n')+'\n-----END CERTIFICATE-----\n';
 const certificate=new X509Certificate(pem);if(!certificate.verify(publicKey)||certificate.checkHost('wao-seller-landing.invalid')!=='wao-seller-landing.invalid')throw Error('Certificate generation failed');
 return pem;
}
