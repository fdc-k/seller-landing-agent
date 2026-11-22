import {createPrivateKey,randomBytes,sign} from 'node:crypto';
export function makeEnvelope(machine,config,privateKey){
  const key=createPrivateKey(privateKey);
  if(key.asymmetricKeyType!=='ed25519')throw new Error('Ed25519 key required');
  const e={version:1,accountId:config.accountId,machineId:config.machineId,observedAt:machine.observedAt,platform:machine.platform,timeZone:machine.timeZone,nonce:randomBytes(24).toString('base64url')};
  return {...e,signature:sign(null,Buffer.from(JSON.stringify([e.version,e.accountId,e.machineId,e.observedAt,e.platform,e.timeZone,e.nonce])),key).toString('base64url')};
}
