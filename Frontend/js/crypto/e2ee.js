import {seal,open,hex,unhex,randomHex,sharedSecret,importMessageKey} from './messaging.js';
import {validatePacket,metadata} from '../schema.js';
const s=crypto.subtle,enc=new TextEncoder();
const binding=(envelope,recipients,userId)=>enc.encode(JSON.stringify(['e2ee-v1',metadata(envelope),envelope.ciphertext,envelope.mac||null,recipients,userId]));
async function wrappingKey(privateKey,publicJwk,keyId){
 const secret=await sharedSecret(privateKey,publicJwk);
 return s.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(keyId),info:enc.encode('secure-chat-e2ee-wrap-v1')},secret,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function encryptE2EE({text,image=null,target,from,algorithm,privateKey,accounts,id=crypto.randomUUID()}){
 if(!['AES-GCM','DES-CBC'].includes(algorithm))throw Error('Thuật toán không hợp lệ.');
 if(typeof text!=='string'||enc.encode(text).length>16000||(!text.trim()&&!image))throw Error('Tin nhắn trống hoặc quá dài.');
 const raw=crypto.getRandomValues(new Uint8Array(algorithm==='AES-GCM'?32:40));
 const keys=algorithm==='AES-GCM'?{aes:await s.importKey('raw',raw,'AES-GCM',false,['encrypt'])}:{des:hex(raw.slice(0,8)),mac:await s.importKey('raw',raw.slice(8),{name:'HMAC',hash:'SHA-256'},false,['sign'])};
 const {envelope}=await seal(JSON.stringify({text,image}),keys,{from,to:target.startsWith('group:')?target.slice(6):target,algorithm,keyId:randomHex(16),id},1600000);
 const recipients=accounts.map(a=>a.id).sort(),wrappedKeys={};
 for(const account of accounts){const key=await wrappingKey(privateKey,account.publicJwk,envelope.keyId),iv=randomHex(12);wrappedKeys[account.id]={iv,ciphertext:hex(await s.encrypt({name:'AES-GCM',iv:unhex(iv),additionalData:binding(envelope,recipients,account.id)},key,raw))};}
 raw.fill(0);
 return {target,packet:validatePacket({v:1,envelope,recipients,wrappedKeys})};
}
export async function decryptE2EE(packet,{userId,privateKey,senderPublicJwk}){
 validatePacket(packet);const {envelope,recipients,wrappedKeys}=packet,w=wrappedKeys[userId];
 if(!w)throw Error('Bạn không có khóa cho tin nhắn này.');
 const key=await wrappingKey(privateKey,senderPublicJwk,envelope.keyId);
 const raw=await s.decrypt({name:'AES-GCM',iv:unhex(w.iv),additionalData:binding(envelope,recipients,userId)},key,unhex(w.ciphertext));
 const keys=await importMessageKey(envelope.algorithm,hex(raw));new Uint8Array(raw).fill(0);
 const result=JSON.parse((await open(envelope,keys)).text);
 if(!result||typeof result.text!=='string'||enc.encode(result.text).length>16000||(!result.text.trim()&&!result.image))throw Error('Nội dung không hợp lệ.');
 if(result.image!=null&&(typeof result.image!=='string'||result.image.length>1400000||!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(result.image)))throw Error('Ảnh không hợp lệ.');
 return {text:result.text,image:result.image||null};
}
