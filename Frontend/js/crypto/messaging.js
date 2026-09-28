import CryptoJS from './crypto-js-adapter.js';
import {validateEnvelope,metadata} from '../schema.js';
const c=globalThis.crypto,s=c.subtle,enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
export const hex=bytes=>Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
export const unhex=str=>Uint8Array.from(str.match(/../g)||[],x=>parseInt(x,16));
export const randomHex=n=>hex(c.getRandomValues(new Uint8Array(n)));
const b64=bytes=>{const a=new Uint8Array(bytes);let out='';for(let i=0;i<a.length;i+=8192)out+=String.fromCharCode(...a.subarray(i,i+8192));return btoa(out);};
const unb64=str=>Uint8Array.from(atob(str),x=>x.charCodeAt(0));
const iterations=310000;
async function passwordBits(password,salt,label){
 const k=await s.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
 return s.deriveBits({name:'PBKDF2',salt:enc.encode(label+':'+salt),iterations,hash:'SHA-256'},k,256);
}
export async function authProof(password,salt){return hex(await passwordBits(password,salt,'secure-chat-auth-v1'));}
async function vaultKey(password,salt){return s.importKey('raw',await passwordBits(password,salt,'secure-chat-vault-v1'),'AES-GCM',false,['encrypt','decrypt']);}
export async function makeIdentity(username,password){
 const pair=await s.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
 const privateJwk=await s.exportKey('jwk',pair.privateKey),publicJwk=await s.exportKey('jwk',pair.publicKey);
 const salt=randomHex(16),iv=randomHex(12),key=await vaultKey(password,salt);
 const ciphertext=await s.encrypt({name:'AES-GCM',iv:unhex(iv),additionalData:enc.encode(username)},key,enc.encode(JSON.stringify(privateJwk)));
 const authSalt=randomHex(16),proof=await authProof(password,authSalt);
 return {publicJwk,vault:{v:1,salt,iv,ciphertext:b64(ciphertext)},authSalt,proof};
}
export async function unlockIdentity(username,password,vault,publicJwk){
 try{
 const key=await vaultKey(password,vault.salt);
 const raw=await s.decrypt({name:'AES-GCM',iv:unhex(vault.iv),additionalData:enc.encode(username)},key,unb64(vault.ciphertext));
 const jwk=JSON.parse(dec.decode(raw));
 if(jwk.x!==publicJwk.x||jwk.y!==publicJwk.y)throw Error('Public key mismatch');
 return await s.importKey('jwk',jwk,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 }catch{throw Error('Không mở được kho khóa: sai mật khẩu hoặc dữ liệu khóa bị thay đổi.');}
}
export async function fingerprint(jwk){return hex(await s.digest('SHA-256',enc.encode(JSON.stringify(['P-256',jwk.x,jwk.y]))));}
export async function sharedSecret(privateKey,publicJwk){
 const key=await s.importKey('jwk',publicJwk,{name:'ECDH',namedCurve:'P-256'},false,[]);
 const bits=await s.deriveBits({name:'ECDH',public:key},privateKey,256);
 return s.importKey('raw',bits,'HKDF',false,['deriveKey']);
}
// Encryption timing includes cipher, authentication and envelope encoding, but not ECDH/HKDF.
export async function seal(text,keys,{from,to,algorithm,keyId,id=c.randomUUID(),ts=Date.now()},maxBytes=16000){
 if(typeof text!=='string'||!text.trim()||enc.encode(text).length>maxBytes)throw Error('Tin nhắn cần từ 1 đến 16.000 byte UTF-8.');
 const e={v:1,id,from,to,algorithm,keyId,ts,iv:randomHex(algorithm==='AES-GCM'?12:8)};
 const t=performance.now();
 if(algorithm==='AES-GCM')e.ciphertext=b64(await s.encrypt({name:'AES-GCM',iv:unhex(e.iv),additionalData:enc.encode(metadata(e))},keys.aes,enc.encode(text)));
 else{
 const encrypted=CryptoJS.DES.encrypt(text,CryptoJS.enc.Hex.parse(keys.des),{iv:CryptoJS.enc.Hex.parse(e.iv),mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.Pkcs7});
 e.ciphertext=encrypted.ciphertext.toString(CryptoJS.enc.Base64);
 e.mac=hex(await s.sign('HMAC',keys.mac,enc.encode(metadata(e)+':'+e.ciphertext)));
 }
 const envelopeBytes=enc.encode(JSON.stringify(e)).length;
 return {envelope:e,encryptMs:performance.now()-t,plainBytes:enc.encode(text).length,cipherBytes:unb64(e.ciphertext).length,envelopeBytes};
}
export async function open(e,keys){
 const t=performance.now();
 try{
 validateEnvelope(e);let text;
 if(e.algorithm==='AES-GCM')text=dec.decode(await s.decrypt({name:'AES-GCM',iv:unhex(e.iv),additionalData:enc.encode(metadata(e))},keys.aes,unb64(e.ciphertext)));
 else{
 if(!await s.verify('HMAC',keys.mac,unhex(e.mac),enc.encode(metadata(e)+':'+e.ciphertext)))throw Error('MAC');
 const params=CryptoJS.lib.CipherParams.create({ciphertext:CryptoJS.enc.Base64.parse(e.ciphertext)});
 text=CryptoJS.DES.decrypt(params,CryptoJS.enc.Hex.parse(keys.des),{iv:CryptoJS.enc.Hex.parse(e.iv),mode:CryptoJS.mode.CBC,padding:CryptoJS.pad.Pkcs7}).toString(CryptoJS.enc.Utf8);
 if(!text)throw Error('Empty');
 }
 return {text,decryptMs:performance.now()-t};
 }catch{throw Error('Không giải mã: sai khóa hoặc bản mã / thông tin tin nhắn đã bị sửa.');}
}

// Import a message key locally after unwrapping it on the endpoint.
export async function importMessageKey(algorithm,rawHex){
 const bytes=algorithm==='AES-GCM'?32:40;
 if(typeof rawHex!=='string'||!new RegExp(`^[0-9a-f]{${bytes*2}}$`).test(rawHex))throw Error('Khóa tin nhắn không hợp lệ.');
 const raw=unhex(rawHex);
 if(algorithm==='AES-GCM')return {aes:await s.importKey('raw',raw,'AES-GCM',false,['decrypt'])};
 return {des:hex(raw.slice(0,8)),mac:await s.importKey('raw',raw.slice(8),{name:'HMAC',hash:'SHA-256'},false,['verify'])};
}

