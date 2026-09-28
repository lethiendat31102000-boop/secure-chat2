export const hexOK=(s,bytes)=>typeof s==='string'&&new RegExp(`^[0-9a-f]{${bytes*2}}$`).test(s);
export const uuidOK=s=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s);
export function validateEnvelope(e){
 if(!e||e.v!==1||!uuidOK(e.id)||!uuidOK(e.from)||!uuidOK(e.to)||e.from===e.to||!hexOK(e.keyId,16)||!Number.isSafeInteger(e.ts)||e.ts<0)throw Error('Envelope không hợp lệ.');
 if(!['AES-GCM','DES-CBC'].includes(e.algorithm)||!hexOK(e.iv,e.algorithm==='AES-GCM'?12:8))throw Error('Thuật toán hoặc IV không hợp lệ.');
 if(typeof e.ciphertext!=='string'||e.ciphertext.length>2200000||(e.ciphertext.length%4!==0||! /^[A-Za-z0-9+/]*={0,2}$/.test(e.ciphertext)))throw Error('Bản mã không hợp lệ.');
 const bytes=e.ciphertext.length*3/4-(e.ciphertext.endsWith('==')?2:e.ciphertext.endsWith('=')?1:0);
 if(e.algorithm==='AES-GCM'?(bytes<17||e.mac!==undefined):(bytes<8||bytes%8!==0||!hexOK(e.mac,32)))throw Error('Độ dài bản mã hoặc MAC không hợp lệ.');
 const allowed=['v','id','from','to','algorithm','keyId','ts','iv','ciphertext',...(e.algorithm==='DES-CBC'?['mac']:[])];
 if(Object.keys(e).some(k=>!allowed.includes(k)))throw Error('Envelope chứa trường không hỗ trợ.');
 return e;
}
export const metadata=e=>JSON.stringify([e.v,e.id,e.from,e.to,e.algorithm,e.keyId,e.ts,e.iv]);

export function validatePacket(packet){
 if(!packet||packet.v!==1||Object.keys(packet).some(k=>!['v','envelope','recipients','wrappedKeys'].includes(k)))throw Error('Gói E2EE không hợp lệ.');
 validateEnvelope(packet.envelope);
 const {recipients,wrappedKeys}=packet;
 if(!Array.isArray(recipients)||recipients.length<2||recipients.length>30||recipients.some(x=>!uuidOK(x))||new Set(recipients).size!==recipients.length||JSON.stringify([...recipients].sort())!==JSON.stringify(recipients)||!recipients.includes(packet.envelope.from))throw Error('Danh sách người nhận không hợp lệ.');
 if(!wrappedKeys||Array.isArray(wrappedKeys)||Object.keys(wrappedKeys).length!==recipients.length)throw Error('Thiếu khóa đã bọc.');
 for(const id of recipients){const w=wrappedKeys[id];if(!w||Object.keys(w).some(k=>!['iv','ciphertext'].includes(k))||!hexOK(w.iv,12)||!hexOK(w.ciphertext,packet.envelope.algorithm==='AES-GCM'?48:56))throw Error('Khóa đã bọc không hợp lệ.');}
 return packet;
}
