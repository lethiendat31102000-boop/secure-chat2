import {access} from 'node:fs/promises';
import {createApp} from './app.js';
try{await access(new URL('../node_modules/mongodb/package.json',import.meta.url));}catch{console.error('Chay npm.cmd install truoc.');process.exit(1);}
const port=Number(process.env.PORT||8080);let app;
try{app=await createApp();}catch{console.error('Khong ket noi duoc MongoDB. Bat dich vu MongoDB va kiem tra MONGODB_URI/MONGODB_DB trong .env. Mac dinh: mongodb://127.0.0.1:27017, database secure_chat.');process.exit(1);}
app.server.on('error',e=>{console.error(e.code==='EADDRINUSE'?`Cong ${port} dang duoc dung. Tat server cu bang Ctrl+C.`:e.message);process.exit(1);});
app.server.listen(port,'127.0.0.1',()=>console.log(`SECURE CHAT + MONGODB\nMo: http://localhost:${port}\nCompass: database ${process.env.MONGODB_DB||'secure_chat'} -> messages -> packet.envelope.ciphertext\nE2EE: server chi luu ban ma, khong luu khoa giai ma. Dung server: Ctrl+C`));
process.on('SIGINT',async()=>{await app.close();process.exit(0);});
