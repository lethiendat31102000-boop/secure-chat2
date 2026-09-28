import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {randomBytes,randomUUID,scrypt as scryptCallback,timingSafeEqual,webcrypto} from 'node:crypto';
import {promisify} from 'node:util';
import {database} from './database.js';
import {validatePacket,hexOK,uuidOK} from '../Frontend/js/schema.js';
const scrypt=promisify(scryptCallback),root=fileURLToPath(new URL('../Frontend/',import.meta.url)),vendor=fileURLToPath(new URL('../node_modules/crypto-js/crypto-js.js',import.meta.url));
const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.svg':'image/svg+xml'};
const error=(status,message)=>Object.assign(Error(message),{status});
const normalize=x=>typeof x==='string'?x.trim().toLowerCase():'';
export async function createApp({mongoUri,mongoDb,repository,sessionMs=8*3600000}={}){
 const db=repository||await database({uri:mongoUri,name:mongoDb}),sessions=new Map(),streams=new Set(),rates=new Map();
 const account=row=>({id:row.id,username:row.username,publicJwk:row.publicJwk});
 const cookie=req=>(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('sid='))?.slice(4);
 function session(req){const token=cookie(req),s=sessions.get(token);if(!s||s.expires<Date.now()){sessions.delete(token);throw error(401,'Phiên đăng nhập đã hết hạn. Hãy đăng nhập lại.');}return {...s,token};}
 function broadcast(event,data,users){for(const stream of streams)if(sessions.get(stream.token)?.expires>Date.now()&&(!users||users.includes(stream.userId)))stream.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);}
 function rate(key,limit){const now=Date.now();let r=rates.get(key);if(!r||now-r.start>60000){r={start:now,n:0};rates.set(key,r);}if(++r.n>limit)throw error(429,'Quá nhiều yêu cầu. Thử lại sau một phút.');}
 async function body(req){let text='';for await(const chunk of req){text+=chunk;if(Buffer.byteLength(text)>2100000)throw error(413,'Dữ liệu quá lớn.');}try{return JSON.parse(text);}catch{throw error(400,'JSON không hợp lệ.');}}
 function login(res,row){const token=randomBytes(32).toString('hex');sessions.set(token,{userId:row.id,expires:Date.now()+sessionMs});res.setHeader('Set-Cookie',`sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(sessionMs/1000)}`);return {...account(row),vault:row.vault};}
 const server=http.createServer(async(req,res)=>{
 const json=(status,obj)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj));};
 try{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
 res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
 // Local teaching app: reject unexpected Host / browser origins, bind loopback in server.js.
 if(!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host||''))throw error(403,'Host không được phép.');
 if(req.headers.origin&&req.headers.origin!==`http://${req.headers.host}`)throw error(403,'Nguồn yêu cầu không hợp lệ.');
 const url=new URL(req.url,'http://localhost'),route=url.pathname;
 if(req.method==='POST'){
 if(req.headers['x-requested-with']!=='SecureChat')throw error(403,'Thiếu header yêu cầu.');
 if(!(req.headers['content-type']||'').startsWith('application/json'))throw error(415,'Cần JSON.');
 }
 if(route==='/api/auth/config'&&req.method==='GET'){
 rate('auth:'+req.socket.remoteAddress,90);const name=normalize(url.searchParams.get('username'));
 const row=await db.findUser({username:name});
 if(!row)throw error(404,'Tài khoản chưa tồn tại. Hãy đăng ký.');return json(200,{authSalt:row.authSalt});
 }
 if(route==='/api/register'&&req.method==='POST'){
 rate('auth:'+req.socket.remoteAddress,90);const b=await body(req),username=normalize(b.username);
 if(!/^[a-z0-9_]{3,30}$/.test(username)||!hexOK(b.authSalt,16)||!hexOK(b.proof,32))throw error(400,'Tên tài khoản: 3–30 ký tự a-z, 0-9, dấu gạch dưới.');
 if(!b.publicJwk||b.publicJwk.d||b.publicJwk.kty!=='EC'||b.publicJwk.crv!=='P-256')throw error(400,'Khóa công khai không hợp lệ.');
 try{await webcrypto.subtle.importKey('jwk',b.publicJwk,{name:'ECDH',namedCurve:'P-256'},false,[]);}catch{throw error(400,'Khóa công khai không hợp lệ.');}
 const v=b.vault;if(!v||v.v!==1||!hexOK(v.salt,16)||!hexOK(v.iv,12)||typeof v.ciphertext!=='string'||v.ciphertext.length<32||v.ciphertext.length>4096)throw error(400,'Kho khóa không hợp lệ.');
 if(await db.findUser({username}))throw error(409,'Tên tài khoản đã tồn tại.');
 const passwordSalt=randomBytes(16).toString('hex'),passwordHash=(await scrypt(b.proof,passwordSalt,32)).toString('hex');
 const row={id:randomUUID(),username,authSalt:b.authSalt,passwordSalt,passwordHash,publicJwk:{kty:'EC',crv:'P-256',x:b.publicJwk.x,y:b.publicJwk.y,ext:true},vault:v,createdAt:Date.now()};
 try{await db.addUser(row);}catch(e){if(e.code===11000)throw error(409,'Tên tài khoản đã tồn tại.');throw e;}
 broadcast('users',{});return json(201,login(res,row));
 }
 if(route==='/api/login'&&req.method==='POST'){
 rate('auth:'+req.socket.remoteAddress,90);const b=await body(req);
 const row=await db.findUser({username:normalize(b.username)});
 if(!row||!hexOK(b.proof,32))throw error(401,'Tài khoản hoặc mật khẩu không đúng.');
 const hash=await scrypt(b.proof,row.passwordSalt,32);
 if(!timingSafeEqual(hash,Buffer.from(row.passwordHash,'hex')))throw error(401,'Tài khoản hoặc mật khẩu không đúng.');
 return json(200,login(res,row));
 }
 if(route.startsWith('/api/')){
 const sess=session(req),me=await db.findUser({id:sess.userId});
 const clean=row=>({id:row.id,seq:row.seq,conversation:row.conversation||[row.sender,row.recipient].sort().join(':'),sender:row.sender,senderName:row.senderName,algorithm:row.algorithm,packet:row.packet||null,legacy:!row.packet,receivedAt:row.receivedAt});
 async function target(id){
 if(typeof id!=='string')throw error(400,'Chọn cuộc trò chuyện.');
 if(id.startsWith('group:')){const group=await db.findGroup(id.slice(6));if(!group||!group.members.includes(me.id))throw error(403,'Bạn không thuộc nhóm này.');return {conversation:id,members:group.members,to:group.id,name:group.name};}
 if(!uuidOK(id)||id===me.id)throw error(400,'Người nhận không hợp lệ.');
 const peer=await db.findUser({id});if(!peer)throw error(404,'Không tìm thấy người nhận.');return {conversation:[me.id,id].sort().join(':'),members:[me.id,id],to:id,name:peer.username};
 }
 if(route==='/api/chat/config'&&req.method==='GET')return json(200,{ok:true});
 if(route==='/api/groups'&&req.method==='GET')return json(200,await db.listGroups(me.id));
 if(route==='/api/groups'&&req.method==='POST'){
 const b=await body(req);if(typeof b.name!=='string'||!b.name.trim()||b.name.trim().length>60||!Array.isArray(b.members))throw error(400,'Nhập tên nhóm (tối đa 60 ký tự) và chọn thành viên.');
 const members=[...new Set([me.id,...b.members])];if(members.length<3||members.length>30)throw error(400,'Nhóm cần từ 3 đến 30 thành viên.');
 for(const id of members)if(!uuidOK(id)||!await db.findUser({id}))throw error(400,'Thành viên không hợp lệ.');
 const group={id:randomUUID(),name:b.name.trim(),members,owner:me.id,createdAt:new Date()};await db.addGroup(group);broadcast('groups',{},members);return json(201,group);
 }
 if(route==='/api/chat/history'&&req.method==='GET'){
 const t=await target(url.searchParams.get('target')),before=Number(url.searchParams.get('before')||Number.MAX_SAFE_INTEGER);
 if(!Number.isSafeInteger(before)||before<1)throw error(400,'Trang lịch sử không hợp lệ.');
 let rows=await db.chatHistory(t.conversation,before);const more=rows.length>50;return json(200,{more,messages:rows.slice(0,50).reverse().map(clean)});
 }
 if(route==='/api/chat/typing'&&req.method==='POST'){rate('typing:'+me.id,120);const b=await body(req),t=await target(b.target);broadcast('typing',{conversation:t.conversation,user:me.username},t.members.filter(id=>id!==me.id));return json(200,{ok:true});}
 if(route==='/api/chat/send'&&req.method==='POST'){
 rate('chat:'+me.id,120);const b=await body(req),t=await target(b.target);
 if(Object.keys(b).some(k=>!['target','packet'].includes(k)))throw error(400,'Chỉ nhận bản mã E2EE; không gửi bản rõ hoặc khóa giải mã.');
 try{validatePacket(b.packet);}catch{throw error(400,'Gói E2EE không hợp lệ.');}
 const packet=b.packet,envelope=packet.envelope;
 if(envelope.from!==me.id||envelope.to!==t.to)throw error(403,'Người gửi hoặc cuộc trò chuyện không khớp.');
 if(JSON.stringify([...t.members].sort())!==JSON.stringify(packet.recipients))throw error(400,'Danh sách khóa phải khớp thành viên cuộc trò chuyện.');
 const prior=await db.findMessage(envelope.id);
 if(prior){if(prior.sender!==me.id||prior.conversation!==t.conversation||JSON.stringify(prior.packet)!==JSON.stringify(packet))throw error(409,'Mã tin đã tồn tại.');return json(200,clean(prior));}
 const now=Date.now();let saved;
 try{saved=await db.addMessage({id:envelope.id,conversation:t.conversation,sender:me.id,recipient:t.to,senderName:me.username,recipientName:t.name,algorithm:envelope.algorithm,packet,securityMode:envelope.algorithm==='AES-GCM'?'E2EE-AES':'E2EE-DES-DEMO',receivedAt:now,createdAt:new Date(now)});}catch(e){if(e.code!==11000)throw e;throw error(409,'Tin nhắn đang được gửi. Thử lại.');}
 broadcast('chat',clean(saved),t.members);return json(201,clean(saved));
 }
 if(route==='/api/me'&&req.method==='GET')return json(200,{...account(me),authSalt:me.authSalt,vault:me.vault});
 if(route==='/api/logout'&&req.method==='POST'){
 sessions.delete(sess.token);for(const stream of [...streams])if(stream.token===sess.token)stream.res.end();
 res.setHeader('Set-Cookie','sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(200,{ok:true});
 }
 if(route==='/api/users'&&req.method==='GET')return json(200,(await db.listUsers(me.id)).map(row=>({...account(row),online:[...streams].some(s=>s.userId===row.id)})));
 if(route==='/api/events'&&req.method==='GET'){
 if([...streams].filter(s=>s.userId===me.id).length>=8)throw error(429,'Quá nhiều cửa sổ kết nối.');
 res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive'});res.write('event: ready\ndata: {}\n\n');
 const stream={res,userId:me.id,token:sess.token};streams.add(stream);broadcast('users',{});
 const heart=setInterval(()=>{if(!sessions.has(sess.token)||sess.expires<Date.now()){res.write('event: expired\ndata: {}\n\n');res.end();}else res.write(': heartbeat\n\n');},15000);
 res.on('close',()=>{clearInterval(heart);streams.delete(stream);broadcast('users',{});});return;
 }
 if(route==='/api/messages')throw error(410,'API lưu bản rõ đã bị tắt. Dùng giao diện E2EE mới.');
 throw error(404,'Không có API này.');
 }
 if(req.method!=='GET'&&req.method!=='HEAD')throw error(405,'Phương thức không hỗ trợ.');
 const pathname=decodeURIComponent(route),filename=pathname==='/vendor/crypto-js.js'?vendor:path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname));
 if(filename!==vendor&&(!filename.startsWith(root)||pathname.includes('\\')||pathname.split('/').some(x=>x.startsWith('.'))))throw error(403,'Không được truy cập.');
 let data;try{data=await readFile(filename);}catch{throw error(404,'Không tìm thấy file.');}
 res.writeHead(200,{'Content-Type':types[path.extname(filename)]||'application/octet-stream','Cache-Control':'no-store'});res.end(req.method==='HEAD'?undefined:data);
 }catch(e){if(!res.headersSent)json(e.status||500,{error:e.status?e.message:'Lỗi máy chủ.'});else res.end();}
 });
 const cleanup=setInterval(()=>{const now=Date.now();for(const [k,v] of sessions)if(v.expires<now)sessions.delete(k);for(const [k,v]of rates)if(now-v.start>60000)rates.delete(k);},60000);cleanup.unref();
 return {server,db,close:async()=>{clearInterval(cleanup);for(const x of streams)x.res.end();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await db.close();}};
}
