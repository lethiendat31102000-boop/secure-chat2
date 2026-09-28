import {encryptE2EE,decryptE2EE} from './crypto/e2ee.js';
import {makeIdentity,authProof,unlockIdentity,fingerprint} from './crypto/messaging.js';
const $=id=>document.getElementById(id),el=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
let privateKey=null;
let me=null,users=[],groups=[],current=null,rows=new Map(),source=null,register=false,filter='all',version=0,selectedImage=null,pending=null,sending=false,typingTimer,lastTyping=0;
const previews=new Map(),unread=new Map();
$('algorithm').onchange=()=>{pending=null;$('crypto-note').textContent=$('algorithm').value==='DES-CBC'?'DES dùng cho học tập; ưu tiên AES để bảo mật.':'AES: mã hóa đầu cuối. Chỉ thiết bị thành viên đọc được.';};
const status=t=>$('status').textContent=t;
async function api(path,data){const r=await fetch('/api'+path,{method:data===undefined?'GET':'POST',headers:data===undefined?{}:{'Content-Type':'application/json','X-Requested-With':'SecureChat'},body:data===undefined?undefined:JSON.stringify(data)});const b=await r.json();if(!r.ok){if(r.status===401&&me)lock();throw Error(b.error||'Không thể kết nối.');}return b;}
function lock(){privateKey=null;source?.close();source=null;me=null;current=null;rows.clear();previews.clear();unread.clear();users=[];groups=[];version++;$('workspace').hidden=true;$('auth').hidden=false;$('thread').hidden=true;$('welcome').hidden=false;$('workspace').classList.remove('thread-open');$('messages').replaceChildren();$('password').value='';$('confirm').value='';$('message').value='';selectedImage=null;pending=null;$('attachment').hidden=true;document.querySelectorAll('dialog[open]').forEach(d=>d.close());}
function mode(){ $('confirm-wrap').hidden=!register;$('confirm').required=register;$('auth-submit').textContent=register?'Tạo tài khoản':'Đăng nhập';$('auth-toggle').textContent=register?'Đã có tài khoản? Đăng nhập':'Chưa có tài khoản? Đăng ký';$('auth-note').textContent=register?'Tạo tài khoản để kết nối với bạn bè':'Đăng nhập để tiếp tục trò chuyện';$('auth-status').textContent='';}
$('auth-toggle').onclick=()=>{register=!register;mode();};
$('auth-form').onsubmit=async e=>{e.preventDefault();$('auth-submit').disabled=true;$('auth-status').textContent='Đang xử lý…';try{const username=$('username').value.trim().toLowerCase(),password=$('password').value;let result;if(register){if(password!==$('confirm').value)throw Error('Mật khẩu nhập lại không khớp.');result=await api('/register',{username,...await makeIdentity(username,password)});}else{const c=await api('/auth/config?username='+encodeURIComponent(username));result=await api('/login',{username,proof:await authProof(password,c.authSalt)});}const unlocked=await unlockIdentity(username,password,result.vault,result.publicJwk);privateKey=unlocked;await enter(result);}catch(e){$('auth-status').textContent=e.message;}finally{$('auth-submit').disabled=false;}};
async function enter(user){me=user;$('auth').hidden=true;$('workspace').hidden=false;$('me-name').textContent='Đăng nhập với '+me.username;$('my-avatar').textContent=me.username[0].toUpperCase();$('profile-name').textContent='Tên tài khoản: '+me.username;$('password').value=$('confirm').value='';await refresh();connect();}
async function refresh(){const who=me;if(!who)return;try{const [u,g]=await Promise.all([api('/users'),api('/groups')]);if(me!==who)return;users=u;groups=g;renderList();if(current){const c=all().find(x=>x.target===current.target);if(c){current=c;header();}}}catch(e){status(e.message);}}
const all=()=>[...groups.map(g=>({...g,target:'group:'+g.id,group:true})),...users.map(u=>({...u,name:u.username,target:u.id,group:false}))];
function conversation(c){return c.group?c.target:[me.id,c.id].sort().join(':');}
function renderList(){const q=$('search').value.toLowerCase();$('users').replaceChildren();const list=all().filter(c=>(filter==='all'||(filter==='groups')===c.group)&&c.name.toLowerCase().includes(q));for(const kind of [true,false]){const subset=list.filter(c=>c.group===kind).sort((a,b)=>(previews.get(conversation(b))?.receivedAt||0)-(previews.get(conversation(a))?.receivedAt||0));if(!subset.length)continue;$('users').append(el('p','list-label',kind?'Nhóm chat':'Bạn bè chat'));for(const c of subset){const key=conversation(c),b=el('button','user-row'+(current?.target===c.target?' selected':''));b.dataset.user=c.name;b.append(el('span','avatar'+(c.online?' online':''),c.group?'♧':c.name[0].toUpperCase()));const info=el('span','user-info');info.append(el('strong','',c.name));const p=previews.get(key);info.append(el('small','',p?(p.sender===me.id?'Bạn: ':'')+(p.text||'Đã gửi một ảnh'):(c.group?c.members.length+' thành viên':c.online?'Đang hoạt động':'Chưa có tin nhắn')));b.append(info);if(unread.get(key))b.append(el('span','unread',String(unread.get(key))));b.onclick=()=>choose(c);$('users').append(b);}}if(!list.length)$('users').append(el('p','empty',q?'Không tìm thấy cuộc trò chuyện.':filter==='groups'?'Bấm ＋ để tạo nhóm mới.':'Chưa có người dùng khác. Đăng ký thêm tài khoản bằng cửa sổ ẩn danh.'));}
$('search').oninput=renderList;document.querySelectorAll('[data-filter]').forEach(b=>b.onclick=()=>{filter=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(n=>n.classList.toggle('active',n.dataset.filter===filter));renderList();});
function header(){$('peer-name').textContent=current.name;$('peer-avatar').textContent=current.group?'♧':current.name[0].toUpperCase();$('peer-avatar').className='avatar'+(current.online?' online':'');$('peer-status').textContent=current.group?current.members.length+' thành viên':current.online?'Đang hoạt động':'Ngoại tuyến';const wall=localStorage.getItem('wall:'+me.id+':'+current.target)||'plain';$('messages').className='messages wall-'+wall;}
async function choose(c){current=c;version++;rows=new Map();pending=null;selectedImage=null;$('attachment').hidden=true;$('message').value='';$('typing').textContent='';$('welcome').hidden=true;$('thread').hidden=false;$('workspace').classList.add('thread-open');unread.delete(conversation(c));header();renderList();renderMessages();status('');await history();}
async function history(older=false){if(!current)return;const v=version,target=current.target,seq=Math.min(...rows.keys());try{const data=await api('/chat/history?target='+encodeURIComponent(target)+(older&&Number.isFinite(seq)?'&before='+seq:''));if(v!==version)return;const decoded=await Promise.all(data.messages.map(decodeRow));if(v!==version)return;for(const r of decoded)rows.set(r.seq,r);if(data.messages.length&&!older){const last=decoded.at(-1);previews.set(last.conversation,last);renderList();}$('older').hidden=!data.more;renderMessages(!older);}catch(e){status(e.message);}}
function renderMessages(scroll=true){const pane=$('messages'),oldHeight=pane.scrollHeight,oldTop=pane.scrollTop;pane.replaceChildren();if(!rows.size)pane.append(el('p','empty','Chưa có tin nhắn. Gửi lời chào đầu tiên nhé!'));for(const r of [...rows.values()].sort((a,b)=>a.seq-b.seq)){const b=el('article','bubble'+(r.sender===me.id?' own':''));if(current.group&&r.sender!==me.id)b.append(el('div','sender',r.senderName));if(r.image){const img=el('img');img.src=r.image;img.alt='Ảnh từ '+r.senderName;b.append(img);}if(r.text)b.append(el('p','text',r.text));if(r.algorithm)b.append(el('div','crypto-badge','🔒 '+r.algorithm));b.append(el('div','meta',new Date(r.receivedAt).toLocaleTimeString('vi-VN',{hour:'2-digit',minute:'2-digit'})+(r.sender===me.id?' · Đã gửi':'')));pane.append(b);}pane.scrollTop=scroll?pane.scrollHeight:oldTop+(pane.scrollHeight-oldHeight);}
function connect(){source?.close();source=new EventSource('/api/events');source.addEventListener('ready',()=>{$('connection').textContent='Đã kết nối';refresh();history();});source.addEventListener('users',refresh);source.addEventListener('groups',refresh);source.addEventListener('expired',()=>{lock();$('auth-status').textContent='Phiên đã hết hạn, vui lòng đăng nhập lại.';});source.onerror=()=>{$('connection').textContent='Đang kết nối lại…';};source.addEventListener('chat',async e=>{if(!me)return;const who=me;const r=await decodeRow(JSON.parse(e.data));if(me!==who)return;previews.set(r.conversation,r);if(current&&conversation(current)===r.conversation){rows.set(r.seq,r);renderMessages();$('typing').textContent='';}else if(r.sender!==me.id)unread.set(r.conversation,(unread.get(r.conversation)||0)+1);renderList();});source.addEventListener('typing',e=>{const d=JSON.parse(e.data);if(current&&conversation(current)===d.conversation){$('typing').textContent=d.user+' đang nhập…';clearTimeout(typingTimer);typingTimer=setTimeout(()=>$('typing').textContent='',2200);}});}
$('older').onclick=()=>history(true);$('back').onclick=()=>$('workspace').classList.remove('thread-open');
$('send-form').onsubmit=async e=>{
 e.preventDefault();if(!current||sending)return;
 const text=$('message').value,image=selectedImage,target=current.target,v=version,from=me.id,algorithm=$('algorithm').value;
 if(!text.trim()&&!image)return;
 sending=true;$('send').disabled=true;
 try{
  if(!pending||pending.text!==text||pending.image!==image||pending.target!==target||pending.algorithm!==algorithm){
   const ids=current.group?current.members:[from,current.id];const accounts=ids.map(id=>id===me.id?me:users.find(u=>u.id===id));if(accounts.some(a=>!a))throw Error('Thiếu khóa thành viên. Hãy tải lại danh sách.');for(const a of accounts)await checkKey(a);const wire=await encryptE2EE({text,image,target,from,algorithm,privateKey,accounts});
   if(v!==version||me?.id!==from)return;
   pending={text,image,target,algorithm,wire};
  }
  const r=await decodeRow(await api('/chat/send',pending.wire));
  if(v!==version)return;rows.set(r.seq,r);previews.set(r.conversation,r);renderMessages();renderList();
  if($('message').value===text)$('message').value='';
  if(selectedImage===image){selectedImage=null;$('attachment').hidden=true;}
  pending=null;status('');
 }catch(e){status(e.message+' Bấm gửi để thử lại.');}finally{sending=false;$('send').disabled=false;}
};
$('message').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();$('send-form').requestSubmit();}};$('message').oninput=()=>{if(current&&Date.now()-lastTyping>1300){lastTyping=Date.now();api('/chat/typing',{target:current.target}).catch(()=>{});}};
$('emoji').onclick=()=>{$('message').value+=' 😊';$('message').focus();};$('attach').onclick=()=>$('image-file').click();$('image-file').onchange=async()=>{const file=$('image-file').files[0],v=version;$('image-file').value='';if(!file)return;if(file.size>1024*1024||!['image/png','image/jpeg','image/webp'].includes(file.type)){status('Chọn ảnh PNG, JPEG hoặc WebP, tối đa 1 MB.');return;}try{const data=await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(r.result);r.onerror=reject;r.readAsDataURL(file);});if(v!==version)return;selectedImage=data;$('attachment').hidden=false;status('');}catch{status('Không đọc được ảnh.');}};$('remove-image').onclick=()=>{selectedImage=null;$('attachment').hidden=true;};
$('new-group').onclick=()=>{$('member-list').replaceChildren();$('group-error').textContent='';for(const u of users){const label=el('label'),input=el('input');input.type='checkbox';input.value=u.id;label.append(input,document.createTextNode(u.username));$('member-list').append(label);}$('group-dialog').showModal();};$('group-form').onsubmit=async e=>{e.preventDefault();const button=e.submitter;button.disabled=true;try{const group=await api('/groups',{name:$('group-name').value,members:[...$('member-list').querySelectorAll('input:checked')].map(x=>x.value)});$('group-dialog').close();$('group-name').value='';await refresh();await choose({...group,target:'group:'+group.id,group:true});}catch(e){$('group-error').textContent=e.message;}finally{button.disabled=false;}};
$('settings').onclick=()=>$('settings-dialog').showModal();$('wallpaper').onclick=()=>$('wallpaper-dialog').showModal();document.querySelectorAll('[data-wall]').forEach(b=>b.onclick=()=>{if(current){localStorage.setItem('wall:'+me.id+':'+current.target,b.dataset.wall);header();$('wallpaper-dialog').close();}});$('gallery').onclick=()=>{$('gallery-images').replaceChildren();for(const r of rows.values())if(r.image){const img=el('img');img.src=r.image;img.alt='Ảnh đã gửi';$('gallery-images').append(img);}if(!$('gallery-images').children.length)$('gallery-images').append(el('p','','Chưa có ảnh trong lịch sử đã tải.'));$('gallery-dialog').showModal();};document.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>$(b.dataset.close).close());document.querySelectorAll('.theme').forEach(b=>b.onclick=()=>{document.body.classList.toggle('dark');localStorage.setItem('chat-theme',document.body.classList.contains('dark')?'dark':'light');});if(localStorage.getItem('chat-theme')==='dark')document.body.classList.add('dark');$('logout').onclick=async()=>{try{await api('/logout',{});}finally{lock();}};
register=location.hash==='#register';mode();$('auth-status').textContent='Đăng nhập để mở khóa tin nhắn trên thiết bị này.';

async function checkKey(account){
 const value=await fingerprint(account.publicJwk),slot='e2ee-pin:'+me.id+':'+account.id,old=localStorage.getItem(slot);
 if(old&&old!==value)throw Error('Khóa của '+account.username+' đã thay đổi. Dừng gửi và xác minh lại mã an toàn.');
 if(!old)localStorage.setItem(slot,value);
 return value;
}
async function decodeRow(row){
 if(!row.packet)return {...row,text:'[Tin cũ không có mã hóa đầu cuối; không hiển thị bản rõ trong chế độ E2EE.]',image:null};
 try{
  const who=me,key=privateKey;
  if(!who||!key)throw Error('Kho khóa đang khóa.');
  let sender=row.sender===who.id?who:users.find(u=>u.id===row.sender);
  if(!sender){await refresh();sender=users.find(u=>u.id===row.sender);}
  if(!sender)throw Error('Không tìm thấy khóa người gửi.');
  await checkKey(sender);
  const e=row.packet.envelope;
  const expected=row.conversation.startsWith('group:')?'group:'+e.to:[e.from,e.to].sort().join(':');
  if(e.from!==row.sender||e.id!==row.id||expected!==row.conversation)throw Error('Thông tin cuộc trò chuyện đã bị sửa.');
  const payload=await decryptE2EE(row.packet,{userId:who.id,privateKey:key,senderPublicJwk:sender.publicJwk});
  return {...row,...payload,algorithm:e.algorithm};
 }catch(e){return {...row,text:'[Không giải mã được] '+e.message,image:null};}
}
$('verify-keys').onclick=async()=>{
 if(!me||!current)return;
 const ids=current.group?current.members:[me.id,current.id];$('key-list').replaceChildren();
 for(const id of ids){const a=id===me.id?me:users.find(u=>u.id===id);if(!a)continue;const value=await fingerprint(a.publicJwk);const item=el('p','key-fingerprint',a.username+': '+value.match(/.{1,4}/g).join(' '));$('key-list').append(item);}
 $('keys-dialog').showModal();
};
