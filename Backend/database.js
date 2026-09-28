import {MongoClient} from 'mongodb';
export async function database({uri=process.env.MONGODB_URI||'mongodb://127.0.0.1:27017',name=process.env.MONGODB_DB||'secure_chat'}={}){
 const client=new MongoClient(uri,{serverSelectionTimeoutMS:5000});
 try{
 await client.connect();const db=client.db(name),users=db.collection('users'),messages=db.collection('messages'),counters=db.collection('counters'),groups=db.collection('groups');
 await groups.createIndex({id:1},{unique:true});await groups.createIndex({members:1});await messages.createIndex({conversation:1,seq:-1});
 await users.createIndex({username:1},{unique:true});await users.createIndex({id:1},{unique:true});
 await messages.createIndex({id:1},{unique:true});await messages.createIndex({seq:1},{unique:true});await messages.createIndex({sender:1,recipient:1,seq:-1});
 return {db,users,messages,
  listGroups:id=>groups.find({members:id}).toArray(),
  findGroup:id=>groups.findOne({id}),
  addGroup:row=>groups.insertOne(row),
  chatHistory:(conversation,before)=>{const ids=conversation.split(':');const filter=conversation.startsWith('group:')?{conversation}:{$or:[{conversation},{conversation:{$exists:false},sender:ids[0],recipient:ids[1]},{conversation:{$exists:false},sender:ids[1],recipient:ids[0]}]};return messages.find({...filter,seq:{$lt:before}}).sort({seq:-1}).limit(51).toArray();},
  findUser:filter=>users.findOne(filter),
  addUser:row=>users.insertOne(row),
  listUsers:id=>users.find({id:{$ne:id}}).sort({username:1}).toArray(),
  findMessage:id=>messages.findOne({id}),
  history:(me,peer,before)=>messages.find({$or:[{sender:me,recipient:peer},{sender:peer,recipient:me}],seq:{$lt:before}}).sort({seq:-1}).limit(51).toArray(),
  addMessage:async row=>{const count=await counters.findOneAndUpdate({_id:'messages'},{$inc:{value:1}},{upsert:true,returnDocument:'after',includeResultMetadata:false});const record={...row,seq:count.value};await messages.insertOne(record);return record;},
  close:()=>client.close()
 };
 }catch(e){await client.close();throw e;}
}
