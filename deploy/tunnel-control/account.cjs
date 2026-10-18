'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {createAdminPasswordHash,verifyAdminPasswordHash}=require('./password-auth.cjs');
const sharp=require('sharp');
module.exports=function accountStore(directory){
 const file=path.join(directory,'account.json');
 let account=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{username:process.env.CT_USERNAME||'',passwordHash:process.env.CT_PASSWORD_HASH||'',avatar:'',avatarVersion:''};
 const save=next=>{fs.writeFileSync(file+'.tmp',JSON.stringify(next),{mode:0o600});fs.renameSync(file+'.tmp',file);account=next;};
 if(!fs.existsSync(file)&&account.username&&account.passwordHash)save(account);
 const fail=(message,status=400,code)=>{throw Object.assign(Error(message),{status,...(code?{code}:{})});};
 let pending=Promise.resolve();
 const serial=fn=>{const result=pending.then(fn);pending=result.catch(()=>{});return result;};
 return {
  profile:()=>({username:account.username,avatarVersion:account.avatarVersion||'',hasAvatar:!!account.avatar}),
  avatar:()=>account.avatar?Buffer.from(account.avatar,'base64'):null,
  login:async(username,password)=>{const current=account;const valid=await verifyAdminPasswordHash(String(password||''),current.passwordHash);return current===account&&valid&&username===current.username;},
  credentials:(input,active)=>serial(async()=>{
   if(!active())fail('会话已过期，请重新登录',401);
   if(!await verifyAdminPasswordHash(String(input.currentPassword||''),account.passwordHash))fail('当前密码不正确',400,'BAD_CURRENT_PASSWORD');
   const username=String(input.username||'').trim(),password=String(input.newPassword||'');
   if(!/^[\p{L}\p{N}_.@-]{3,64}$/u.test(username))fail('用户名需为 3–64 位字母、数字、中文或 _ . @ -');
   if(password&&(password.length<8||Buffer.byteLength(password)>4096))fail('新密码需至少 8 位，且不超过 4096 字节');
   if(password!==String(input.confirmPassword||''))fail('两次新密码不一致');
   if(username===account.username&&!password)fail('请修改用户名或填写新密码');
   const passwordHash=password?await createAdminPasswordHash(password):account.passwordHash;
   if(!active())fail('会话已过期，请重新登录',401);
   save({...account,username,passwordHash});return {ok:true,relogin:true};
  }),
  setAvatar:(input,active)=>serial(async()=>{
   if(!active())fail('会话已过期，请重新登录',401);
   let avatar='';
   if(input.image!==null){
    if(typeof input.image!=='string'||input.image.length>2800000||!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/]+=*$/.test(input.image))fail('请选择 2 MB 以内的 PNG、JPG 或 WebP 图片');
    const bytes=Buffer.from(input.image.split(',')[1],'base64');if(bytes.length>2*1024*1024)fail('头像不能超过 2 MB',413);
    try{const image=sharp(bytes,{limitInputPixels:16000000,animated:false,failOn:'warning'}),meta=await image.metadata();if(!['png','jpeg','webp'].includes(meta.format)||meta.pages>1)fail('不支持该图片格式');avatar=(await image.rotate().resize(256,256,{fit:'cover'}).webp({quality:85}).toBuffer()).toString('base64');}catch{fail('图片无法读取，请使用有效的静态 PNG、JPG 或 WebP 图片');}
   }
   if(!active())fail('会话已过期，请重新登录',401);
   save({...account,avatar,avatarVersion:crypto.randomBytes(8).toString('hex')});return {ok:true,username:account.username,hasAvatar:!!avatar,avatarVersion:account.avatarVersion};
  })
 };
};
