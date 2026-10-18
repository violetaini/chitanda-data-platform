'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process'),sharp=require('sharp');
const {createAdminPasswordHash}=require('../deploy/tunnel-control/password-auth.cjs');
const base='http://127.0.0.1:5099',password='Local-Account-2026!',newPassword='Case2026';
(async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ct-account-')),hash=await createAdminPasswordHash(password);
 let child,browser,count=0;const check=(v,m)=>{assert.ok(v,m);count++;};
 const start=async()=>{child=spawn(process.execPath,['deploy/tunnel-control/server.cjs'],{cwd:path.resolve(__dirname,'..'),windowsHide:true,stdio:['ignore','ignore','pipe'],env:{...process.env,CT_PORT:'5099',CT_DATA:directory,CT_USERNAME:'test-admin',CT_PASSWORD_HASH:hash,CT_INSECURE:'1',CT_OPENSSL:process.env.CT_OPENSSL||(process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl')}});child.stderr.on('data',()=>{});for(let i=0;i<80;i++){try{if((await fetch(base+'/health')).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw Error('Server did not start');};
 const stop=()=>new Promise(resolve=>{child.once('exit',resolve);child.kill();});
 const login=async(username='test-admin',pass=password)=>{const r=await fetch(base+'/tunnel/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password:pass})});if(!r.ok)return {status:r.status};const b=await r.json();return {status:r.status,headers:{Cookie:r.headers.get('set-cookie').split(';')[0],'X-CSRF-Token':b.csrf,'Content-Type':'application/json'}};};
 const request=(url,method,headers,value)=>fetch(base+'/tunnel/api/'+url,{method,headers,...(value===undefined?{}:{body:JSON.stringify(value)})});
 try{
  await start();const first=await login(),second=await login(),headers=first.headers;
  check(first.status===200,'bootstrap credentials');
  for(const endpoint of ['profile','avatar','account'])check((await request(endpoint,'GET',{})).status===401,'account API requires auth '+endpoint);
  for(const endpoint of ['profile','avatar','account'])check((await request(endpoint,'GET',{'X-Real-IP':'8.8.8.8'})).status===403,'account API source restriction '+endpoint);
  check((await request('account','PATCH',{Cookie:headers.Cookie},{username:'changed'})).status===403,'credential CSRF');
  check((await request('avatar','PUT',{Cookie:headers.Cookie},{image:null})).status===403,'avatar CSRF');
  const before=await(await request('state','GET',headers)).json();
  check((await request('account','PATCH',headers,{username:'changed',currentPassword:'wrong'})).status===400,'current password required');
  check((await request('account','PATCH',headers,{username:'x',currentPassword:password})).status===400,'username validation');
  check((await request('account','PATCH',headers,{username:'changed',currentPassword:password,newPassword:'short',confirmPassword:'short'})).status===400,'password minimum');
  check((await request('account','PATCH',headers,{username:'changed',currentPassword:password,newPassword,confirmPassword:'different'})).status===400,'password confirmation');
  check((await request('avatar','PUT',headers,{image:'data:image/svg+xml;base64,'+Buffer.from('<svg/>').toString('base64')})).status===400,'SVG rejected');
  check((await request('avatar','PUT',headers,{image:'data:image/png;base64,'+Buffer.from('not an image').toString('base64')})).status===400,'malformed image rejected');
  check((await request('avatar','PUT',headers,{image:'data:image/png;base64,'+Buffer.alloc(2100001).toString('base64')})).status===400,'oversized image rejected');
  const png=await sharp({create:{width:640,height:360,channels:3,background:'#bfa5ce'}}).png().toBuffer(),image='data:image/png;base64,'+png.toString('base64');
  check((await request('avatar','PUT',headers,{image})).status===200,'valid avatar accepted');
  let avatar=await request('avatar','GET',headers),metadata=await sharp(Buffer.from(await avatar.arrayBuffer())).metadata();check(avatar.headers.get('content-type')==='image/webp'&&metadata.width===256&&metadata.height===256,'avatar decoded, resized and reencoded');
  const profile=await(await request('profile','GET',headers)).json();check(profile.hasAvatar&&!JSON.stringify(profile).includes('passwordHash'),'safe profile response');
  check((await(await request('state','GET',headers)).json()).version===before.version,'profile does not change node configuration revision');
  const {chromium}=require('playwright');browser=await chromium.launch({headless:true});const dir=path.resolve(__dirname,'../tmp/tunnel-control-account-qa');fs.mkdirSync(dir,{recursive:true});
  for(const width of [1440,390]){
   const page=await browser.newPage({viewport:{width,height:width===390?844:1050}});const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'/tunnel/');await page.locator('[name=username]').fill('test-admin');await page.locator('[name=password]').fill(password);await page.locator('.login-submit').click();await page.locator('#shell').waitFor({state:'visible'});await page.locator('nav [data-view=account]').click();await page.locator('#account-form').waitFor();await page.locator('#account-form [name=username]').fill('draft-user');await new Promise(r=>setTimeout(r,5600));check(await page.locator('#account-form [name=username]').inputValue()==='draft-user','polling preserves account form '+width);check(await page.locator('#settings-avatar img').count()===1,'saved avatar appears '+width);check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'settings fits viewport '+width);check(!/传输|连接|代理|翻墙|VPN|proxy|connection|transmission/i.test(await page.locator('body').innerText()),'settings vocabulary '+width);await page.screenshot({path:path.join(dir,'account-'+width+'.png'),fullPage:true});check(!errors.length,'no browser errors '+width);await page.close();
  }
  const editor=await browser.newPage();await editor.goto(base+'/tunnel/');await editor.locator('[name=username]').fill('test-admin');await editor.locator('[name=password]').fill(password);await editor.locator('.login-submit').click();await editor.locator('#shell').waitFor({state:'visible'});await editor.locator('nav [data-view=account]').click();
  await editor.locator('#avatar-file').setInputFiles({name:'avatar.png',mimeType:'image/png',buffer:png});await editor.getByRole('status').filter({hasText:'头像已更新'}).waitFor();check(await editor.locator('#settings-avatar img').count()===1,'avatar upload UI');
  await editor.locator('#remove-avatar').click();await editor.getByRole('status').filter({hasText:'已恢复默认头像'}).waitFor();check(await editor.locator('#settings-avatar img').count()===0,'remove avatar UI');
  await editor.locator('#avatar-file').setInputFiles({name:'avatar.png',mimeType:'image/png',buffer:png});await editor.getByRole('status').filter({hasText:'头像已更新'}).waitFor();
  await editor.locator('#account-form [name=username]').fill('renamed-admin');await editor.locator('#account-form [name=currentPassword]').fill('wrong-password');await editor.locator('#account-form [type=submit]').click();await editor.locator('#account-form .form-error').filter({hasText:'当前密码不正确'}).waitFor();check(true,'current password error in UI');await new Promise(r=>setTimeout(r,2100));
  await editor.locator('#account-form [name=currentPassword]').fill(password);await editor.locator('#account-form [type=submit]').click();await editor.locator('#login').waitFor({state:'visible'});check(await editor.locator('#login-form [name=username]').inputValue()==='renamed-admin','username-only change and relogin UI');
  await browser.close();browser=null;
  check((await request('profile','GET',headers)).status===401&&(await request('profile','GET',second.headers)).status===401,'all sessions revoked');
  check((await login()).status===401,'old username rejected');
  const renamed=await login('renamed-admin');check(renamed.status===200,'renamed username keeps password');
  check((await request('account','PATCH',renamed.headers,{username:'renamed-admin',currentPassword:password,newPassword,confirmPassword:newPassword})).status===200,'password change');
  check((await login('renamed-admin')).status===401,'old password rejected');
  check((await login('renamed-admin',newPassword)).status===200,'new password works');
  const disk=fs.readFileSync(path.join(directory,'account.json'),'utf8');check(!disk.includes(newPassword)&&!disk.includes(password)&&disk.includes('scrypt'),'only password hash persisted');
  await stop();await start();const restarted=await login('renamed-admin',newPassword);check(restarted.status===200,'account survives restart and bootstrap env');
  check((await(await request('profile','GET',restarted.headers)).json()).hasAvatar,'avatar survives restart');
  check((await request('avatar','PUT',restarted.headers,{image:null})).status===200,'remove avatar');
  check((await request('avatar','GET',restarted.headers)).status===404,'removed avatar unavailable');
  console.log(`PASS ${count} account checks: credential changes, session revocation, avatar normalization, persistence, source ACL, CSRF and responsive settings.`);
 }finally{if(browser)await browser.close();if(child&&child.exitCode===null)await stop();fs.rmSync(directory,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
