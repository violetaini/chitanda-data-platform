'use strict';
const fs=require('node:fs'),path=require('node:path');
const POLICY=Object.freeze({failureLimit:5,windowSeconds:900,initialLockSeconds:900,maxLockSeconds:86400,accountFailureLimit:10,maxConcurrent:2,sessionSeconds:43200});
module.exports=function loginDefense(directory,{now=Date.now}={}){
 const file=path.join(directory,'login-defense.json');
 let state=fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{records:{},events:[]};
 const active=new Map(),buckets=new Map();let total=0;
 const save=()=>{fs.writeFileSync(file+'.tmp',JSON.stringify(state),{mode:0o600});fs.renameSync(file+'.tmp',file);};
 const deny=seconds=>{const retryAfter=Math.max(1,Math.ceil(seconds));throw Object.assign(Error(`尝试暂时受限，请 ${retryAfter} 秒后重试`),{status:429,retryAfter});};
 const keys=(ip,scope)=>[scope+':ip:'+ip,scope+':account'];
 const record=key=>{const r=state.records[key]||{count:0,start:now(),until:0,strikes:0};if(now()-r.start>=900000&&r.until<=now()){r.count=0;r.start=now();}return r;};
 const log=(ip,scope,outcome)=>{state.events.unshift({at:new Date(now()).toISOString(),ip,scope,outcome});state.events=state.events.slice(0,50);};
 return {
  begin(ip,scope='login'){
   for(const key of keys(ip,scope)){const r=record(key);if(r.until>now())deny((r.until-now())/1000);}
   if((active.get(ip)||0)>=1||total>=POLICY.maxConcurrent)deny(2);
   const bucketKey=scope+':'+ip,bucket=buckets.get(bucketKey)||{start:now(),count:0};if(now()-bucket.start>=60000){bucket.start=now();bucket.count=0;}if(bucket.count>=12)deny((bucket.start+60000-now())/1000);bucket.count++;buckets.set(bucketKey,bucket);
   active.set(ip,(active.get(ip)||0)+1);total++;return {ip,scope,finished:false};
  },
  failure(ticket){
   const {ip,scope}=ticket;
   for(const [i,key]of keys(ip,scope).entries()){
    const r=record(key);r.count++;
    if(r.count>=(i===0?POLICY.failureLimit:POLICY.accountFailureLimit)){r.strikes++;r.until=now()+Math.min(POLICY.maxLockSeconds,900*2**Math.min(r.strikes-1,7))*1000;}
    else if(r.count>=2)r.until=now()+Math.min(30,2**(r.count-1))*1000;
    state.records[key]=r;
   }
   log(ip,scope,'failed');save();return Math.max(0,...keys(ip,scope).map(key=>Math.ceil((state.records[key].until-now())/1000)));
  },
  success(ticket){for(const key of keys(ticket.ip,ticket.scope))delete state.records[key];log(ticket.ip,ticket.scope,'success');save();},
  finish(ticket){if(ticket.finished)return;ticket.finished=true;active.set(ticket.ip,Math.max(0,(active.get(ticket.ip)||1)-1));total=Math.max(0,total-1);},
  snapshot:()=>({policy:POLICY,events:state.events.slice(0,20),activeVerifications:total}),
 };
};
