'use strict';
// Bounded, process-local admission control. Authentication still happens separately.
module.exports=function({now=Date.now,maxBuckets=4096,maxActive=128}={}){
 const buckets=new Map();let active=0;
 const deny=seconds=>{throw Object.assign(Error('请求过于频繁，请稍后重试'),{status:429,retryAfter:Math.max(1,Math.ceil(seconds))});};
 function bucket(key){
  const t=now();let b=buckets.get(key);
  if(!b){
   if(buckets.size>=maxBuckets)for(const [k,v]of buckets)if(v.until<=t&&!v.active)buckets.delete(k);
   if(buckets.size>=maxBuckets)deny(60);
   b={until:t+60000,count:0,active:0};buckets.set(key,b);
  }else if(b.until<=t){b.until=t+60000;b.count=0;}
  return b;
 }
 function take(key,limit){const b=bucket(key);if(b.count>=limit)deny((b.until-now())/1000);b.count++;return b;}
 function begin(req,res,key,{limit=600,concurrent=24}={}){
  const b=take(key,limit);if(b.active>=concurrent||active>=maxActive)deny(2);
  b.active++;active++;let done=false;
  const release=()=>{if(done)return;done=true;b.active--;active--;res.off('finish',release);res.off('close',release);};
  res.once('finish',release);res.once('close',release);
 }
 return {take,begin};
};
