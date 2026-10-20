'use strict';
const defaults={enabled:true,intervalSeconds:60,maxAgeSeconds:180};
const updateDefaults={enabled:true,intervalSeconds:3600,failureCooldownSeconds:21600};
const validUpdates=s=>s&&typeof s.enabled==='boolean'&&Number.isInteger(s.intervalSeconds)&&s.intervalSeconds>=300&&s.intervalSeconds<=86400&&Number.isInteger(s.failureCooldownSeconds)&&s.failureCooldownSeconds>=600&&s.failureCooldownSeconds<=604800;
const valid=s=>s&&typeof s.enabled==='boolean'&&Number.isInteger(s.intervalSeconds)&&s.intervalSeconds>=15&&s.intervalSeconds<=3600&&Number.isInteger(s.maxAgeSeconds)&&s.maxAgeSeconds>=120&&s.maxAgeSeconds<=86400&&s.maxAgeSeconds>=s.intervalSeconds+90;
const read=input=>{const s=valid(input?.routeChecks)?input.routeChecks:defaults,u=validUpdates(input?.nodeUpdates)?input.nodeUpdates:updateDefaults;return {routeChecks:{enabled:s.enabled,intervalSeconds:s.intervalSeconds,maxAgeSeconds:s.maxAgeSeconds},nodeUpdates:{enabled:u.enabled,intervalSeconds:u.intervalSeconds,failureCooldownSeconds:u.failureCooldownSeconds}};};
function update(current,input){
 const fail=message=>{throw Object.assign(Error(message),{status:400});};
 if(!input||typeof input!=='object'||Array.isArray(input)||!Object.keys(input).length||Object.keys(input).some(k=>!['routeChecks','nodeUpdates'].includes(k)))fail('系统设置字段不正确');
 if(input.routeChecks&&(typeof input.routeChecks!=='object'||Array.isArray(input.routeChecks)||Object.keys(input.routeChecks).some(k=>!Object.hasOwn(defaults,k))))fail('系统设置字段不正确');
 if(input.nodeUpdates&&(typeof input.nodeUpdates!=='object'||Array.isArray(input.nodeUpdates)||Object.keys(input.nodeUpdates).some(k=>!Object.hasOwn(updateDefaults,k))))fail('自动更新字段不正确');
 if(Object.values(input).some(v=>!v||typeof v!=='object'))fail('系统设置字段不正确');
 const previous=read(current),next={...previous.routeChecks,...input.routeChecks},updates={...previous.nodeUpdates,...input.nodeUpdates};
 if(!valid(next))fail('测活间隔须为 15–3600 秒；结果有效期须为 120–86400 秒，且至少比间隔长 90 秒');
 if(!validUpdates(updates))fail('更新检查间隔须为 300–86400 秒，失败冷却须为 600–604800 秒');
 return {routeChecks:next,nodeUpdates:updates};
}
module.exports={read,update};
