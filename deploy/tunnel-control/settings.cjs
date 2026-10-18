'use strict';
const defaults={enabled:true,intervalSeconds:60,maxAgeSeconds:180};
const valid=s=>s&&typeof s.enabled==='boolean'&&Number.isInteger(s.intervalSeconds)&&s.intervalSeconds>=15&&s.intervalSeconds<=3600&&Number.isInteger(s.maxAgeSeconds)&&s.maxAgeSeconds>=120&&s.maxAgeSeconds<=86400&&s.maxAgeSeconds>=s.intervalSeconds+90;
const read=input=>{const s=valid(input?.routeChecks)?input.routeChecks:defaults;return {routeChecks:{enabled:s.enabled,intervalSeconds:s.intervalSeconds,maxAgeSeconds:s.maxAgeSeconds}};};
function update(current,input){
 const fail=message=>{throw Object.assign(Error(message),{status:400});};
 if(!input||Object.keys(input).some(k=>k!=='routeChecks')||!input.routeChecks||typeof input.routeChecks!=='object'||Array.isArray(input.routeChecks)||Object.keys(input.routeChecks).some(k=>!Object.hasOwn(defaults,k)))fail('系统设置字段不正确');
 const next={...read(current).routeChecks,...input.routeChecks};
 if(!valid(next))fail('测活间隔须为 15–3600 秒；结果有效期须为 120–86400 秒，且至少比间隔长 90 秒');
 return {routeChecks:next};
}
module.exports={read,update};
