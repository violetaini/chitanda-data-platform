'use strict';
const relays=r=>r.relayIds?.length?r.relayIds:[r.relayId];
const path=r=>[r.source,...relays(r),r.target].filter((id,i,a)=>i===0||id!==a[i-1]);
const first=r=>relays(r)[0],last=r=>relays(r).at(-1);
const next=(r,id)=>{const p=relays(r),i=p.indexOf(id);return i>=0?p[i+1]:undefined;};
const previous=(r,id)=>{const p=relays(r),i=p.indexOf(id);return i===0?r.source:i>0?p[i-1]:undefined;};
const link=(r,id)=>id===r.source&&id!==first(r)?first(r):id===r.target&&id!==last(r)?last(r):next(r,id);
module.exports={relays,path,first,last,next,previous,link};
