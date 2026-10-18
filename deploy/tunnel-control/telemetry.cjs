'use strict';
// Bound node observations to that node's configured scope. Persist no secrets.
module.exports=function sanitizeTLS(value,node,state){
 if(!value||value.schema!==1||!Array.isArray(value.entries))return null;
 const text=(s,max=256)=>typeof s==='string'?s.slice(0,max):'';
 const date=s=>typeof s==='string'&&Number.isFinite(Date.parse(s))?new Date(s).toISOString():'';
 const entries=[];
 for(const raw of value.entries.slice(0,32)){
  if(!raw||typeof raw!=='object'||!['client','server'].includes(raw.side)||!['channel','https-ingress'].includes(raw.usage))continue;
  if(raw.side==='server'&&raw.usage==='channel'&&!state.relays.some(n=>n.id===node.id))continue;
  if(raw.side==='server'&&raw.usage==='https-ingress'&&!node.ingress)continue;
  if(raw.side==='client'&&(raw.usage!=='channel'||!state.routes.some(r=>r.enabled&&(r.source===node.id||r.target===node.id)&&r.relayId===raw.relayId&&r.transport===raw.transport&&r.serverName===raw.serverName)))continue;
  let certificate=null;const c=raw.certificate;
  if(c&&/^[a-f0-9]{64}$/i.test(c.fingerprint)&&date(c.notBefore)&&date(c.notAfter)&&Date.parse(c.notAfter)>Date.parse(c.notBefore))certificate={fingerprint:c.fingerprint.toLowerCase(),subject:text(c.subject,384),issuer:text(c.issuer,384),dnsNames:Array.isArray(c.dnsNames)?c.dnsNames.filter(n=>typeof n==='string'&&n.length<=253).slice(0,24):[],notBefore:date(c.notBefore),notAfter:date(c.notAfter)};
  const observedAt=date(raw.observedAt);
  entries.push({side:raw.side,usage:raw.usage,relayId:raw.side==='server'?node.id:text(raw.relayId,80),transport:['h2','h3'].includes(raw.transport)?raw.transport:'',serverName:text(raw.serverName,253),active:raw.active===true,verified:raw.side==='client'&&raw.verified===true&&!!certificate&&!!observedAt,observedAt,version:text(raw.version,32),minimumVersion:text(raw.minimumVersion,32),alpn:text(raw.alpn,32),cipher:text(raw.cipher,96),certificate});
 }
 return {schema:1,collectedAt:date(value.collectedAt),entries};
};
