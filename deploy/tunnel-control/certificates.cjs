'use strict';
const crypto=require('node:crypto'),tls=require('node:tls');
const fail=message=>{throw Object.assign(Error(message),{status:400});};
const info=pem=>{const c=new crypto.X509Certificate(pem);return {subject:c.subject,issuer:c.issuer,dnsNames:c.subjectAltName?.split(', ').filter(n=>n.startsWith('DNS:')).map(n=>n.slice(4))||[],notBefore:new Date(c.validFrom).toISOString(),notAfter:new Date(c.validTo).toISOString(),fingerprint:c.fingerprint256.replaceAll(':','').toLowerCase()};};
function validate(input,names,ca){
 const certPEM=String(input.certPEM||'').trim(),keyPEM=String(input.keyPEM||'').trim();
 if(certPEM.length>65536||keyPEM.length>16384)fail('证书或私钥过大');
 let chain,leaf;
 try{chain=(certPEM.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)||[]).map(p=>new crypto.X509Certificate(p));leaf=chain[0];if(!leaf||chain.length>10||!leaf.checkPrivateKey(crypto.createPrivateKey(keyPEM)))throw Error();tls.createSecureContext({cert:certPEM,key:keyPEM,minVersion:'TLSv1.3'});}catch{fail('证书格式错误或私钥不匹配');}
 if(leaf.keyUsage?.length&&!leaf.keyUsage.includes('1.3.6.1.5.5.7.3.1'))fail('证书用途不包含服务器身份验证');
 if(chain.some(c=>Date.parse(c.validFrom)>Date.now()||Date.parse(c.validTo)<Date.now()+86400000))fail('证书尚未生效或不足一天即将到期');
 for(const name of names)if(!leaf.checkHost(name))fail('证书未覆盖域名：'+name);
 // Trust only the current workspace CA or system public roots; arbitrary private roots are not accepted.
 const roots=[ca,...tls.rootCertificates].filter(Boolean).map(p=>new crypto.X509Certificate(p));let current=leaf,seen=new Set();
 for(let i=0;i<12;i++){if(roots.some(r=>(current.fingerprint256===r.fingerprint256)||(current.checkIssued(r)&&current.verify(r.publicKey))))return {mode:'custom',certPEM:certPEM+'\n',keyPEM:keyPEM+'\n'};seen.add(current.fingerprint256);const issuer=chain.find(c=>!seen.has(c.fingerprint256)&&current.checkIssued(c)&&current.verify(c.publicKey));if(!issuer)break;current=issuer;}
 fail('证书链不完整，须使用公开受信任证书或当前工作空间签发的证书');
}
function read(state){return Object.fromEntries(['channel','https'].map(p=>{const c=state.certificates?.[p];return [p,{mode:c?.mode==='custom'?'custom':'auto',...(c?.certPEM?{certificate:info(c.certPEM)}:{}),nodeIds:c?.nodeIds||[]}];}));}
module.exports={validate,read,info};
