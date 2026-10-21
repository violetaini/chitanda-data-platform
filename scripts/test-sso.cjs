'use strict';
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const source=path.resolve(process.env.CT_SSO_SOURCE||path.join(__dirname,'../../chitanda-sso'));
if(!fs.existsSync(path.join(source,'server.js'))){
 console.error('SSO 源码已移至私有仓库 https://github.com/violetaini/chitanda-sso 。请克隆到相邻目录 chitanda-sso，或使用 CT_SSO_SOURCE 指定路径，并在私有仓库运行 npm ci。');
 process.exit(1);
}
try{require.resolve('qrcode',{paths:[source]});}catch{
 console.error('请先在私有 SSO 仓库运行 npm ci。');process.exit(1);
}
const env={...process.env,CT_SSO_SOURCE:source};
for(const [cwd,args] of [
 [path.resolve(__dirname,'..'),['--test','scripts/sso-integration.test.cjs']],
 [source,['--test','scripts/security.test.cjs','scripts/security-regressions.test.cjs']]
]){
 const result=spawnSync(process.execPath,args,{cwd,env,stdio:'inherit',windowsHide:true});
 if(result.error){console.error(result.error.message);process.exit(1);}
 if(result.status!==0)process.exit(result.status||1);
}
