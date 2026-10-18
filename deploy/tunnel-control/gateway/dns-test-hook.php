<?php
// Narrow DNS hook for this isolated test name only; credentials remain in DNS Manager.
require '/www/wwwroot/dns.chitanda.net/vendor/autoload.php';
$app=new think\App('/www/wwwroot/dns.chitanda.net/');$app->initialize();
$d=think\facade\Db::name('domain')->where('name','chitanda.net')->find();
$m=app\lib\DnsHelper::getModel($d['aid'],$d['name'],$d['thirdid']);
$action=$argv[1]??'list';
$name=$argv[2]??'data-test.chitanda.net';
if(!in_array($name,['data-test.chitanda.net','_acme-challenge.data-test.chitanda.net'],true))throw new Exception('Name outside test scope');
$rr=substr($name,0,-strlen('.chitanda.net'));
$type=$name[0]==='_'?'TXT':'A';
$records=$m->getSubDomainRecords($rr,1,100,$type);
if($records===false)throw new Exception('DNS record lookup failed');
if($action==='list'){echo json_encode($records);exit;}
if($action==='add'){
 $value=$argv[3];$line=$argv[4]??'default_view';
 foreach($records['list'] as $record){if(($record['Line']??$record['line']??'')===$line){throw new Exception('Refusing to overwrite existing test record');}}
 $result=$m->addDomainRecord($rr,$type,$value,$line,300,1,null,'Chitanda HTTPS isolated test');
 if($result===false)throw new Exception('DNS add failed: '.$m->getError());
 think\facade\Db::name('log')->insert(['uid'=>1000,'action'=>'测试解析配置','domain'=>'chitanda.net','data'=>$rr.' '.$type.' '.$line,'addtime'=>date('Y-m-d H:i:s')]);
 echo json_encode(['ok'=>true,'recordId'=>$result]);
}elseif($action==='remove'&&$type==='TXT'){
 foreach($records['list'] as $record){if(trim($record['Value']??$record['value']??'', '"')!==$argv[3])continue;$id=$record['RecordId']??$record['recordid']??$record['id'];if($m->deleteDomainRecord($id)===false)throw new Exception('DNS cleanup failed');}
 echo '{"ok":true}';
}else{throw new Exception('Unsupported operation');}
