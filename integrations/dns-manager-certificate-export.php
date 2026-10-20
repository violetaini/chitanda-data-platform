<?php
// Install as app/controller/DatahubCertificate.php in DNS Manager.
// Add Route::post('/cert/datahub/order', 'datahubCertificate/order') inside the existing AuthApi group.
namespace app\controller;

use app\BaseController;
use think\facade\Db;

class DatahubCertificate extends BaseController
{
    public function order()
    {
        $request = request();
        $uid = (int)($request->user['id'] ?? 0);
        $id = (int)input('post.id/d', 0);
        $file = dirname(__DIR__, 2) . '/config/datahub-certificate-scopes.json';
        $scope = is_readable($file) ? json_decode(file_get_contents($file), true) : null;
        $allowed = $scope['users'][(string)$uid] ?? [];
        if (!$request->isApi || !$uid || !$id || !is_array($allowed) || !in_array($id, $allowed, true)) {
            return json(['code' => -1, 'msg' => '无此证书的读取权限'])->code(403);
        }
        $row = Db::name('cert_order')->where('id', $id)->field('id,status,fullchain,privatekey,issuetime,expiretime')->find();
        if (!$row || (int)$row['status'] !== 3 || empty($row['fullchain']) || empty($row['privatekey'])) {
            return json(['code' => -1, 'msg' => '证书尚未签发'])->code(409);
        }
        return json(['code' => 0, 'data' => [
            'id' => $row['id'], 'crt' => $row['fullchain'], 'key' => $row['privatekey'],
            'issuetime' => $row['issuetime'], 'expiretime' => $row['expiretime'],
            'domains' => Db::name('cert_domain')->where('oid', $id)->order('sort', 'ASC')->column('domain'),
        ]])->header(['Cache-Control' => 'no-store']);
    }
}
