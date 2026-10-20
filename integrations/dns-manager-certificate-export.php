<?php
// Install as app/controller/DatahubCertificate.php in DNS Manager.
// Also add Route::post('/cert/datahub/list', 'datahubCertificate/catalog') in that group.
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
    public function catalog()
    {
        $request = request();
        $uid = (int)($request->user['id'] ?? 0);
        $file = dirname(__DIR__, 2) . '/config/datahub-certificate-scopes.json';
        $scope = is_readable($file) ? json_decode(file_get_contents($file), true) : null;
        $allowed = $scope['users'][(string)$uid] ?? [];
        if (!$request->isApi || !$uid || !is_array($allowed) || !$allowed) {
            return json(['code' => -1, 'msg' => '无证书列表读取权限'])->code(403);
        }
        $allowed = array_slice(array_values(array_filter($allowed, function ($id) { return is_int($id) && $id > 0; })), 0, 64);
        $rows = [];
        if ($allowed) foreach (Db::name('cert_order')->whereIn('id', $allowed)->where('status', 3)->field('id,fullchain')->select() as $row) {
            $parsed = openssl_x509_parse($row['fullchain']);
            if (!$parsed) continue;
            $domains = [];
            foreach (explode(',', $parsed['extensions']['subjectAltName'] ?? '') as $san) {
                $san = trim($san);
                if (strpos($san, 'DNS:') === 0) $domains[] = strtolower(substr($san, 4));
            }
            $rows[] = ['id' => (int)$row['id'], 'domains' => $domains,
                'notBefore' => gmdate('c', $parsed['validFrom_time_t']), 'notAfter' => gmdate('c', $parsed['validTo_time_t'])];
        }
        return json(['code' => 0, 'rows' => $rows])->header(['Cache-Control' => 'no-store']);
    }

}
