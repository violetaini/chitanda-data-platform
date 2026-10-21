# 通过隧道收发数据

把 JSON 或文件放进 HTTPS 请求，对方业务收到后处理，结果沿隧道返回。

## 1. 在面板准备一次

打开隧道详情的“URL 请求接入”，填对方业务的 HTTPS 地址并保存，再复制本隧道令牌。使用指南会按所选隧道、方向和目标生成示例。

## 2. 从发送方发出数据

下面的域名与 `/receive`、`/upload`、`/export` 是格式示例，替换成自己业务已有的接口。请求发到隧道入口，X-Target-URL 填真正接收数据的接口。

发送 JSON：

```bash
CHITANDA_TUNNEL_TOKEN='填写本隧道令牌'
curl --fail-with-body \
  -H "Authorization: Bearer ${CHITANDA_TUNNEL_TOKEN}" \
  -H 'X-Target-URL: https://business.example.com/api/receive' \
  -H 'Content-Type: application/json' \
  --data-binary '{"message":"hello","value":123}' \
  'https://entry.example.com/'
```

`--data-binary` 后面就是实际发送的 JSON。curl 自动使用 POST，对方返回的结果直接显示在终端。

上传文件内容：

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CHITANDA_TUNNEL_TOKEN}" \
  -H 'X-Target-URL: https://business.example.com/api/upload' \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @./example.bin \
  'https://entry.example.com/'
```

`@./example.bin` 读取发送方本地文件，把文件内容作为 POST 请求体交给对方。替换成自己的路径；接收接口需支持二进制文件内容。大文件按业务接口分片，每次请求不超过 16 MiB。

读取数据或下载文件：

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CHITANDA_TUNNEL_TOKEN}" \
  -H 'X-Target-URL: https://business.example.com/api/export' \
  --output ./response.dat \
  'https://entry.example.com/'
```

这个示例使用 GET，对方返回的内容保存到发送方的 `response.dat`。反方向发送时，选择相反方向的入口和业务地址。

## 3. 对方处理并返回

对方接口收到原来的方法、路径、查询参数和请求体，由业务代码负责保存文件、入库或其他处理。隧道负责递送请求与回复，不会自动创建业务接口。

## Chitanda 自动同步

已有 Chitanda 业务不需要手工执行每次 curl。在业务后台环境中配置三项，再重新加载后台，事件、设置和文件分片由现有同步逻辑自动发送：

```dotenv
CHITANDA_SYNC_PEERS=https://entry.example.com
CHITANDA_TUNNEL_TOKEN=本隧道令牌
CHITANDA_SYNC_TARGET=https://business.example.com
```

PEERS 是入口，TARGET 是对端原网站地址；后台自动生成 X-Target-URL。重置隧道令牌后，使用它的业务后台也要更新。业务集成补丁见 [请求头接入](../integrations/chitanda-header-url.patch)。

## 接入失败

401 检查令牌；403 检查入口权限和目标设置；404 检查真实业务接口路径；502 或超时检查节点、回源地址与证书。测活成功不代表业务已经接收和保存数据。

证书在系统设置管理，节点管理确认应用。需要指定对端实际源站 IP 时，在 URL 请求接入的“固定回源地址”填写公开 IP:端口；Host 和 TLS SNI 仍用目标 URL 的域名。目标业务需要独立 Authorization 时，通过 X-Target-Authorization 携带。
