# 第三方说明

- Chitanda 上游：`https://github.com/chitanda-project/chitanda`，固定提交 `2926cf2c41c85d2177536a4ba2d9931f1ec675f9`。构建时获取，不将完整上游源码复制进本仓库；固定提交许可证保存在 `third_party/chitanda-LICENSE`（PolyForm Noncommercial 1.0.0），构建和使用须遵守原许可证与通知。
- 2.4.0 的 `patches/chitanda-tls-observer.patch` 修改上述上游 SDK，新增只读握手观察能力；修改文件及原版权归属在补丁中保留，构建会校验其与固定提交的兼容性。原信任链与主机名验证未更改。
- Node.js 依赖 sharp 及测试依赖 Playwright：各自许可证与原生组件通知由 npm 包提供，版本由锁文件固定。
- Go 传递依赖：由上游固定提交及其 `go.mod` / `go.sum` 管理，各依赖保留原有许可证。
- 界面品牌图标来自 Chitanda 项目，保留原权利；私有仓库不表示授予第三方使用或再分发权。
