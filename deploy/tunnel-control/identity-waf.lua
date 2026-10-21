-- Site-scoped source policy before vendor whitelists. Machine routes require app credentials.
local file = io.open('/www/server/btwaf/chitanda-identity-access.json', 'rb')
if not file then return ngx.exit(503) end
local encoded = file:read('*a'); file:close()
local ok, policy = pcall(Json.decode, encoded)
if not ok or type(policy) ~= 'table' then return ngx.exit(503) end
local source = ngx.var[policy.sourceVariable]
if not source or source == '' then return ngx.exit(403) end
ngx.req.set_header('X-Chitanda-Verified-IP', source)
local uri = ngx.var.uri
local machine = false
for _, ip in ipairs(policy.serverSources or {}) do if source == ip then machine = true end end
if policy.kind == 'datahub' and (uri:sub(1,14) == '/transit-node/' or uri == '/install.sh') then machine = true end
if policy.kind == 'sso' and source == policy.backchannelSource then
    if uri == '/oauth/token' or uri == '/oauth/introspect' or uri == '/oauth/revoke' or uri == '/.well-known/jwks.json' or uri == '/.well-known/openid-configuration' then machine = true end
end
if machine then
    ngx.ctx.proxy = true
    ngx.ctx.server_name = ngx.var.server_name
    ngx.ctx.ip = source
    ngx.ctx.time = ngx.time()
    return
end
local _, _, _, tag = IpInfo.get_country(source)
if tag == 'IDC' then
    ngx.ctx.proxy = true
    ngx.ctx.server_name = ngx.var.server_name
    ngx.ctx.ip = source
    ngx.ctx.time = ngx.time()
    ngx.var.waf2monitor_blocked = 'IDC拦截'
    ngx.status = 403
    ngx.header['Content-Type'] = 'text/plain; charset=utf-8'
    ngx.say('访问被拒绝')
    return ngx.exit(403)
end
-- Administrative JSON contains URLs, certificate material and command-like text.
-- The app enforces identity, origin, CSRF, scopes, schema and body/rate limits.
-- Keep the IDC gate above, while avoiding the vendor body parser consuming API bodies.
if (policy.kind == 'datahub' and uri:sub(1,12) == '/tunnel/api/') or
   (policy.kind == 'sso' and uri:sub(1,5) == '/api/') then
    ngx.ctx.proxy = true
    ngx.ctx.server_name = ngx.var.server_name
    ngx.ctx.ip = source
    ngx.ctx.time = ngx.time()
    return
end
dofile('/www/server/btwaf/waf.lua')
