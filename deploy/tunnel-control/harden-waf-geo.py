"""Fix WAF country/tag caching without publishing vendor implementation."""
import datetime
import pathlib
import shutil
import re


def harden(file):
    file = pathlib.Path(file)
    text = file.read_text()
    if '-- Chitanda: preserve IDC tags for all address families' in text:
        return False
    start = text.index('function ipinfo.get_country(ip)')
    end = text.index('function ipinfo.bt_ip_filter(', start)
    replacement = '''-- Chitanda: preserve IDC tags for all address families
function ipinfo.get_country(ip)
    local key = "identity-geo-v2:" .. ip
    local cached = ngx.shared.ipinfo:get(key)
    if cached then
        local values = Public.split(cached, "|")
        return values[1] or "", values[2] or "", values[3] or "", values[4] or "", values[5] or ""
    end
    local result = ipinfo.get_ip_position_data(ip)
    if type(result) ~= "table" or type(result.country) ~= "table" then return "", "", "", "", "" end
    local value = result.country
    local values = {}
    for _, field in ipairs({"country", "province", "city", "tag", "spider"}) do
        values[#values + 1] = type(value[field]) == "string" and value[field] or ""
    end
    ngx.shared.ipinfo:set(key, table.concat(values, "|"), 600)
    return unpack(values)
end

'''
    updated = text[:start] + replacement + text[end:]
    updated, count = re.subn(r'(ngx\.ctx\.iplong\s*=\s*0\s*\n[ \t]*if country then\s*\n([ \t]*)ngx\.ctx\.country\s*=\s*country)',lambda m:m[0]+''.join('\n'+m[2]+'ngx.ctx.'+k+'='+v for k,v in [('ip_province','province'),('ip_city','city'),('ip_tag','tag'),('spider','spider')]),updated,count=1)
    assert count == 1
    backup = file.with_name(file.name + '.before-identity-geo-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    shutil.copy2(file, backup)
    file.write_text(updated)
    return True
