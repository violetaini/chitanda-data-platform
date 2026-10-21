"""Register an existing identity vhost with Baota WAF, preserving other sites."""
import copy
import datetime
import json
import pathlib
import re
import sqlite3
import subprocess


def apply(kind, backup):
    assert kind in ('sso', 'datahub')
    name = kind + '.chitanda.net'
    root = pathlib.Path('/www/server/btwaf')
    nginx = pathlib.Path('/www/server/panel/vhost/nginx')
    expected_wrapper = '/www/server/btwaf/chitanda-' + kind + '-access.lua'
    if ('access_by_lua_file ' + expected_wrapper + ';') in (nginx / (name + '.conf')).read_text():
        current = json.loads((root / 'site.json').read_text())[name]
        assert current['open'] and current['idc']
        return {'site': name, 'idc': True, 'subnetPolicy': True, 'verifiedSource': True, 'nativeBaotaWaf': True, 'alreadyApplied': True}
    backup = pathlib.Path(backup)
    backup.mkdir(parents=True, exist_ok=True, mode=0o700)
    saved = {}

    def put(file, value):
        file = pathlib.Path(file)
        old = file.read_bytes() if file.exists() else None
        saved[str(file)] = old
        if old is not None:
            (backup / (file.name + '.before')).write_bytes(old)
        file.write_bytes(value)
        file.chmod(0o600 if file.name == '0.datahub-access.conf' else 0o644)

    site_db = pathlib.Path('/www/server/panel/data/db/site.db')
    assert site_db.exists()
    db = sqlite3.connect(site_db)
    site_id = None
    try:
        profiles = json.loads((root / 'site.json').read_text())
        profile = copy.deepcopy(profiles.get(name) or next(iter(profiles.values())))
        profile.update(open=True, log=True, idc=True, cdn=True, cdn_header=['x-chitanda-verified-ip'])
        # Keep browser challenges out of machine exchanges; rate limits are applied independently.
        profile['cc']['open'] = False
        profile['smart_cc']['open'] = False
        profile['crawler'] = copy.deepcopy(profile.get('crawler', {}))
        for key in ('html', 'html_fast', 'js', 'picture'):
            profile['crawler'][key] = False
        profile['drop_abroad'] = False
        profile['drop_china'] = False
        profiles[name] = profile
        custom = json.loads((root / 'rule/customize.json').read_text())
        rule_id = '2026102101' if kind == 'sso' else '2026102102'
        conditions = []
        for ip in ['110.42.32.161', '168.138.209.1', '127.0.0.1', '::1']:
            conditions.append({'type': 'option', 'logic': '', 'children': [], 'option': {'type': 'ip', 'operator': 'eq', 'left_factor': '', 'right_factor': ip}})
        if kind == 'datahub':
            conditions.append({'type': 'option', 'logic': '', 'children': [], 'option': {'type': 'uri', 'operator': 'regexp', 'left_factor': '', 'right_factor': r'^/(?:transit-node(?:/|$)|install\.sh$)'}})
        if kind == 'sso':
            conditions.append({'type': 'block', 'logic': 'and', 'option': None, 'children': [{'type': 'option', 'logic': '', 'children': [], 'option': {'type': 'ip', 'operator': 'eq', 'left_factor': '', 'right_factor': '47.243.148.109'}}, {'type': 'option', 'logic': '', 'children': [], 'option': {'type': 'uri', 'operator': 'regexp', 'left_factor': '', 'right_factor': r'^/(?:oauth/(?:token|introspect|revoke)|\.well-known/(?:jwks\.json|openid-configuration))$'}}]})
        custom['rules'][rule_id] = {'id': rule_id, 'name': 'Chitanda 身份服务必要机器通信', 'servers': [name], 'status': 1, 'is_global': 0, 'priority': 0, 'root': {'type': 'block', 'logic': 'or', 'option': None, 'children': conditions}, 'action': {'type': 'allow', 'response': {'type': '', 'response_id': 0, 'status': 0, 'headers': {}, 'body': ''}, 'cc': None, 'block_time': 0}, 'src': 0, 'execute_phase': 'access', 'create_time': int(datetime.datetime.now().timestamp())}
        custom[name] = [rule_id] + [v for v in custom.get(name, []) if v != rule_id]
        domains = json.loads((root / 'domains.json').read_text())
        if not any(v['name'] == name for v in domains):
            domains.append({'name': name, 'domains': [name]})
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT id FROM sites WHERE name=?', (name,)).fetchone():
            columns = [c[1] for c in db.execute('PRAGMA table_info(sites)') if c[1] != 'id']
            values = dict(name=name, path='/opt/chitanda-sso/public' if kind == 'sso' else '/opt/chitanda-transit-panel/public', status='1', index='index.html', ps='Chitanda 统一登录' if kind == 'sso' else 'Chitanda 数据中台', addtime=now, type_id=0, edate='0000-00-00', project_type='PHP', project_config='{}', rname=name, stop=0)
            site_id = db.execute('INSERT INTO sites (' + ','.join('"' + c + '"' for c in columns) + ') VALUES (' + ','.join('?' for _ in columns) + ')', [values.get(c, '') for c in columns]).lastrowid
            assert not db.execute('SELECT id FROM domain WHERE name=?', (name,)).fetchone()
            db.execute('INSERT INTO domain(pid,name,port,addtime) VALUES(?,?,80,?)', (site_id, name, now))
        for file, value in [(root / 'site.json', profiles), (root / 'rule/customize.json', custom), (root / 'domains.json', domains)]:
            put(file, json.dumps(value, ensure_ascii=False).encode())
        variable = '$datahub_client_ip' if kind == 'datahub' else '$remote_addr'
        wrapper = pathlib.Path('/www/server/btwaf/chitanda-' + kind + '-access.lua')
        put(wrapper, pathlib.Path(__file__).with_name('identity-waf.lua').read_bytes())
        put(root / 'chitanda-identity-access.json', json.dumps({'kind': kind, 'sourceVariable': 'datahub_client_ip' if kind == 'datahub' else 'remote_addr', 'serverSources': ['110.42.32.161', '168.138.209.1', '127.0.0.1', '::1'], 'backchannelSource': '47.243.148.109'}).encode())
        vhost = nginx / (name + '.conf')
        text = vhost.read_text()
        marker = '    server_name ' + name + ';'
        assert text.count(marker) in (1,2) and 'access_by_lua' not in text
        text = text.replace(marker, marker + '\n    access_by_lua_file ' + str(wrapper) + ';')
        if kind == 'datahub':
            access = nginx / '0.datahub-access.conf'
            original = access.read_text()
            # Preserve the private edge proof and verified client map, remove the old whitelist.
            revised, count = re.subn(r'geo\s+\$remote_addr\s+\$datahub_direct_admin\s*\{[^{}]*\}\s*', '', original)
            assert count == 1
            revised, count = re.subn(r'map\s+"[^"\n]*"\s+\$datahub_cdn_admin\s*\{[^{}]*\}\s*', '', revised)
            assert count == 1
            geo = 'geo $datahub_client_ip $datahub_admin_allowed {\n    default 1;\n    110.42.32.0/24 0;\n    168.138.209.0/24 0;\n    110.42.32.161/32 1;\n    168.138.209.1/32 1;\n    127.0.0.1/32 1;\n    ::1/128 1;\n}'
            revised, count = re.subn(r'map\s+"[^"\n]*"\s+\$datahub_admin_allowed\s*\{[^{}]*\}', lambda m: geo, revised)
            assert count == 1
            put(access, revised.encode())
        else:
            text = text.replace('client_max_body_size 16m;', '''client_max_body_size 64k;
    client_header_timeout 15s;
    client_body_timeout 15s;
    send_timeout 30s;
    limit_req_status 429;
    limit_conn_status 429;
    limit_conn sso_connections 24;
    if ($sso_source_allowed = 0) { return 403; }''')
            text = text.replace('    location / {', '    location / {\n        limit_req zone=sso_requests burst=60 nodelay;')
            text = text.replace('proxy_connect_timeout 30s;', 'proxy_connect_timeout 5s;')
            proxy = text[text.index('        proxy_pass http://127.0.0.1:9787;'):text.index('        proxy_buffering off;')]
            login = '    location = /api/auth/login {\n        limit_req zone=sso_login burst=5 nodelay;\n' + proxy + '    }\n'
            text = text.replace('    location / {', login + '    location / {', 1)
            limits = '''limit_req_zone $binary_remote_addr zone=sso_requests:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=sso_login:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=sso_connections:10m;
geo $remote_addr $sso_source_allowed {
    default 1;
    110.42.32.0/24 0;
    168.138.209.0/24 0;
    110.42.32.161/32 1;
    168.138.209.1/32 1;
    127.0.0.1/32 1;
    ::1/128 1;
}
'''
            put(nginx / '0.sso-access.conf', limits.encode())
        put(vhost, text.encode())
        subprocess.run(['/www/server/nginx/sbin/nginx', '-t'], capture_output=True, check=True)
        db.commit()
        subprocess.run(['/www/server/nginx/sbin/nginx', '-s', 'reload'], capture_output=True, check=True)
        (backup / 'access-policy-applied.json').write_text(json.dumps({'site': name, 'createdSiteId': site_id, 'files': list(saved)}))
        return {'site': name, 'idc': True, 'subnetPolicy': True, 'verifiedSource': True, 'nativeBaotaWaf': True}
    except BaseException:
        db.rollback()
        if site_id:
            db.execute('DELETE FROM domain WHERE pid=?', (site_id,))
            db.execute('DELETE FROM sites WHERE id=? AND name=?', (site_id, name))
            db.commit()
        for name, old in saved.items():
            file = pathlib.Path(name)
            if old is None:
                file.unlink(missing_ok=True)
            else:
                file.write_bytes(old)
        subprocess.run(['/www/server/nginx/sbin/nginx', '-t'], capture_output=True, check=True)
        subprocess.run(['/www/server/nginx/sbin/nginx', '-s', 'reload'], capture_output=True, check=True)
        raise
    finally:
        db.close()
