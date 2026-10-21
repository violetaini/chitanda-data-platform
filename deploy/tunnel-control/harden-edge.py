"""Apply admission limits without replacing private source identity or TLS settings."""
import argparse
import datetime
import pathlib
import re
import shutil
import subprocess


def harden(text):
    # A child add_header disables inheritance of the server's HSTS and other
    # security headers. The server and application already send no-store.
    text = text.replace('        add_header Cache-Control "private, no-store, max-age=0" always;\n', '')
    if '# BEGIN Chitanda admission limits' in text:
        return text
    if text.count('client_max_body_size 3m;') != 1 or 'X-Real-IP $datahub_client_ip;' not in text:
        raise ValueError('Unrecognized Datahub vhost; review the configuration before applying')
    settings = '''client_max_body_size 3m;
    # BEGIN Chitanda admission limits
    limit_req_status 429;
    limit_conn_status 429;
    limit_conn datahub_connections 32;
    client_body_timeout 15s;
    client_header_timeout 15s;
    send_timeout 30s;
    # END Chitanda admission limits'''
    text = text.replace('client_max_body_size 3m;', settings, 1)

    def location(match):
        prefix, name = match.group(1), match.group(2)
        zone = 'datahub_node_rate' if '/transit-node/' in name or '/install.sh' in name else 'datahub_control_rate' if '/tunnel' in name else None
        if not zone:
            return match.group(0)
        burst = 100 if zone == 'datahub_node_rate' else 60
        return prefix + '\n        limit_req zone=' + zone + ' burst=' + str(burst) + ' nodelay;'

    text = re.sub(r'(^[ \t]*location[ \t]+([^\n{]+)\{)[ \t]*$', location, text, flags=re.M)
    login = '''    location = /tunnel/api/login {
        if ($datahub_admin_allowed = 0) { return 403; }
        limit_except POST { deny all; }
        limit_req zone=datahub_login_rate burst=5 nodelay;
        client_max_body_size 32k;
        proxy_pass http://127.0.0.1:5092;
        proxy_set_header Host datahub.chitanda.net;
        proxy_set_header X-Real-IP $datahub_client_ip;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 15s;
    }
'''
    if 'location = /tunnel/api/login' in text:
        raise ValueError('Existing login location needs manual review')
    marker = '    location ^~ /tunnel/ {'
    if text.count(marker) != 1:
        raise ValueError('Missing management location')
    return text.replace(marker, login + marker, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vhost', required=True, type=pathlib.Path)
    parser.add_argument('--http-output', required=True, type=pathlib.Path)
    parser.add_argument('--nginx', default='/www/server/nginx/sbin/nginx')
    args = parser.parse_args()
    before = args.vhost.read_bytes()
    limits = pathlib.Path(__file__).with_name('datahub-abuse-limits.conf').read_bytes()
    previous = args.http_output.read_bytes() if args.http_output.exists() else None
    if previous is not None and previous != limits:
        raise ValueError('Existing HTTP limits differ; review before applying')
    hardened = harden(before.decode()).encode()
    if hardened == before and previous == limits:
        print('Datahub admission limits already applied')
        return
    backup = args.vhost.with_name(args.vhost.name + '.before-admission-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    shutil.copy2(args.vhost, backup)
    try:
        args.http_output.write_bytes(limits)
        args.http_output.chmod(0o644)
        args.vhost.write_bytes(hardened)
        subprocess.run([args.nginx, '-t'], capture_output=True, check=True)
        subprocess.run([args.nginx, '-s', 'reload'], capture_output=True, check=True)
    except BaseException:
        args.vhost.write_bytes(before)
        if previous is None:
            args.http_output.unlink(missing_ok=True)
        else:
            args.http_output.write_bytes(previous)
        subprocess.run([args.nginx, '-t'], capture_output=True, check=False)
        raise
    print('Datahub admission limits applied; previous vhost saved at ' + str(backup))


if __name__ == '__main__':
    main()
