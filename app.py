#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenVPN Admin v4 - 后端（标准库零依赖）"""
import os, re, sys, json, subprocess, base64, time, socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

EASY_RSA = os.environ.get('EASY_RSA_DIR', '/etc/openvpn/easy-rsa')
PKI = os.path.join(EASY_RSA, 'pki')
ISSUED = os.path.join(PKI, 'issued')
PRIVATE = os.path.join(PKI, 'private')
CA_CRT = os.path.join(PKI, 'ca.crt')
TA_KEY = '/etc/openvpn/server/ta.key'
STATUS_LOG = '/var/log/openvpn/openvpn-status.log'
CRL = os.path.join(PKI, 'crl.pem')
CRL_DST = '/etc/openvpn/server/crl.pem'
INDEX_TXT = os.path.join(PKI, 'index.txt')
SERVER_CONF = '/etc/openvpn/server/server.conf'
CCD_DIR = '/etc/openvpn/server/ccd'
META_FILE = '/opt/ovpn-admin/users.json'
PANEL_CONF = '/opt/ovpn-admin/settings.json'
AUDIT_LOG = '/opt/ovpn-admin/audit.log'
WEB_DIR = '/opt/ovpn-admin'
REMOTE_HOST = os.environ.get('OVPN_HOST', '')
ADMIN_USER = 'admin'
PORT = 8080
NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
SKIP_NAMES = {'server', 'OpenVPN-Home-CA'}
CLIENT_HEADER = """client
dev tun
proto {proto}
remote {host} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
"""


def run_cmd(args, cwd=None, timeout=120, stdin=None):
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, input=stdin)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except Exception as e:
        return -1, str(e)


def audit(action):
    try:
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), action))
    except Exception:
        pass


def load_meta():
    try:
        with open(META_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_meta(meta):
    tmp = META_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    os.replace(tmp, META_FILE)


def load_panel():
    defs = {'hostname': REMOTE_HOST, 'local': '', 'proto': 'udp',
            'port': '1194', 'dns': [], 'daemons': 1, 'admin_password': 'changeme',
            'groups': {}, 'auth': {'method': 'local'}}
    try:
        with open(PANEL_CONF, 'r', encoding='utf-8') as f:
            d = json.load(f)
        for k, v in defs.items():
            d.setdefault(k, v)
        return d
    except Exception:
        return dict(defs)


def save_panel(d):
    tmp = PANEL_CONF + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.replace(tmp, PANEL_CONF)


def admin_pass():
    return load_panel().get('admin_password') or 'changeme'


def read_index():
    users = {}
    try:
        with open(INDEX_TXT, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.rstrip('\n').split('\t')
                if len(parts) < 6:
                    continue
                m = re.search(r'/CN=([^/]+)$', parts[5])
                if not m or m.group(1) in SKIP_NAMES:
                    continue
                users[m.group(1)] = {'status': parts[0],
                                     'expiry': parts[1] if len(parts) > 1 else '',
                                     'revoked': parts[2] if len(parts) > 2 else ''}
    except Exception:
        pass
    return users


def read_online():
    online = {}
    try:
        with open(STATUS_LOG, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith('CLIENT_LIST,'):
                    parts = line.rstrip('\n').split(',')
                    if len(parts) >= 9:
                        online[parts[1]] = {'real': parts[2], 'virtual': parts[3],
                                            'bytes_in': parts[5], 'bytes_out': parts[6],
                                            'since': parts[7]}
    except Exception:
        pass
    return online


def read_server_conf(path=SERVER_CONF):
    conf = {}
    dns = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                k, _, v = line.partition(' ')
                if k == 'dhcp-option' and v.startswith('DNS '):
                    dns.append(v[4:])
                    continue
                conf.setdefault(k, v)
    except Exception:
        pass
    conf['_dns'] = dns
    return conf


def mask_to_cidr(mask):
    try:
        return str(sum(bin(int(o)).count('1') for o in mask.split('.')))
    except Exception:
        return '24'


def cidr_to_mask(cidr):
    try:
        n = int(cidr.split('/')[1])
        mask = (0xffffffff << (32 - n)) & 0xffffffff
        return '.'.join(str((mask >> (24 - 8 * i)) & 255) for i in range(4))
    except Exception:
        return '255.255.255.0'


def read_ccd(name):
    out = {'static_ip': '', 'routes': []}
    try:
        with open(os.path.join(CCD_DIR, name), 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith('ifconfig-push'):
                    parts = line.split()
                    if len(parts) >= 2:
                        out['static_ip'] = parts[1]
                elif line.startswith('push "route'):
                    m = re.search(r'push "route\s+([\d\.]+)\s+([\d\.]+)"', line)
                    if m:
                        ip, mask = m.groups()
                        out['routes'].append(ip + '/' + mask_to_cidr(mask))
    except Exception:
        pass
    return out


def write_ccd(name, static_ip, routes):
    lines = []
    if static_ip:
        lines.append('ifconfig-push %s 255.255.255.0' % static_ip)
    for r in routes:
        r = r.strip()
        if '/' not in r:
            r = r + '/24'
        ip, _ = r.split('/', 1)
        mask = cidr_to_mask(r)
        if re.match(r'^[\d\.]+$', ip.strip()):
            lines.append('push "route %s %s"' % (ip.strip(), mask))
    content = '\n'.join(lines)
    p = os.path.join(CCD_DIR, name)
    if content:
        rc, out = run_cmd(['sudo', 'tee', p], timeout=30, stdin=content + '\n')
        return rc == 0, out
    run_cmd(['sudo', 'rm', '-f', p], timeout=30)
    return True, ''


def list_interfaces():
    rc, out = run_cmd(['sh', '-c', "ip -o -4 addr show scope global | awk '{print $2, $4}'"],
                      timeout=15)
    ifs = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ifs.append({'iface': parts[0], 'ip': parts[1].split('/')[0]})
    return ifs


def conf_lines(src_lines, proto, port, local, dns, subnet=None, extra_push=None):
    out, dns_written, local_written = [], False, False
    for line in src_lines:
        s = line.strip()
        if s.startswith('proto '):
            out.append('proto %s' % proto)
            continue
        if s.startswith('port '):
            out.append('port %s' % port)
            continue
        if s.startswith('local '):
            if local and local != '0.0.0.0':
                out.append('local %s' % local)
            local_written = True
            continue
        if s.startswith('server ') and subnet:
            out.append('server %s' % subnet)
            continue
        if s.startswith('push "dhcp-option DNS'):
            if not dns_written:
                for d in dns:
                    out.append('push "dhcp-option DNS %s"' % d)
                dns_written = True
            continue
        out.append(line)
    if local and local != '0.0.0.0' and not local_written:
        out.insert(0, 'local %s' % local)
    if not dns_written:
        for d in dns:
            out.append('push "dhcp-option DNS %s"' % d)
    if extra_push:
        for p in extra_push:
            out.append(p)
    return out


def sync_instances(proto, port, local, dns, daemons):
    with open(SERVER_CONF, 'r', encoding='utf-8') as f:
        base = f.read().splitlines()
    plans = []
    if proto == 'both':
        cur = read_server_conf()
        mp = cur.get('proto', 'udp')
        plans.append((1, mp, port))
        p2 = 'tcp' if mp == 'udp' else 'udp'
        port2 = '443' if p2 == 'tcp' else '1194'
        plans.append((2, p2, port2))
        start_i = 3
    else:
        plans.append((1, proto, port))
        start_i = 2
    for i in range(start_i, daemons + 1):
        plans.append((i, proto, str(int(port) + (i - 1))))
    errs = []
    for n, p, pt in plans:
        path = SERVER_CONF if n == 1 else '/etc/openvpn/server/server%d.conf' % n
        content = '\n'.join(conf_lines(base, p, pt, local, dns)) + '\n'
        if os.path.exists(path):
            run_cmd(['sudo', 'cp', path, path + '.bak'], timeout=30)
        rc, o = run_cmd(['sudo', 'tee', path], timeout=30, stdin=content)
        if rc != 0:
            errs.append('instance %d write: %s' % (n, o[-150:]))
            continue
        run_cmd(['sudo', 'systemctl', 'enable', 'openvpn-server@server%d' % n], timeout=30)
        run_cmd(['sudo', 'systemctl', 'restart', 'openvpn-server@server%d' % n], timeout=60)
    for i in range(daemons + 1, 9):
        run_cmd(['sudo', 'systemctl', 'disable', '--now',
                 'openvpn-server@server%d' % i], timeout=30)
        run_cmd(['sudo', 'rm', '-f', '/etc/openvpn/server/server%d.conf' % i], timeout=15)
    if errs:
        return False, '; '.join(errs)
    rc, o = run_cmd(['sudo', 'systemctl', 'restart', 'openvpn-server@server'], timeout=60)
    return rc == 0, o


def list_instances():
    out = []
    for i in range(1, 9):
        s = 'server' if i == 1 else 'server%d' % i
        conf_path = SERVER_CONF if i == 1 else '/etc/openvpn/server/server%d.conf' % i
        if not os.path.exists(conf_path):
            continue
        rc, _ = run_cmd(['systemctl', 'is-active', 'openvpn-server@%s' % s], timeout=15)
        c = read_server_conf(conf_path)
        out.append({'name': s, 'proto': c.get('proto', ''), 'port': c.get('port', ''),
                    'server': c.get('server', ''), 'active': rc == 0})
    return out


def ensure_management():
    """确保 server.conf 有 management 接口（用于动态断开客户端）"""
    with open(SERVER_CONF, 'r', encoding='utf-8') as f:
        content = f.read()
    if 'management 127.0.0.1 7505' in content:
        return True, ''
    lines = content.splitlines()
    ins = 0
    for i, l in enumerate(lines):
        if l.strip().startswith('ca '):
            ins = i
            break
    lines.insert(ins, 'management 127.0.0.1 7505')
    rc, o = run_cmd(['sudo', 'tee', SERVER_CONF], timeout=30,
                    stdin='\n'.join(lines) + '\n')
    if rc != 0:
        return False, o[-200:]
    rc, o = run_cmd(['sudo', 'systemctl', 'restart', 'openvpn-server@server'], timeout=60)
    return rc == 0, o


def kick_user(name):
    try:
        s = socket.create_connection(('127.0.0.1', 7505), timeout=3)
        s.sendall(('kill %s\n' % name).encode())
        s.close()
        return True, ''
    except Exception as e:
        return False, str(e)


def read_vpn_logs(n=300, q=''):
    lines = []
    for f in ('/var/log/openvpn/openvpn.log', '/var/log/openvpn/server.log',
              '/var/log/syslog'):
        if os.path.exists(f):
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines += fh.read().splitlines()
            except Exception:
                pass
    try:
        with open(AUDIT_LOG, 'r', encoding='utf-8', errors='ignore') as fh:
            lines += ['[admin] ' + l for l in fh.read().splitlines()]
    except Exception:
        pass
    lines = lines[-n:]
    if q:
        lines = [l for l in lines if q in l]
    return lines


def cpu_usage():
    try:
        with open('/proc/stat') as f:
            l = f.readline().split()
        idle1, total1 = int(l[4]), sum(int(x) for x in l[1:])
        time.sleep(1)
        with open('/proc/stat') as f:
            l = f.readline().split()
        idle2, total2 = int(l[4]), sum(int(x) for x in l[1:])
        return round(100.0 * (1 - (idle2 - idle1) / (total2 - total1 or 1)), 1)
    except Exception:
        return 0


def mem_usage():
    try:
        d = {}
        for line in open('/proc/meminfo'):
            parts = line.split(':')
            if len(parts) >= 2:
                d[parts[0]] = int(parts[1].split()[0])
        return round(100.0 * (1 - d.get('MemAvailable', 0) / d.get('MemTotal', 1)), 1)
    except Exception:
        return 0


def net_rate():
    def get():
        d = {}
        try:
            for line in open('/proc/net/dev').readlines()[2:]:
                parts = line.split(':')
                if len(parts) < 2:
                    continue
                iface = parts[0].strip()
                v = parts[1].split()
                d[iface] = (int(v[0]), int(v[8]))
        except Exception:
            pass
        return d
    a = get()
    time.sleep(1)
    b = get()
    out = {}
    for k in b:
        if k in a and (k.startswith('tun') or k in ('ens160', 'eth0', 'enp0s3')):
            out[k] = {'rx': round((b[k][0] - a[k][0]) / 1024.0, 1),
                      'tx': round((b[k][1] - a[k][1]) / 1024.0, 1)}
    return out


def group_routes(name):
    meta = load_meta().get(name, {})
    g = meta.get('group', '')
    groups = load_panel().get('groups', {})
    info = groups.get(g)
    if not info or not info.get('networks'):
        return '', []
    lines = []
    for net in info['networks']:
        net = net.strip()
        if not net:
            continue
        if '/' not in net:
            net += '/24'
        ip, _ = net.split('/')
        mask = cidr_to_mask(net)
        lines.append('push "route %s %s"' % (ip.strip(), mask))
    return g, lines


def make_ovpn(name):
    conf = read_server_conf()
    port = conf.get('port', '1194')
    proto = conf.get('proto', 'udp')
    host = load_panel().get('hostname') or REMOTE_HOST
    ca = open(CA_CRT, 'r').read()
    crt = open(os.path.join(ISSUED, name + '.crt'), 'r').read()
    key = open(os.path.join(PRIVATE, name + '.key'), 'r').read()
    ta = open(TA_KEY, 'r').read()
    cfg = CLIENT_HEADER.format(proto=proto, host=host, port=port)
    _, groutes = group_routes(name)
    if groutes:
        cfg += '\n'.join(groutes) + '\n'
    cfg += '<ca>\n' + ca + '</ca>\n<cert>\n' + crt + '</cert>\n<key>\n' + key + '</key>\n<tls-crypt>\n' + ta + '</tls-crypt>\n'
    return cfg


def auth_ok(h):
    if not h:
        return False
    try:
        s, _, t = h.partition(' ')
        if s.lower() != 'basic':
            return False
        d = base64.b64decode(t.strip()).decode('utf-8')
        u, _, p = d.partition(':')
        return u == ADMIN_USER and p == admin_pass()
    except Exception:
        return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write('[%s] %s\n' % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype='application/json; charset=utf-8', headers=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode('utf-8'))

    def _err(self, msg):
        self._json(400, {'ok': False, 'error': msg})

    def _auth(self):
        if not auth_ok(self.headers.get('Authorization')):
            self._send(401, b'', headers={'WWW-Authenticate': 'Basic realm="ovpn-admin"'})
            return False
        return True

    def _read_json(self):
        try:
            ln = int(self.headers.get('Content-Length', 0))
            return json.loads(self.rfile.read(ln).decode('utf-8') or '{}')
        except Exception:
            return None

    def do_GET(self):
        if not self._auth():
            return
        path = urlparse(self.path).path
        if path == '/':
            self._send(200, open(os.path.join(WEB_DIR, 'index.html'), 'rb').read(),
                       'text/html; charset=utf-8')
            return
        if path == '/api/users':
            users = read_index()
            online = read_online()
            meta = load_meta()
            out = [{'name': n, 'status': u['status'], 'expiry': u['expiry'],
                    'revoked': u['revoked'], 'online': n in online,
                    'admin': bool(meta.get(n, {}).get('admin')),
                    'auto_login': bool(meta.get(n, {}).get('auto_login')),
                    'group': meta.get(n, {}).get('group', '')}
                   for n, u in sorted(users.items())]
            self._json(200, {'ok': True, 'users': out})
            return
        if path == '/api/status':
            online = read_online()
            rc, out = run_cmd(['openvpn', '--version'], timeout=15)
            ver = out.splitlines()[0] if rc == 0 else 'unknown'
            self._json(200, {'ok': True, 'online': online, 'version': ver,
                             'remote': load_panel().get('hostname') or REMOTE_HOST,
                             'port': read_server_conf().get('port', '1194')})
            return
        if path == '/api/server-config':
            self._json(200, {'ok': True, 'conf': read_server_conf(),
                             'online_count': len(read_online())})
            return
        if path == '/api/overview':
            conf = read_server_conf()
            p = load_panel()
            rc, _ = run_cmd(['systemctl', 'is-active', 'openvpn-server@server'], timeout=15)
            rc2, out = run_cmd(['openvpn', '--version'], timeout=15)
            ver = out.splitlines()[0] if rc2 == 0 else 'unknown'
            auth = p.get('auth', {}) or {}
            self._json(200, {'ok': True, 'overview': {
                'version': ver,
                'server_name': p.get('hostname', ''),
                'allowed': 1024,
                'active_users': len(read_online()),
                'auth_method': auth.get('method', 'local'),
                'listen_ip': p.get('local') or 'all interfaces',
                'port': conf.get('port', '1194'),
                'proto': conf.get('proto', 'udp'),
                'osi_layer': '3 (routing/NAT)',
                'vpn_on': rc == 0}})
            return
        if path == '/api/online':
            self._json(200, {'ok': True, 'online': read_online()})
            return
        if path == '/api/logs':
            q = urlparse(self.path).query
            qs = {}
            for kv in q.split('&'):
                if '=' in kv:
                    k, v = kv.split('=', 1)
                    qs[k] = unquote(v)
            n = int(qs.get('n', 300))
            self._json(200, {'ok': True, 'logs': read_vpn_logs(n, qs.get('q', ''))[-n:]})
            return
        if path == '/api/server-settings':
            p = load_panel()
            dns = p.get('dns') or []
            self._json(200, {'ok': True, 'settings': {
                'hostname': p.get('hostname', ''),
                'local': p.get('local', ''),
                'proto': p.get('proto', 'udp'),
                'port': p.get('port', '1194'),
                'dns': dns if isinstance(dns, list) else [],
                'daemons': int(p.get('daemons', 1)),
                'cpu_count': os.cpu_count() or 1,
                'interfaces': list_interfaces(),
                'instances': list_instances()}})
            return
        if path == '/api/vpn-settings':
            conf = read_server_conf()
            self._json(200, {'ok': True, 'settings': {
                'cipher': conf.get('cipher', 'AES-256-GCM'),
                'auth': conf.get('auth', 'SHA256'),
                'redirect': 'redirect-gateway' in str(conf.get('push', '')),
                'mode': '3 (routing/NAT)'}})
            return
        if path == '/api/webadmin':
            p = load_panel()
            self._json(200, {'ok': True, 'settings': {
                'username': ADMIN_USER,
                'session_timeout': 30}})
            return
        if path == '/api/groups':
            p = load_panel()
            self._json(200, {'ok': True, 'groups': p.get('groups', {})})
            return
        if path == '/api/auth-settings':
            p = load_panel()
            self._json(200, {'ok': True, 'auth': p.get('auth', {})})
            return
        if path == '/api/debug':
            tail = read_vpn_logs(80)
            svcs = {}
            for s in ('openvpn-server@server', 'ovpn-admin'):
                rc, _ = run_cmd(['systemctl', 'is-active', s], timeout=15)
                svcs[s] = rc == 0
            rc, route = run_cmd(['ip', 'route', 'show'], timeout=15)
            self._json(200, {'ok': True, 'tail': tail, 'services': svcs,
                             'routes': route if rc == 0 else ''})
            return
        if path == '/api/monitor':
            self._json(200, {'ok': True, 'monitor': {
                'cpu': cpu_usage(), 'mem': mem_usage(),
                'net': net_rate(), 'connections': len(read_online())}})
            return
        if path == '/api/backup':
            try:
                p = subprocess.run(
                    ['sh', '-c', "cd / && tar -czf - etc/openvpn/server/server*.conf "
                     "etc/openvpn/server/ccd 2>/dev/null"],
                    capture_output=True, timeout=60)
            except Exception as e:
                return self._err('backup failed: ' + str(e))
            if p.returncode != 0:
                return self._err('backup failed: ' + (p.stderr or p.stdout)[-200:])
            try:
                with open(META_FILE, 'rb') as f:
                    meta_b = f.read()
                with open(PANEL_CONF, 'rb') as f:
                    panel_b = f.read()
            except Exception as e:
                return self._err('read failed: ' + str(e))
            body = p.stdout + b'\n--META--\n' + meta_b + b'\n--PANEL--\n' + panel_b
            self._send(200, body, 'application/gzip',
                       {'Content-Disposition': 'attachment; filename="ovpn-backup.tar.gz"'})
            return
        if path == '/api/ca':
            self._json(200, {'ok': True, 'ca_info': '', 'certs': [
                {'name': n, 'status': u['status'], 'expiry': u['expiry'],
                 'revoked': u['revoked']} for n, u in sorted(read_index().items())]})
            return
        m = re.match(r'^/api/user/([A-Za-z0-9_-]+)$', path)
        if m:
            name = m.group(1)
            users = read_index()
            if name not in users:
                return self._err('user not found')
            meta = load_meta().get(name, {})
            ccd = read_ccd(name)
            self._json(200, {'ok': True, 'user': {
                'name': name, 'status': users[name]['status'],
                'expiry': users[name]['expiry'], 'revoked': users[name]['revoked'],
                'online': name in read_online(),
                'admin': bool(meta.get('admin')),
                'auto_login': bool(meta.get('auto_login')),
                'group': meta.get('group', ''),
                'password_set': bool(meta.get('password')),
                'static_ip': ccd['static_ip'], 'routes': ccd['routes']}})
            return
        if path.startswith('/api/download/'):
            name = unquote(path.rsplit('/', 1)[1])
            if not NAME_RE.match(name):
                return self._err('invalid name')
            if read_index().get(name, {}).get('status') != 'V':
                return self._err('no active certificate for %s' % name)
            try:
                cfg = make_ovpn(name)
            except Exception as e:
                return self._err('file missing: %s' % str(e))
            self._send(200, cfg.encode('utf-8'), 'application/x-openvpn-profile',
                       {'Content-Disposition': 'attachment; filename="%s.ovpn"' % name})
            return
        self._json(404, {'ok': False, 'error': 'not found'})

    def do_POST(self):
        if not self._auth():
            return
        path = urlparse(self.path).path
        data = self._read_json()
        if data is None:
            return self._err('bad json')
        if path == '/api/users':
            name = (data.get('name') or '').strip()
            if not NAME_RE.match(name):
                return self._err('name must be 1-32 chars: letters/digits/_-')
            users = read_index()
            if name in users and users[name]['status'] == 'V':
                return self._err('user %s already exists' % name)
            if name in users:
                for f, ext in (('issued', '.crt'), ('private', '.key'), ('reqs', '.req')):
                    p = os.path.join(PKI, f, name + ext)
                    if os.path.exists(p):
                        os.remove(p)
            rc, out = run_cmd(['./easyrsa', '--batch', 'build-client-full', name, 'nopass'],
                              cwd=EASY_RSA, timeout=120)
            if rc != 0:
                return self._err('easyrsa failed: ' + out[-400:])
            audit('create user %s' % name)
            self._json(200, {'ok': True, 'name': name, 'detail': out[-300:]})
            return
        m = re.match(r'^/api/user/([A-Za-z0-9_-]+)/settings$', path)
        if m:
            name = m.group(1)
            if name not in read_index():
                return self._err('user not found')
            static_ip = (data.get('static_ip') or '').strip()
            if static_ip and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', static_ip):
                return self._err('invalid static ip format (e.g. 10.8.0.101)')
            routes = data.get('routes') or []
            if isinstance(routes, str):
                routes = [r.strip() for r in re.split(r'[,\n]', routes) if r.strip()]
            bad = []
            for r in routes:
                if '/' in r:
                    ip, c = r.split('/', 1)
                    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip.strip()) or \
                       not (c.isdigit() and 1 <= int(c) <= 32):
                        bad.append(r)
                elif not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', r.strip()):
                    bad.append(r)
            if bad:
                return self._err('invalid route (use 192.168.0.0 or 192.168.0.0/24): ' + bad[0])
            ok, out = write_ccd(name, static_ip, routes)
            if not ok:
                return self._err('ccd write failed: ' + out[-200:])
            meta = load_meta()
            cur = meta.get(name, {})
            if 'password' in data:
                cur['password'] = data.get('password') or ''
            meta[name] = cur
            save_meta(meta)
            audit('update settings for %s' % name)
            self._json(200, {'ok': True, 'name': name, 'ccd': read_ccd(name)})
            return
        m = re.match(r'^/api/users/([A-Za-z0-9_-]+)/meta$', path)
        if m:
            name = m.group(1)
            meta = load_meta()
            cur = meta.get(name, {})
            for k in ('admin', 'auto_login', 'group'):
                if k in data:
                    cur[k] = data[k]
            meta[name] = cur
            save_meta(meta)
            audit('update meta %s' % name)
            self._json(200, {'ok': True, 'name': name, 'meta': cur})
            return
        if path == '/api/online/kick':
            name = (data.get('name') or '').strip()
            if name not in read_online():
                return self._err('user %s is not online' % name)
            ok, o = ensure_management()
            if not ok:
                return self._err('management setup failed: ' + o[-200:])
            ok, o = kick_user(name)
            if not ok:
                return self._err('kick failed: ' + o[-200:])
            audit('kick %s' % name)
            self._json(200, {'ok': True, 'name': name})
            return
        if path == '/api/vpn/control':
            act = (data.get('action') or '').strip()
            if act not in ('start', 'stop', 'restart'):
                return self._err('action must be start/stop/restart')
            rc, o = run_cmd(['sudo', 'systemctl', act, 'openvpn-server@server'], timeout=60)
            if rc != 0:
                return self._err('vpn %s failed: %s' % (act, o[-200:]))
            audit('vpn %s' % act)
            self._json(200, {'ok': True, 'action': act})
            return
        if path == '/api/server-settings':
            proto = (data.get('proto') or '').strip().lower()
            port = (data.get('port') or '').strip()
            hostname = (data.get('hostname') or '').strip()
            local = (data.get('local') or '').strip()
            dns = data.get('dns') or []
            if isinstance(dns, str):
                dns = [d.strip() for d in re.split(r'[,\n]', dns) if d.strip()]
            daemons = str(data.get('daemons', 1)).strip()
            cpu = os.cpu_count() or 4
            if proto not in ('udp', 'tcp', 'both'):
                return self._err('proto must be udp, tcp or both')
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                return self._err('invalid port')
            if not daemons.isdigit() or not (1 <= int(daemons) <= cpu):
                return self._err('daemons must be 1-%d (CPU cores)' % cpu)
            if proto == 'both' and int(daemons) < 2:
                daemons = '2'  # Both 双实例至少需要 2 个进程，自动提升
            if hostname and not re.match(r'^[A-Za-z0-9\.\-]+$', hostname):
                return self._err('invalid hostname (letters/digits/./-)')
            if local and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', local):
                return self._err('invalid interface address')
            ok, o = sync_instances(proto, port, local, dns, int(daemons))
            if not ok:
                return self._err('write/restart failed: ' + o[-300:])
            p = load_panel()
            p.update({'hostname': hostname, 'local': local, 'proto': proto,
                      'port': port, 'dns': dns, 'daemons': int(daemons)})
            save_panel(p)
            audit('network settings saved')
            self._json(200, {'ok': True, 'settings': p})
            return
        if path == '/api/vpn-settings':
            cipher = (data.get('cipher') or '').strip()
            auth = (data.get('auth') or '').strip()
            redirect = bool(data.get('redirect'))
            if cipher not in ('AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305'):
                return self._err('invalid cipher')
            if auth not in ('SHA256', 'SHA512', 'SHA1'):
                return self._err('invalid auth')
            with open(SERVER_CONF, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
            out = []
            push_lines = []
            for line in lines:
                s = line.strip()
                if s.startswith('cipher '):
                    out.append('cipher %s' % cipher)
                    continue
                if s.startswith('auth '):
                    out.append('auth %s' % auth)
                    continue
                if s.startswith('push "redirect-gateway'):
                    if redirect:
                        push_lines.append(line)
                    continue
                if s.startswith('push "route'):
                    if redirect:
                        push_lines.append(line)
                    continue
                out.append(line)
            if redirect and not push_lines:
                out.append('push "redirect-gateway def1 bypass-dhcp"')
            content = '\n'.join(out) + '\n'
            rc, o = run_cmd(['sudo', 'tee', SERVER_CONF], timeout=30, stdin=content)
            if rc != 0:
                return self._err('write failed: ' + o[-200:])
            rc, o = run_cmd(['sudo', 'systemctl', 'restart', 'openvpn-server@server'], timeout=60)
            if rc != 0:
                return self._err('restart failed: ' + o[-200:])
            audit('vpn settings saved')
            self._json(200, {'ok': True})
            return
        if path == '/api/webadmin':
            newp = (data.get('password') or '').strip()
            if len(newp) < 6:
                return self._err('password must be at least 6 chars')
            p = load_panel()
            p['admin_password'] = newp
            save_panel(p)
            audit('admin password changed')
            self._json(200, {'ok': True})
            return
        if path == '/api/groups':
            action = (data.get('action') or 'save').strip()
            gname = (data.get('name') or '').strip()
            if not NAME_RE.match(gname):
                return self._err('invalid group name')
            p = load_panel()
            groups = p.get('groups', {})
            if action == 'delete':
                groups.pop(gname, None)
            else:
                networks = data.get('networks') or []
                if isinstance(networks, str):
                    networks = [n.strip() for n in re.split(r'[,\n]', networks) if n.strip()]
                groups[gname] = {'desc': (data.get('desc') or '').strip(),
                                 'networks': networks,
                                 'bandwidth': (data.get('bandwidth') or '').strip()}
            p['groups'] = groups
            save_panel(p)
            audit('group %s %s' % (gname, action))
            self._json(200, {'ok': True, 'groups': groups})
            return
        if path == '/api/auth-settings':
            method = (data.get('method') or 'local').strip()
            if method not in ('local', 'pam', 'radius', 'ldap', 'saml'):
                return self._err('invalid auth method')
            p = load_panel()
            cur = p.get('auth', {}) or {}
            cur['method'] = method
            for key in ('radius_host', 'radius_secret', 'radius_port',
                        'ldap_host', 'ldap_bind', 'ldap_base',
                        'saml_idp', 'saml_entity'):
                if key in data:
                    cur[key] = data[key]
            p['auth'] = cur
            save_panel(p)
            audit('auth settings saved: %s' % method)
            self._json(200, {'ok': True, 'auth': cur})
            return
        if path == '/api/servers':
            action = (data.get('action') or '').strip()
            if action == 'add':
                port = (data.get('port') or '').strip()
                subnet = (data.get('subnet') or '').strip()
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    return self._err('invalid port')
                if not re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+\d{1,3}(\.\d{1,3}){3}$', subnet):
                    return self._err('subnet must be like 10.9.0.0 255.255.255.0')
                n = None
                for i in range(2, 9):
                    if not os.path.exists('/etc/openvpn/server/server%d.conf' % i):
                        n = i
                        break
                if n is None:
                    return self._err('too many instances (max 8)')
                with open(SERVER_CONF, 'r', encoding='utf-8') as f:
                    base = f.read().splitlines()
                conf = read_server_conf()
                lines = conf_lines(base, conf.get('proto', 'udp'), port,
                                   load_panel().get('local', ''), [], subnet=subnet)
                content = '\n'.join(lines) + '\n'
                p = '/etc/openvpn/server/server%d.conf' % n
                rc, o = run_cmd(['sudo', 'tee', p], timeout=30, stdin=content)
                if rc != 0:
                    return self._err('write failed: ' + o[-200:])
                run_cmd(['sudo', 'systemctl', 'enable', 'openvpn-server@server%d' % n], timeout=30)
                rc, o = run_cmd(['sudo', 'systemctl', 'restart',
                                 'openvpn-server@server%d' % n], timeout=60)
                if rc != 0:
                    return self._err('start failed: ' + o[-200:])
                audit('add instance server%d port %s subnet %s' % (n, port, subnet))
                self._json(200, {'ok': True, 'instances': list_instances()})
                return
            if action == 'remove':
                name = (data.get('name') or '').strip()
                if not re.match(r'^server\d+$', name) or name == 'server':
                    return self._err('cannot remove main instance')
                run_cmd(['sudo', 'systemctl', 'disable', '--now',
                         'openvpn-server@%s' % name], timeout=30)
                run_cmd(['sudo', 'rm', '-f',
                         '/etc/openvpn/server/%s.conf' % name], timeout=15)
                audit('remove instance %s' % name)
                self._json(200, {'ok': True, 'instances': list_instances()})
                return
            return self._err('action must be add/remove')
        self._json(404, {'ok': False, 'error': 'not found'})

    def do_DELETE(self):
        if not self._auth():
            return
        path = urlparse(self.path).path
        m = re.match(r'^/api/users/([A-Za-z0-9_-]+)/remove$', path)
        if m:
            return self._revoke(m.group(1), remove=True)
        m = re.match(r'^/api/users/([A-Za-z0-9_-]+)$', path)
        if m:
            return self._revoke(m.group(1), remove=False)
        self._json(404, {'ok': False, 'error': 'not found'})

    def _revoke(self, name, remove=False):
        if not NAME_RE.match(name):
            return self._err('invalid name')
        if name not in read_index():
            return self._err('user not found')
        rc, out = run_cmd(['./easyrsa', '--batch', 'revoke', name],
                          cwd=EASY_RSA, timeout=120)
        if rc != 0:
            return self._err('revoke failed: ' + out[-400:])
        run_cmd(['./easyrsa', 'gen-crl'], cwd=EASY_RSA, timeout=120)
        rc, out2 = run_cmd(['sudo', 'cp', CRL, CRL_DST], timeout=30)
        if rc != 0:
            return self._err('crl copy failed: ' + out2[-200:])
        run_cmd(['sudo', 'systemctl', 'restart', 'openvpn-server@server'], timeout=60)
        detail = 'revoked'
        audit('revoke %s' % name)
        if remove:
            for f, ext in (('issued', '.crt'), ('private', '.key'), ('reqs', '.req')):
                p = os.path.join(PKI, f, name + ext)
                if os.path.exists(p):
                    os.remove(p)
            run_cmd(['sudo', 'rm', '-f', os.path.join(CCD_DIR, name)], timeout=30)
            meta = load_meta()
            if name in meta:
                del meta[name]
                save_meta(meta)
            detail = 'removed'
        self._json(200, {'ok': True, 'name': name, 'action': detail,
                         'revoked': not remove})


if __name__ == '__main__':
    srv = HTTPServer(('0.0.0.0', PORT), Handler)
    print('ovpn-admin v4 listening on 0.0.0.0:%d' % PORT, flush=True)
    srv.serve_forever()
