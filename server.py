#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   CYBERSECURITY WORKSHOP — Flask + Flask-SocketIO Server        ║
║                                                                  ║
║   Port 8080  BrewNet Cafe              HTTP                     ║
║   Port 8081  SecureBank SOC Race       HTTP + WebSocket         ║
║   Port 8443  SecureBank HTTPS Portal   HTTPS                    ║
╚══════════════════════════════════════════════════════════════════╝

Usage:  python server.py
Deps:   pip install flask flask-socketio eventlet
"""

# eventlet monkey-patch MUST be first — before any stdlib imports
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning, module='eventlet')
import eventlet
eventlet.monkey_patch()

import io as _io
import os
import time
import uuid
import socket as _sock
import threading
import subprocess
import logging
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from flask_socketio import SocketIO, emit, join_room

# ── Silence noisy loggers ─────────────────────────────────────────
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('engineio').setLevel(logging.ERROR)
logging.getLogger('socketio').setLevel(logging.ERROR)

# ── Paths ─────────────────────────────────────────────────────────
BASE   = Path(__file__).parent.resolve()
TMPL   = BASE / 'templates'
STATIC = BASE / 'static'
CERTS  = BASE / 'certs'
CERT   = CERTS / 'workshop.crt'
KEY    = CERTS / 'workshop.key'
CFG    = CERTS / 'openssl.cnf'

# ── Ports ─────────────────────────────────────────────────────────
BREWNET_PORT = 8080
SECBANK_PORT = 8081
HTTPS_PORT   = 8443

# ── Flask apps ────────────────────────────────────────────────────
_kw = dict(template_folder=str(TMPL), static_folder=str(STATIC))
brewnet_app = Flask('brewnet',    **_kw)
secbank_app = Flask('securebank', **_kw)
https_app   = Flask('https',      **_kw)

brewnet_app.secret_key = os.urandom(24)
secbank_app.secret_key = os.urandom(24)
https_app.secret_key   = os.urandom(24)

socketio = SocketIO(
    secbank_app,
    cors_allowed_origins='*',
    async_mode='eventlet',
    logger=False,
    engineio_logger=False,
)

# ══════════════════════════════════════════════════════════════════
#  GAME STATE
# ══════════════════════════════════════════════════════════════════

game: dict = {
    'status':         'lobby',   # lobby | running | ended
    'timer_duration': 600,       # seconds
    'timer_start':    None,      # float timestamp
    'correct': {
        'username': 'soc.admin.rowe',
        'password': 'Sb@nk#S3cure99',
        'endpoint': '/bank/login',
    },
    'students':     {},           # student_id → student_dict
    'teacher_sid':  None,         # socket sid of teacher
    'winner_id':    None,         # student_id of first correct
    'rounds':       [],           # completed round summaries
    'round_number': 0,            # rounds completed so far
}

_lock = threading.Lock()

# Bidirectional socket-id ↔ student-id maps
_sid_to_student: dict[str, str] = {}
_student_to_sid: dict[str, str] = {}


# ── Serialisers ───────────────────────────────────────────────────

def _lobby_payload() -> list:
    return sorted(
        [
            {
                'id':          sid,
                'name':        s['name'],
                'employee_id': s['employee_id'],
                'joined_at':   s['joined_at_str'],
                'status':      s['status'],
            }
            for sid, s in game['students'].items()
        ],
        key=lambda x: x['joined_at'],
    )


def _leaderboard_payload() -> list:
    def _key(e):
        if e['status'] == 'correct': return (0, e['elapsed_secs'])
        if e['status'] == 'wrong':   return (1, e['elapsed_secs'])
        return (2, 0)

    entries = [
        {
            'id':          sid,
            'name':        s['name'],
            'status':      s['status'],
            'elapsed':     s.get('elapsed_str', ''),
            'elapsed_secs':s.get('elapsed_secs', 999_999),
            'attempts':    s.get('attempts', 0),
            'is_winner':   sid == game['winner_id'],
        }
        for sid, s in game['students'].items()
    ]
    entries.sort(key=_key)
    return entries


def _elapsed_str(secs: int) -> str:
    m, s = divmod(int(secs), 60)
    return f"{m}m {s:02d}s"


# ══════════════════════════════════════════════════════════════════
#  BREWNET ROUTES  (port 8080, plain HTTP)
# ══════════════════════════════════════════════════════════════════

@brewnet_app.route('/')
def bn_index():
    return render_template('brewnet.html')


@brewnet_app.route('/login', methods=['POST'])
def bn_login():
    user = request.form.get('username', '').strip()
    pwd  = request.form.get('password', '').strip()
    role = request.form.get('role', 'barista')

    # Print captured credentials to the presenter's terminal
    R = '\033[91m'; Y = '\033[93m'; B = '\033[1m'; X = '\033[0m'; D = '\033[2m'
    print(f"\n{R}{'━'*58}{X}")
    print(f"{R}{B}  ⚠   HTTP CREDENTIALS CAPTURED IN PLAINTEXT   ⚠{X}")
    print(f"{R}{'━'*58}{X}")
    print(f"  Source IP : {request.remote_addr}")
    print(f"  Endpoint  : POST /login  (HTTP — unencrypted)")
    print(f"  Username  : {Y}{user}{X}")
    print(f"  Password  : {Y}{pwd}{X}")
    print(f"  Role      : {role}")
    print(f"  Raw body  : {D}{request.get_data(as_text=True)[:200]}{X}")
    print(f"{R}{'━'*58}{X}\n")

    resp = make_response(redirect(url_for('bn_dashboard')))
    resp.set_cookie('bn_user', user or 'guest', httponly=True, samesite='Lax')
    resp.set_cookie('bn_role', role,             httponly=True, samesite='Lax')
    return resp


@brewnet_app.route('/dashboard')
def bn_dashboard():
    user = request.cookies.get('bn_user', '')
    role = request.cookies.get('bn_role', 'barista')
    if not user:
        return redirect(url_for('bn_index'))
    return render_template('brewnet_dashboard.html', username=user, role=role)


# ══════════════════════════════════════════════════════════════════
#  SECUREBANK ROUTES  (port 8081, HTTP + WebSocket)
# ══════════════════════════════════════════════════════════════════

@secbank_app.route('/join')
def sb_join():
    return render_template('securebank_join.html', port=SECBANK_PORT)


@secbank_app.route('/game')
def sb_game():
    return render_template('securebank_game.html', port=SECBANK_PORT)


@secbank_app.route('/bank/login', methods=['POST'])
def sb_bank_login():
    """Real HTTP POST login — credentials visible in Wireshark as form data."""
    username   = request.form.get('username',   '').strip()
    password   = request.form.get('password',   '').strip()
    student_id = request.form.get('student_id', '').strip()

    R = '\033[91m'; Y = '\033[93m'; B = '\033[1m'; X = '\033[0m'; D = '\033[2m'
    c          = game['correct']
    is_correct = (username == c['username'] and password == c['password'])
    is_teacher = not student_id or student_id not in game['students']
    mark       = '\033[2mN/A (instructor)\033[0m' if is_teacher else ('✓ CORRECT' if is_correct else '✗ WRONG')
    print(f"\n{R}{'━'*58}{X}")
    print(f"{R}{B}  ⚠   SECUREBANK — HTTP CREDENTIALS CAPTURED   ⚠{X}")
    print(f"{R}{'━'*58}{X}")
    print(f"  Source IP : {request.remote_addr}")
    print(f"  Endpoint  : POST /bank/login  (HTTP — unencrypted)")
    print(f"  Username  : {Y}{username}{X}")
    print(f"  Password  : {Y}{password}{X}")
    print(f"  Result    : {mark}")
    print(f"  Raw body  : {D}{request.get_data(as_text=True)[:200]}{X}")
    print(f"{R}{'━'*58}{X}\n")

    if game['status'] != 'running':
        return jsonify({'correct': False, 'message': 'The challenge is not currently active.'})

    elapsed_secs = int(time.time() - game['timer_start']) if game['timer_start'] else 0
    elapsed_s    = _elapsed_str(elapsed_secs)

    if student_id and student_id in game['students']:
        with _lock:
            s              = game['students'][student_id]
            s['attempts']  = s.get('attempts', 0) + 1
            s['elapsed_str']  = elapsed_s
            s['elapsed_secs'] = elapsed_secs
            s['submission_time'] = datetime.now().strftime('%H:%M:%S')
            if not is_correct:
                s['status'] = 'wrong'
        lb = _leaderboard_payload()
        if game['teacher_sid']:
            socketio.emit('leaderboard_update', {'entries': lb},          to=game['teacher_sid'])
            socketio.emit('lobby_update',        {'students': _lobby_payload()}, to=game['teacher_sid'])

    return jsonify({
        'correct': is_correct,
        'message': 'Access granted.' if is_correct else 'Incorrect credentials.',
        'time':    elapsed_s,
    })



@secbank_app.route('/teacher')
def sb_teacher():
    return render_template(
        'securebank_teacher.html',
        port=SECBANK_PORT,
        correct=game['correct'],
        timer_minutes=game['timer_duration'] // 60,
    )


# ══════════════════════════════════════════════════════════════════
#  HTTPS ROUTES  (port 8443, TLS)
# ══════════════════════════════════════════════════════════════════

@https_app.route('/')
def https_index():
    return render_template('securebank_https.html')


@https_app.route('/demo-login', methods=['POST'])
def https_demo_login():
    """HTTPS demo — credentials are encrypted in transit, so we just redirect back."""
    user = request.form.get('username', '').strip()
    G = '\033[92m'; X = '\033[0m'; B = '\033[1m'
    print(f"\n{G}{'━'*54}{X}")
    print(f"{G}{B}  ✅  HTTPS DEMO LOGIN (credentials encrypted in transit){X}")
    print(f"{G}{'━'*54}{X}")
    print(f"  Source IP : {request.remote_addr}")
    print(f"  Username  : {user or '(empty)'}")
    print(f"  Password  : [REDACTED — transmitted over TLS]")
    print(f"  Note      : Wireshark sees only ciphertext.\n{G}{'━'*54}{X}\n")
    return redirect('/?demo=1')


# ══════════════════════════════════════════════════════════════════
#  SOCKET.IO — lifecycle
# ══════════════════════════════════════════════════════════════════

@socketio.on('connect')
def _on_connect():
    pass  # state flows through named events only


@socketio.on('disconnect')
def _on_disconnect():
    sid = request.sid
    if game['teacher_sid'] == sid:
        game['teacher_sid'] = None
    if sid in _sid_to_student:
        student_id = _sid_to_student.pop(sid)
        _student_to_sid.pop(student_id, None)
        with _lock:
            s = game['students'].get(student_id)
            if s and s['status'] not in ('correct', 'wrong', 'ended'):
                s['status'] = 'disconnected'
            if s:
                s['socket_id'] = None


# ══════════════════════════════════════════════════════════════════
#  SOCKET.IO — student events
# ══════════════════════════════════════════════════════════════════

@socketio.on('join')
def _on_join(data):
    """Student submits the join form on /join."""
    name        = str(data.get('name', '')).strip()[:60]
    employee_id = str(data.get('employeeId', '')).strip()[:30]
    if not name:
        emit('error', {'msg': 'Name is required'})
        return

    student_id = uuid.uuid4().hex[:8]
    sid        = request.sid
    now        = time.time()

    with _lock:
        status = 'waiting' if game['status'] == 'lobby' else 'investigating'
        game['students'][student_id] = {
            'name':          name,
            'employee_id':   employee_id,
            'joined_at':     now,
            'joined_at_str': datetime.now().strftime('%H:%M:%S'),
            'status':        status,
            'socket_id':     sid,
            'attempts':      0,
        }
        _sid_to_student[sid]        = student_id
        _student_to_sid[student_id] = sid

    join_room('lobby')

    emit('join_confirmed', {
        'student_id':  student_id,
        'name':        name,
        'game_status': game['status'],
    })

    # Push updated lobby to teacher
    if game['teacher_sid']:
        socketio.emit('lobby_update',
                      {'students': _lobby_payload()},
                      to=game['teacher_sid'])

    # If game already running, send them directly to the game
    if game['status'] == 'running' and game['timer_start']:
        elapsed = int(time.time() - game['timer_start'])
        emit('game_start', {'duration': game['timer_duration'], 'elapsed': elapsed})
    elif game['status'] == 'ended':
        emit('game_ended', {
            'username': game['correct']['username'],
            'password': game['correct']['password'],
            'endpoint': game['correct']['endpoint'],
        })
        if game['winner_id'] and game['winner_id'] in game['students']:
            emit('winner_found', {'name': game['students'][game['winner_id']]['name'], 'winner_id': game['winner_id']})


@socketio.on('rejoin')
def _on_rejoin(data):
    """Student reloads /game — reconnects and resumes their session."""
    student_id = str(data.get('student_id', ''))
    sid        = request.sid

    with _lock:
        if student_id not in game['students']:
            emit('redirect', {'url': '/join'})
            return

        s = game['students'][student_id]
        # Remap socket
        old = s.get('socket_id')
        if old and old in _sid_to_student:
            del _sid_to_student[old]
        s['socket_id']             = sid
        _sid_to_student[sid]       = student_id
        _student_to_sid[student_id] = sid
        # Restore active status unless they already finished
        if s['status'] in ('waiting', 'disconnected'):
            s['status'] = 'investigating'

    join_room('game')

    emit('rejoin_confirmed', {
        'name':        game['students'][student_id]['name'],
        'status':      game['students'][student_id]['status'],
        'game_status': game['status'],
    })
    emit('leaderboard_update', {'entries': _leaderboard_payload()})

    if game['status'] == 'running' and game['timer_start']:
        elapsed   = int(time.time() - game['timer_start'])
        remaining = max(0, game['timer_duration'] - elapsed)
        emit('timer_sync', {'remaining': remaining})
    elif game['status'] == 'ended':
        emit('game_ended', {
            'username':    game['correct']['username'],
            'password':    game['correct']['password'],
            'endpoint':    game['correct']['endpoint'],
            'leaderboard': _leaderboard_payload(),
        })
        if game['winner_id'] and game['winner_id'] in game['students']:
            emit('winner_found', {'name': game['students'][game['winner_id']]['name'], 'winner_id': game['winner_id']})


@socketio.on('submit_answer')
def _on_submit(data):
    """Student submits their credential guess."""
    sid        = request.sid
    student_id = _sid_to_student.get(sid)

    if not student_id or student_id not in game['students']:
        emit('submission_result', {'correct': False,
             'message': 'Session not found — please rejoin from /join.'})
        return
    if game['status'] != 'running':
        emit('submission_result', {'correct': False,
             'message': 'The challenge is not currently active.'})
        return

    endpoint = str(data.get('endpoint', '')).strip()
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', '')).strip()

    c = game['correct']
    is_correct = (
        endpoint.lower() == c['endpoint'].lower()
        and username     == c['username']
        and password     == c['password']
    )

    elapsed_secs = int(time.time() - game['timer_start']) if game['timer_start'] else 0
    elapsed_s    = _elapsed_str(elapsed_secs)

    with _lock:
        s              = game['students'][student_id]
        s['attempts']  = s.get('attempts', 0) + 1
        s['elapsed_str']  = elapsed_s
        s['elapsed_secs'] = elapsed_secs
        s['submission_time'] = datetime.now().strftime('%H:%M:%S')
        # Correct login → dashboard (not winner yet — recovery step decides winner)
        s['status'] = 'investigating' if is_correct else 'wrong'

    lb = _leaderboard_payload()

    if is_correct:
        emit('submission_result', {
            'correct': True,
            'message': 'Access granted.',
            'time':    elapsed_s,
        })
    else:
        emit('submission_result', {
            'correct': False,
            'message': 'Incorrect credentials.',
        })

    socketio.emit('leaderboard_update', {'entries': lb}, to='game')
    if game['teacher_sid']:
        socketio.emit('leaderboard_update', {'entries': lb},       to=game['teacher_sid'])
        socketio.emit('lobby_update', {'students': _lobby_payload()}, to=game['teacher_sid'])


@socketio.on('recovery_complete')
def _on_recovery_complete():
    """Student completed the fund-recovery transfer — announce winner and end game."""
    sid        = request.sid
    student_id = _sid_to_student.get(sid)
    if not student_id or student_id not in game['students']:
        return

    with _lock:
        # Only the first recovery while the game is running counts
        is_first = game['status'] == 'running' and not game['winner_id']
        if is_first:
            game['winner_id'] = student_id
            game['students'][student_id]['status'] = 'correct'
            game['status'] = 'ended'

    if is_first:
        name    = game['students'][student_id]['name']
        payload = {'name': name, 'winner_id': student_id}
        socketio.emit('winner_found', payload, to='game')
        socketio.emit('winner_found', payload, to='lobby')
        if game['teacher_sid']:
            socketio.emit('winner_found',       payload,                               to=game['teacher_sid'])
            socketio.emit('leaderboard_update', {'entries': _leaderboard_payload()},  to=game['teacher_sid'])
            socketio.emit('end_ack',            {},                                    to=game['teacher_sid'])


# ══════════════════════════════════════════════════════════════════
#  SOCKET.IO — teacher events
# ══════════════════════════════════════════════════════════════════

@socketio.on('teacher_connect')
def _on_teacher_connect():
    game['teacher_sid'] = request.sid
    join_room('teacher')
    emit('full_state', {
        'status':         game['status'],
        'correct':        game['correct'],
        'timer_duration': game['timer_duration'],
        'students':       _lobby_payload(),
        'leaderboard':    _leaderboard_payload(),
        'winner_id':      game['winner_id'],
        'timer_elapsed':  (int(time.time() - game['timer_start'])
                           if game['timer_start'] else 0),
        'rounds':         game['rounds'],
    })


@socketio.on('teacher_save_creds')
def _on_save_creds(data):
    with _lock:
        game['correct']['username'] = str(data.get('username', '')).strip() or game['correct']['username']
        game['correct']['password'] = str(data.get('password', '')).strip() or game['correct']['password']
        game['correct']['endpoint'] = str(data.get('endpoint', '')).strip() or game['correct']['endpoint']
    emit('creds_saved', {'correct': game['correct']})


@socketio.on('teacher_set_timer')
def _on_set_timer(data):
    mins = max(1, min(60, int(data.get('minutes', 10))))
    game['timer_duration'] = mins * 60
    emit('timer_set_ack', {'duration': game['timer_duration'], 'minutes': mins})


@socketio.on('teacher_start')
def _on_teacher_start():
    with _lock:
        game['status']      = 'running'
        game['timer_start'] = time.time()
        for s in game['students'].values():
            if s['status'] in ('waiting', 'disconnected'):
                s['status'] = 'investigating'

    payload = {'duration': game['timer_duration'], 'elapsed': 0}
    socketio.emit('game_start', payload, to='lobby')
    socketio.emit('game_start', payload, to='game')
    emit('game_started', {'timer_duration': game['timer_duration']})
    emit('leaderboard_update', {'entries': _leaderboard_payload()})


@socketio.on('teacher_reset')
def _on_teacher_reset():
    with _lock:
        # Save completed round to history if there was a winner
        if game['winner_id'] and game['winner_id'] in game['students']:
            winner = game['students'][game['winner_id']]
            game['round_number'] += 1
            game['rounds'].append({
                'round':        game['round_number'],
                'winner_name':  winner['name'],
                'winner_time':  winner.get('elapsed_str', '—'),
                'completed_at': datetime.now().strftime('%H:%M:%S'),
                'participants': len(game['students']),
            })

        for s in game['students'].values():
            s['status']   = 'waiting'
            s['attempts'] = 0
            for k in ('elapsed_str', 'elapsed_secs', 'submission_time'):
                s.pop(k, None)
        game['status']      = 'lobby'
        game['timer_start'] = None
        game['winner_id']   = None

    socketio.emit('game_reset', {}, to='game')
    socketio.emit('game_reset', {}, to='lobby')
    emit('reset_ack', {'students': _lobby_payload(), 'rounds': game['rounds']})


@socketio.on('teacher_factory_reset')
def _on_teacher_factory_reset():
    with _lock:
        game['students']     = {}
        game['status']       = 'lobby'
        game['timer_start']  = None
        game['winner_id']    = None
        game['rounds']       = []
        game['round_number'] = 0
    _sid_to_student.clear()
    _student_to_sid.clear()

    socketio.emit('game_reset', {}, to='game')
    socketio.emit('game_reset', {}, to='lobby')
    emit('factory_reset_ack', {'students': [], 'rounds': []})


@socketio.on('teacher_end_game')
def _on_teacher_end():
    with _lock:
        game['status'] = 'ended'

    payload = {
        'username':    game['correct']['username'],
        'password':    game['correct']['password'],
        'endpoint':    game['correct']['endpoint'],
        'leaderboard': _leaderboard_payload(),
    }
    socketio.emit('game_ended', payload, to='game')
    socketio.emit('game_ended', payload, to='lobby')
    emit('end_ack', payload)


@socketio.on('teacher_mark')
def _on_teacher_mark(data):
    student_id = str(data.get('student_id', ''))
    mark       = str(data.get('mark', ''))  # 'correct' | 'wrong'
    if mark not in ('correct', 'wrong'):
        return
    with _lock:
        if student_id in game['students']:
            game['students'][student_id]['status'] = mark
            if mark == 'correct' and not game['winner_id']:
                game['winner_id'] = student_id

    lb = _leaderboard_payload()
    socketio.emit('leaderboard_update', {'entries': lb}, to='game')
    emit('leaderboard_update', {'entries': lb})


# ══════════════════════════════════════════════════════════════════
#  CERTIFICATE GENERATION
# ══════════════════════════════════════════════════════════════════

def _get_local_ip() -> str:
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _generate_cert(local_ip: str) -> None:
    CERTS.mkdir(exist_ok=True)
    if CERT.exists() and KEY.exists():
        print("  → Certificate already exists — reusing.")
        return
    print(f"  → Generating self-signed TLS cert for {local_ip} …")
    CFG.write_text(f"""[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[dn]
C  = AU
ST = NSW
O  = Cybersecurity Workshop
CN = {local_ip}

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE

[alt_names]
IP.1  = {local_ip}
IP.2  = 127.0.0.1
DNS.1 = localhost
""")
    try:
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
             '-keyout', str(KEY), '-out', str(CERT),
             '-days', '1', '-nodes', '-config', str(CFG)],
            check=True, capture_output=True,
        )
        print("  → Certificate generated successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"  ✖ openssl error: {exc}")
        raise SystemExit(1)


# ══════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main() -> None:
    local_ip = _get_local_ip()
    G = '\033[92m'; Y = '\033[93m'; C = '\033[96m'; B = '\033[1m'; X = '\033[0m'

    print(f"\n{C}{'═'*62}{X}")
    print(f"{C}{B}  🛡   CYBERSECURITY WORKSHOP — Flask + SocketIO  🛡{X}")
    print(f"{C}{'═'*62}{X}\n")

    print(f"{B}[1/3] TLS Certificate{X}")
    _generate_cert(local_ip)

    print(f"\n{B}[2/3] Starting servers …{X}")

    null_log = _io.StringIO()

    # BrewNet — plain HTTP on its own eventlet greenlet
    bn_sock = eventlet.listen(('0.0.0.0', BREWNET_PORT))
    eventlet.spawn(eventlet.wsgi.server, bn_sock, brewnet_app,
                   log=null_log, log_output=False)

    # SecureBank HTTPS — TLS-wrapped eventlet greenlet
    hs_sock = eventlet.listen(('0.0.0.0', HTTPS_PORT))
    hs_ssl  = eventlet.wrap_ssl(
        hs_sock,
        certfile=str(CERT),
        keyfile=str(KEY),
        server_side=True,
    )
    eventlet.spawn(eventlet.wsgi.server, hs_ssl, https_app,
                   log=null_log, log_output=False)

    print(f"\n{G}{'═'*62}{X}")
    print(f"{G}{B}  ✅  ALL SERVERS RUNNING{X}")
    print(f"{G}{'═'*62}{X}\n")
    print(f"  {B}STAGE 1  BrewNet Cafe (HTTP){X}")
    print(f"  {Y}http://{local_ip}:{BREWNET_PORT}{X}\n")
    print(f"  {B}STAGE 2  SecureBank SOC Race (HTTP + WebSocket){X}")
    print(f"  {Y}http://{local_ip}:{SECBANK_PORT}/join{X}     ← share with students")
    print(f"  {Y}http://{local_ip}:{SECBANK_PORT}/teacher{X}  ← open on your laptop\n")
    print(f"  {B}STAGE 3  SecureBank Secure Portal (HTTPS){X}")
    print(f"  {C}https://{local_ip}:{HTTPS_PORT}{X}")
    print(f"  {G}(students must accept the self-signed cert warning){X}\n")
    print(f"{'─'*62}")
    print(f"  Stage 1 captured credentials print above this line.")
    print(f"  Press {B}Ctrl+C{R if (R:='\033[0m') else ''} to stop.\n")

    # SecureBank SocketIO server — blocks here, drives the eventlet loop
    socketio.run(secbank_app,
                 host='0.0.0.0',
                 port=SECBANK_PORT,
                 debug=False,
                 log_output=False)


if __name__ == '__main__':
    main()
