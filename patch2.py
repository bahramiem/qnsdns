path = r'd:\qns\qnsdns\server\main.c'
data = open(path, 'rb').read()

# 1. Add handshake_done field to session struct (after burst_decoded)
old1 = b'  bool burst_decoded;        /* true once this burst_seq_start has been fully\r\n                              * decoded+forwarded; gate against re-decode from\r\n                              * redundant FEC symbols of the same burst */\r\n\r\n  /* Downstream sequencing (Server \xe2\x86\x92 Client) */'

new1 = b'  bool burst_decoded;        /* true once this burst_seq_start has been fully\r\n                              * decoded+forwarded; gate against re-decode from\r\n                              * redundant FEC symbols of the same burst */\r\n\r\n  /* Set true once the client has sent a capability/MTU handshake for this\r\n   * session. After this point downstream_seq is used for ALL replies\r\n   * (including FEC chunk ACKs and polls) so the client reorder buffer\r\n   * receives a gapless monotonic stream. Pre-handshake probe polls get\r\n   * seq=0 with no increment to keep them outside the reorder window. */\r\n  bool handshake_done;\r\n\r\n  /* Downstream sequencing (Server \xe2\x86\x92 Client) */'

if old1 in data:
    data = data.replace(old1, new1, 1)
    print('step1: struct field added')
else:
    print('step1 FAILED - old1 not found')

# 2. Set handshake_done=true when the handshake is processed (near is_handshake block)
old2 = b'    sess->downstream_seq = 0;\r\n    LOG_INFO("Session %d: downstream_seq reset to 0 on handshake\\n", sidx);'
new2 = b'    sess->downstream_seq = 0;\r\n    sess->handshake_done = true;\r\n    LOG_INFO("Session %d: downstream_seq reset to 0 on handshake, handshake_done=true\\n", sidx);'

if old2 in data:
    data = data.replace(old2, new2, 1)
    print('step2: handshake_done set on handshake')
else:
    print('step2 FAILED, searching...')
    idx = data.find(b'downstream_seq = 0')
    print('  downstream_seq=0 at:', data[:idx].count(b'\n') + 1 if idx != -1 else 'NOT FOUND')

# 3. Replace the two inline out_seq computations:
#    has_capability_header ? sess->downstream_seq++ : 0
# with:
#    sess->handshake_done ? sess->downstream_seq++ : 0
old3 = b'has_capability_header ? sess->downstream_seq++ : 0'
new3 = b'sess->handshake_done ? sess->downstream_seq++ : 0'
count = data.count(old3)
if count > 0:
    data = data.replace(old3, new3)
    print(f'step3: replaced {count} occurrence(s) of out_seq guard')
else:
    print('step3 FAILED - guard not found')

# Also fix the SWARM path which also uses has_capability_header
old4 = b'uint16_t swarm_seq = has_capability_header ? sess->downstream_seq++ : 0;'
new4 = b'uint16_t swarm_seq = sess->handshake_done ? sess->downstream_seq++ : 0;'
count4 = data.count(old4)
if count4 > 0:
    data = data.replace(old4, new4)
    print(f'step4: fixed SWARM path ({count4} occurrence(s))')
else:
    # Not a hard failure, swarm path might already be using different variable
    print('step4: SWARM guard not found (may be OK)')

open(path, 'wb').write(data)
print('written OK')
