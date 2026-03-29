import sys

path = r'd:\qns\qnsdns\server\main.c'
data = open(path, 'rb').read()

old = b'    sess->downstream_seq = 0;\r\n    sess->status_sent = true;\r\n    LOG_DEBUG("Session %d: prioritized SOCKS5 status %02x (downstream_seq reset to 0)\\n", sidx, status);'

new = (
    b'    /* Do NOT reset downstream_seq here. The status byte is delivered at\n'
    b'     * whatever downstream_seq is currently at. The client reorder buffer\n'
    b'     * (expected_seq) has been advancing with each empty poll reply, so the\n'
    b'     * status byte arrives at the correct next seq and is delivered without\n'
    b'     * gaps. Resetting to 0 caused the status byte to collide with the\n'
    b'     * handshake reply (also seq=0) and be dropped as a duplicate. */\n'
    b'    sess->status_sent = true;\n'
    b'    LOG_DEBUG("Session %d: queued SOCKS5 status %02x at downstream_seq=%u\\n", sidx, status, sess->downstream_seq);'
)

if old in data:
    out = data.replace(old, new, 1)
    open(path, 'wb').write(out)
    print('patched OK')
else:
    # Print context around downstream_seq = 0 to debug
    idx = data.find(b'downstream_seq = 0')
    if idx != -1:
        print('NOT FOUND as expected, showing context:')
        print(repr(data[idx-120:idx+200]))
    else:
        print('downstream_seq = 0 not found at all')
