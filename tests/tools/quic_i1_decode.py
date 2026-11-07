"""Independent decoder for an AmneziaWG I1 mask that should be a QUIC v1 Initial (RFC 9000/9001).
Fills <r N> with random bytes (as AmneziaWG does), removes header protection with keys derived from the
DCID, decrypts the payload with the AES-GCM keystream (the tag is random by design, so it is not
checked - a DPI reading Initials does not need it), parses the CRYPTO frame and prints the ClientHello SNI.
Also checks the RFC 9001 Appendix A key derivation vectors first.
Usage: python quic_i1_decode.py '<b 0x...><r 32>...'
"""
import os
import re
import sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SALT = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')


def hkdf_extract(salt, ikm):
    h = hmac.HMAC(salt, hashes.SHA256()); h.update(ikm); return h.finalize()


def expand_label(secret, label, length):
    full = b'tls13 ' + label.encode()
    info = length.to_bytes(2, 'big') + bytes([len(full)]) + full + b'\x00'
    out, t, i = b'', b'', 1
    while len(out) < length:
        h = hmac.HMAC(secret, hashes.SHA256()); h.update(t + info + bytes([i])); t = h.finalize(); out += t; i += 1
    return out[:length]


def keys(dcid):
    initial = hkdf_extract(SALT, dcid)
    client = expand_label(initial, 'client in', 32)
    return expand_label(client, 'quic key', 16), expand_label(client, 'quic iv', 12), expand_label(client, 'quic hp', 16)


def rfc_vectors():
    k, iv, hp = keys(bytes.fromhex('8394c8f03e515708'))
    assert k.hex() == '1f369613dd76d5467730efcbe3b1a22d', k.hex()
    assert iv.hex() == 'fa044b2f42a3fd3b46fb255c', iv.hex()
    assert hp.hex() == '9f50449e04a0e810283a1e9933adedd2', hp.hex()


def fill(mask):
    out = b''
    for tag, val in re.findall(r'<(b|r|rc|rd|c|t) ?([^>]*)>', mask):
        if tag == 'b': out += bytes.fromhex(val[2:])
        elif tag == 'r': out += os.urandom(int(val))
        else: raise SystemExit('unsupported tag ' + tag)
    return out


def varint(b, i):
    l = 1 << (b[i] >> 6); v = b[i] & 0x3f
    for j in range(1, l): v = (v << 8) | b[i + j]
    return v, i + l


def decode(pkt):
    assert pkt[0] & 0xc0 == 0xc0, 'not a long header'
    assert pkt[1:5] == b'\x00\x00\x00\x01', 'not QUIC v1'
    i = 5; dl = pkt[i]; i += 1; dcid = pkt[i:i + dl]; i += dl
    sl = pkt[i]; i += 1 + sl
    tl, i = varint(pkt, i); i += tl
    length, i = varint(pkt, i)
    pn_off = i
    k, iv, hp = keys(dcid)
    sample = pkt[pn_off + 4:pn_off + 20]
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = pkt[0] ^ (mask[0] & 0x0f)
    pnl = (first & 3) + 1
    pn = bytes(pkt[pn_off + j] ^ mask[1 + j] for j in range(pnl))
    pnum = int.from_bytes(pn, 'big')
    ct = pkt[pn_off + pnl:pn_off + length]
    nonce = bytes(a ^ b for a, b in zip(iv, pnum.to_bytes(12, 'big')))
    ctr = Cipher(algorithms.AES(k), modes.CTR(nonce + b'\x00\x00\x00\x02')).decryptor()
    plain = ctr.update(ct[:-16])
    assert plain[0] == 0x06, 'first frame is not CRYPTO'
    off, j = varint(plain, 1); clen, j = varint(plain, j)
    hello = plain[j:j + clen]
    assert hello[0] == 0x01, 'not a ClientHello'
    return {'size': len(pkt), 'dcid': dcid.hex(), 'pn': pnum, 'hello_len': len(hello),
            'sni': client_hello_sni(hello), 'padding_zero': all(x == 0 for x in plain[j + clen:])}


def client_hello_sni(h):
    # handshake: type 1, length 3; body: version 2, random 32, session id, cipher suites, compression, extensions
    p = 4 + 2 + 32
    p += 1 + h[p]
    p += 2 + int.from_bytes(h[p:p + 2], 'big')
    p += 1 + h[p]
    end = p + 2 + int.from_bytes(h[p:p + 2], 'big'); p += 2
    while p + 4 <= end:
        et = int.from_bytes(h[p:p + 2], 'big'); el = int.from_bytes(h[p + 2:p + 4], 'big'); d = h[p + 4:p + 4 + el]
        if et == 0:   # server_name: list length 2, name type 1 (0 = host_name), name length 2, name
            assert d[2] == 0
            return d[5:5 + int.from_bytes(d[3:5], 'big')].decode()
        p += 4 + el
    return None


if __name__ == '__main__':
    rfc_vectors()
    r = decode(fill(sys.argv[1]))
    print(r)
    ok = r['size'] >= 1200 and r['sni'] and r['padding_zero'] and r['pn'] == 0
    print('OK' if ok else 'FAIL')
    sys.exit(0 if ok else 1)
