import socket, struct, threading, os, sys, secrets, string

# ================= AES-128 MANUAL =================
def xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a

def gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = xtime(a); b >>= 1
    return r

def make_sbox():
    sb = [0] * 256
    for i in range(256):
        inv = 0
        if i:
            for j in range(1, 256):
                if gmul(i, j) == 1: inv = j; break
        x = s = inv
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        sb[i] = s ^ 0x63
    return sb

SBOX = make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX): INV_SBOX[_v] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion(key):
    w = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = w[i-1][:]
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return [sum(w[4*r:4*r+4], []) for r in range(11)]

def add_rk(s, rk): return [a ^ b for a, b in zip(s, rk)]
def sub_bytes(s): return [SBOX[b] for b in s]
def inv_sub_bytes(s): return [INV_SBOX[b] for b in s]

def shift_rows(s):
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            o[4*c + r] = s[4*((c + r) % 4) + r]
    return o

def inv_shift_rows(s):
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            o[4*((c + r) % 4) + r] = s[4*c + r]
    return o

def mix_columns(s):
    o = []
    for c in range(4):
        a = s[4*c:4*c+4]
        o += [gmul(a[0],2)^gmul(a[1],3)^a[2]^a[3],
              a[0]^gmul(a[1],2)^gmul(a[2],3)^a[3],
              a[0]^a[1]^gmul(a[2],2)^gmul(a[3],3),
              gmul(a[0],3)^a[1]^a[2]^gmul(a[3],2)]
    return o

def inv_mix_columns(s):
    o = []
    for c in range(4):
        a = s[4*c:4*c+4]
        o += [gmul(a[0],14)^gmul(a[1],11)^gmul(a[2],13)^gmul(a[3],9),
              gmul(a[0],9)^gmul(a[1],14)^gmul(a[2],11)^gmul(a[3],13),
              gmul(a[0],13)^gmul(a[1],9)^gmul(a[2],14)^gmul(a[3],11),
              gmul(a[0],11)^gmul(a[1],13)^gmul(a[2],9)^gmul(a[3],14)]
    return o

def enc_block(blk, rk):
    s = add_rk(list(blk), rk[0])
    for r in range(1, 10):
        s = add_rk(mix_columns(shift_rows(sub_bytes(s))), rk[r])
    return bytes(add_rk(shift_rows(sub_bytes(s)), rk[10]))

def dec_block(blk, rk):
    s = add_rk(list(blk), rk[10])
    for r in range(9, 0, -1):
        s = inv_mix_columns(add_rk(inv_sub_bytes(inv_shift_rows(s)), rk[r]))
    return bytes(add_rk(inv_sub_bytes(inv_shift_rows(s)), rk[0]))

def pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n

def unpad(b):
    n = b[-1]
    if n < 1 or n > 16 or b[-n:] != bytes([n]) * n:
        raise ValueError("padding salah (key tidak cocok?)")
    return b[:-n]

def encrypt(key, text):          # key: str ASCII 16 char, text: str -> bytes (IV||CT)
    rk = key_expansion(key.encode('ascii'))
    iv = os.urandom(16); prev = iv; out = iv
    data = pad(text.encode('ascii'))
    for i in range(0, len(data), 16):
        prev = enc_block(bytes(a ^ b for a, b in zip(data[i:i+16], prev)), rk)
        out += prev
    return out

def decrypt(key, ct):
    rk = key_expansion(key.encode('ascii'))
    prev = ct[:16]; out = b''
    for i in range(16, len(ct), 16):
        blk = ct[i:i+16]
        out += bytes(a ^ b for a, b in zip(dec_block(blk, rk), prev))
        prev = blk
    return unpad(out).decode('ascii')

def selftest():  # vektor uji FIPS-197 Appendix C.1
    k = bytes(range(16)); p = bytes.fromhex("00112233445566778899aabbccddeeff")
    rk = key_expansion(k); c = enc_block(p, rk)
    print("cipher :", c.hex(), "(harus 69c4e0d86a7b0430d8cdb78070b4c55a)")
    print("decrypt:", dec_block(c, rk).hex())

# ================= JARINGAN =================
KDC_PORT, PEER_PORT = 5000, 6000

def send_frame(s, data): s.sendall(struct.pack('>I', len(data)) + data)

def recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d: raise ConnectionError("koneksi terputus")
        buf += d
    return buf

def recv_frame(s):
    return recv_exact(s, struct.unpack('>I', recv_exact(s, 4))[0])

def ask_key(label):
    while True:
        k = input(f"{label} (16 karakter ASCII): ")
        if len(k) == 16 and k.isascii(): return k
        print("  Key harus tepat 16 karakter ASCII.")

def rand_str(n, alphabet=string.ascii_letters + string.digits):
    return ''.join(secrets.choice(alphabet) for _ in range(n))

def nonce(): return rand_str(8, string.digits)

# ================= KDC =================
def kdc_handle(conn, keys):
    try:
        req = recv_frame(conn).decode()
        ida, idb, n1 = req.split('|')
        print(f"\n[KDC] Langkah 1 diterima: {req}")
        ks = rand_str(16)
        ticket = encrypt(keys[idb], f"{ks}|{ida}")
        print(f"[KDC] Ks={ks}")
        print(f"[KDC] Ticket E(Kb,[Ks||ID_A]) hex: {ticket.hex()}")
        resp = encrypt(keys[ida], f"{ks}|{idb}|{n1}|{ticket.hex()}")
        print(f"[KDC] Langkah 2 dikirim, E(Ka,...) hex: {resp.hex()}")
        send_frame(conn, resp)
    except Exception as e:
        print("[KDC] error:", e)
    finally:
        conn.close()

def run_kdc():
    keys = {'Alice': ask_key("Master key Alice (Ka)"), 'Bob': ask_key("Master key Bob (Kb)")}
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', KDC_PORT)); srv.listen()
    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=kdc_handle, args=(c, keys), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    print(f"[KDC] listening di port {KDC_PORT}")
    while True:
        p = input("\nKDC menu: 1=ganti Ka, 2=ganti Kb, 0=keluar > ")
        if p == '1': keys['Alice'] = ask_key("Ka baru")
        elif p == '2': keys['Bob'] = ask_key("Kb baru")
        elif p == '0': return

# ================= ALICE / BOB =================
def recv_loop(st, conn, peer):
    try:
        while True:
            ct = recv_frame(conn)
            try:
                msg = decrypt(st['ks'], ct)
            except Exception as e:
                msg = f"<gagal dekripsi: {e}>"
            print(f"\n[{peer}] cipher(hex): {ct.hex()}\n[{peer}] plaintext   : {msg}")
    except Exception:
        print(f"\n[info] koneksi dengan {peer} ditutup")
        st['conn'] = None

def bob_listener(st):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PEER_PORT)); srv.listen()
    print(f"[Bob] menunggu Alice di port {PEER_PORT}")
    while True:
        conn, addr = srv.accept()
        try:
            ticket = recv_frame(conn)                                   # langkah 3
            print(f"\n[Bob] Langkah 3 diterima dari {addr[0]}, hex: {ticket.hex()}")
            ks, ida = decrypt(st['master'], ticket).split('|')
            n2 = nonce()
            send_frame(conn, encrypt(ks, n2))                           # langkah 4
            print(f"[Bob] Langkah 4 dikirim, N2={n2}")
            ans = decrypt(ks, recv_frame(conn))                         # langkah 5
            if int(ans) != int(n2) + 1: raise ValueError("verifikasi N2 gagal")
            print(f"[Bob] Langkah 5 OK ({ans}). Session key aktif dengan {ida}.")
            st['ks'], st['conn'] = ks, conn
            recv_loop(st, conn, ida)
        except Exception as e:
            print("[Bob] gagal key distribution:", e); conn.close()

def alice_distribute(st):
    kdc_ip = input("IP KDC: "); bob_ip = input("IP Bob: ")
    n1 = nonce()
    s = socket.create_connection((kdc_ip, KDC_PORT))
    req = f"Alice|Bob|{n1}"
    send_frame(s, req.encode())                                         # langkah 1
    print(f"[Alice] Langkah 1 dikirim: {req}")
    resp = recv_frame(s); s.close()                                     # langkah 2
    print(f"[Alice] Langkah 2 diterima, hex: {resp.hex()}")
    ks, idb, n1r, ticket_hex = decrypt(st['master'], resp).split('|')
    if n1r != n1 or idb != 'Bob': raise ValueError("N1/ID_B tidak cocok")
    print(f"[Alice] Ks={ks}")
    conn = socket.create_connection((bob_ip, PEER_PORT))
    send_frame(conn, bytes.fromhex(ticket_hex))                         # langkah 3
    print("[Alice] Langkah 3 dikirim (ticket)")
    n2 = decrypt(ks, recv_frame(conn))                                  # langkah 4
    print(f"[Alice] Langkah 4 diterima, N2={n2}")
    send_frame(conn, encrypt(ks, str(int(n2) + 1)))                     # langkah 5
    print("[Alice] Langkah 5 dikirim. Session key aktif.")
    st['ks'], st['conn'] = ks, conn
    threading.Thread(target=recv_loop, args=(st, conn, 'Bob'), daemon=True).start()

def run_peer(role):
    me, other = ('Alice', 'Bob') if role == 'alice' else ('Bob', 'Alice')
    st = {'master': ask_key(f"Master key {me}"), 'ks': None, 'conn': None}
    if role == 'bob':
        threading.Thread(target=bob_listener, args=(st,), daemon=True).start()
    while True:
        p = input(f"\n{me} menu: " + ("1=key distribution, " if role == 'alice' else "")
                  + "2=kirim pesan, 3=ganti master key, 4=lihat Ks, 0=keluar > ")
        try:
            if p == '1' and role == 'alice': alice_distribute(st)
            elif p == '2':
                if not st['conn']: print("Belum ada session."); continue
                m = input("Pesan (ASCII): ")
                ct = encrypt(st['ks'], m)
                print(f"cipher(hex): {ct.hex()}")
                send_frame(st['conn'], ct)
            elif p == '3': st['master'] = ask_key("Master key baru")
            elif p == '4': print("Ks =", st['ks'])
            elif p == '0': return
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    role = sys.argv[1].lower() if len(sys.argv) > 1 else ''
    if role == 'test': selftest()
    elif role == 'kdc': run_kdc()
    elif role in ('alice', 'bob'): run_peer(role)
    else: print("Pakai: python kia.py [test|kdc|alice|bob]")
