#!/usr/bin/env python3
"""
Terrapin Attack – Realistic Binary-Level Simulation (CVE-2023-48795)

Layers implemented:
  • SSH binary packet format (RFC 4253 §6): [uint32 len][uint8 pad_len][msg_type][payload][padding]
  • AES-128-CTR encryption + HMAC-SHA256-ETM authentication
  • Simplified SSH key derivation (SHA-256 KDF, RFC 4253 §7.2)
  • EXT_INFO (RFC 8308) encoding with real extension names
  • Four scenarios:
      1. Clean handshake (no MITM)
      2. Partial attack – drop EXT_INFO only  → MAC fails, connection breaks
      3. Full Terrapin attack – inject IGNORE + drop EXT_INFO → MAC succeeds,
         but EXT_INFO extensions are silently removed (downgrade)
      4. Countermeasure – strict-KEX intercepts the injected IGNORE

Attack mechanics (CVE-2023-48795) – both operations in the S→C channel:

  IMPORTANT: BOTH manipulations happen in the server→client direction only.
  The client→server stream is never touched.

  1. INJECT (plaintext phase, before server NEWKEYS):
     The MITM slips one SSH_MSG_IGNORE into the S→C unencrypted stream just
     before the server's NEWKEYS packet.  The client counts it as a real
     packet, so client.recv_seq (S→C) advances by one extra step (now +1
     ahead of what the server's send_seq will be for encrypted packets).

  2. DROP (encrypted phase – first post-NEWKEYS S→C packet):
     The MITM silently discards the server's SSH_MSG_EXT_INFO.  The client's
     recv_seq is NOT incremented, cancelling out the +1 from step 1.

  Net effect:
    • client S→C recv_seq == server S→C send_seq  → all MACs verify ✓
    • C→S channel is completely untouched         → no MAC disruption ✓
    • EXT_INFO is silently gone from the client   → downgrade possible ✗

  Practical impact: losing EXT_INFO removes server-sig-algs (forcing fallback
  to weaker algorithms like rsa-sha1), no-flow-control, ping@openssh.com, and
  delay-compression.  In vulnerable AsyncSSH versions this also enables
  complete authentication bypass via keyboard-interactive downgrade.

Dependencies: cryptography  (pip install cryptography)
"""

import os
import struct
import hashlib
import hmac as _hmac
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Message type constants (RFC 4253 / RFC 8308) ───────────────────────────────
SSH_MSG_IGNORE = 2
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXECDH_INIT = 30
SSH_MSG_KEXECDH_REPLY = 31
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_EXT_INFO = 60

_MSG_NAME: Dict[int, str] = {
    SSH_MSG_IGNORE:           "SSH_MSG_IGNORE",
    SSH_MSG_SERVICE_REQUEST:  "SSH_MSG_SERVICE_REQUEST",
    SSH_MSG_SERVICE_ACCEPT:   "SSH_MSG_SERVICE_ACCEPT",
    SSH_MSG_KEXINIT:          "SSH_MSG_KEXINIT",
    SSH_MSG_NEWKEYS:          "SSH_MSG_NEWKEYS",
    SSH_MSG_KEXECDH_INIT:     "SSH_MSG_KEXECDH_INIT",
    SSH_MSG_KEXECDH_REPLY:    "SSH_MSG_KEXECDH_REPLY",
    SSH_MSG_USERAUTH_REQUEST: "SSH_MSG_USERAUTH_REQUEST",
    SSH_MSG_EXT_INFO:         "SSH_MSG_EXT_INFO",
}


def msg_name(t: int) -> str:
    return _MSG_NAME.get(t, f"MSG_{t}")


# ── SSH binary packet encoding (RFC 4253 §6) ───────────────────────────────────
BLOCK_SIZE = 16   # AES block size; wire frame must be a multiple of this


def _ssh_pack_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def encode_packet(msg_type: int, payload: bytes = b"") -> bytes:
    """
    Build an unencrypted SSH binary packet:
        [uint32 packet_length][uint8 padding_length][uint8 msg_type][payload][padding]
    packet_length = 1 + 1 + len(payload) + padding_length
    Total wire length must be a multiple of BLOCK_SIZE.
    """
    content = bytes([msg_type]) + payload
    # 4 (packet_length field) + 1 (padding_length field) + len(content) + padding ≡ 0 (mod BLOCK_SIZE)
    overhead = 4 + 1 + len(content)
    padding_len = BLOCK_SIZE - (overhead % BLOCK_SIZE)
    if padding_len < 4:
        padding_len += BLOCK_SIZE
    padding = os.urandom(padding_len)
    packet_length = 1 + len(content) + padding_len
    return struct.pack(">IB", packet_length, padding_len) + content + padding


def decode_packet(data: bytes) -> Tuple[int, bytes]:
    """
    Decode an SSH binary packet.
    Returns (msg_type, payload_bytes_without_msg_type_byte).
    """
    if len(data) < 6:
        raise ValueError("packet too short")
    packet_length = struct.unpack(">I", data[:4])[0]
    padding_length = data[4]
    msg_type = data[5]
    payload_end = 4 + packet_length - padding_length
    payload = data[6:payload_end]
    return msg_type, payload


# ── EXT_INFO encoding / decoding (RFC 8308) ───────────────────────────────────

# Extensions negotiated by modern OpenSSH; losing these enables downgrade attacks
_SERVER_EXTENSIONS: Dict[str, str] = {
    "server-sig-algs":
        "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
        "sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,"
        "rsa-sha2-256,rsa-sha2-512",
    "no-flow-control":   "p",
    "delay-compression": "zlib@openssh.com,none",
    "ping@openssh.com":  "0",
}


def encode_ext_info(extensions: Dict[str, str]) -> bytes:
    buf = struct.pack(">I", len(extensions))
    for name, value in extensions.items():
        buf += _ssh_pack_string(name.encode())
        buf += _ssh_pack_string(value.encode())
    return buf


def decode_ext_info(payload: bytes) -> Dict[str, str]:
    count = struct.unpack(">I", payload[:4])[0]
    offset = 4
    exts: Dict[str, str] = {}
    for _ in range(count):
        nlen = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        name = payload[offset:offset + nlen].decode()
        offset += nlen
        vlen = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        val = payload[offset:offset + vlen].decode()
        offset += vlen
        exts[name] = val
    return exts


# ── Key material derivation (RFC 4253 §7.2, simplified with SHA-256) ──────────

def derive_session_keys(shared_secret: bytes, session_id: bytes) -> Dict[str, bytes]:
    """
    Derive symmetric keys from DH shared secret + session ID.
    RFC 4253 uses HASH(K || H || label || session_id) iterated; here we use
    HMAC-SHA256 for clarity while preserving the label structure.
    """
    def kdf(label: bytes, length: int) -> bytes:
        return _hmac.new(shared_secret, session_id + label, hashlib.sha256).digest()[:length]

    return {
        "c2s_enc_key": kdf(b"C", 16),   # AES-128-CTR key  (client → server)
        "s2c_enc_key": kdf(b"D", 16),   # AES-128-CTR key  (server → client)
        "c2s_enc_iv":  kdf(b"A", 16),   # IV               (client → server)
        "s2c_enc_iv":  kdf(b"B", 16),   # IV               (server → client)
        "c2s_mac_key": kdf(b"E", 32),   # HMAC-SHA256-ETM  (client → server)
        "s2c_mac_key": kdf(b"F", 32),   # HMAC-SHA256-ETM  (server → client)
    }


# ── Cipher engine (AES-128-CTR + HMAC-SHA256-ETM) ─────────────────────────────

class CipherEngine:
    """
    Stateful cipher engine for one direction of an SSH channel.

    Cipher suite: AES-128-CTR + HMAC-SHA256-ETM
      (analogous to aes128-ctr + hmac-sha2-256-etm@openssh.com)

    ETM MAC formula:
        mac = HMAC-SHA256(mac_key, uint32(seq) || ciphertext)[:MAC_LEN]

    The AES-CTR nonce is derived per-packet from (base_iv XOR seq) so the demo
    stays deterministic and illustrates the attack clearly.  In production the
    CTR state advances continuously across packets.
    """
    MAC_LEN = 20   # truncated to 20 bytes, like hmac-sha2-256

    def __init__(self, enc_key: bytes, enc_iv: bytes, mac_key: bytes):
        self.enc_key = enc_key
        self.base_iv = enc_iv
        self.mac_key = mac_key

    def _ctr_nonce(self, seq: int) -> bytes:
        iv_int = int.from_bytes(self.base_iv, "big")
        nonce_int = (iv_int + seq) & ((1 << 128) - 1)
        return nonce_int.to_bytes(16, "big")

    def encrypt(self, seq: int, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, mac)."""
        nonce = self._ctr_nonce(seq)
        enc = Cipher(algorithms.AES(self.enc_key),
                     modes.CTR(nonce)).encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()
        mac = self._compute_mac(seq, ciphertext)
        return ciphertext, mac

    def decrypt(self, seq: int, ciphertext: bytes) -> bytes:
        nonce = self._ctr_nonce(seq)
        dec = Cipher(algorithms.AES(self.enc_key),
                     modes.CTR(nonce)).decryptor()
        return dec.update(ciphertext) + dec.finalize()

    def _compute_mac(self, seq: int, ciphertext: bytes) -> bytes:
        seq_bytes = struct.pack(">I", seq)
        return _hmac.new(self.mac_key, seq_bytes + ciphertext, hashlib.sha256).digest()[:self.MAC_LEN]

    def verify_mac(self, seq: int, ciphertext: bytes, mac: bytes) -> bool:
        expected = self._compute_mac(seq, ciphertext)
        return _hmac.compare_digest(expected, mac)


# ── Wire packet ────────────────────────────────────────────────────────────────

@dataclass
class WirePacket:
    """A packet as it appears on the network wire."""
    seq:        int
    encrypted:  bool
    raw:        bytes          # plaintext SSH frame
    ciphertext: bytes = field(default=b"")
    mac:        bytes = field(default=b"")
    injected:   bool = field(default=False)
    dropped:    bool = field(default=False)

    @property
    def msg_type(self) -> int:
        # msg_type lives at byte 5 of the raw SSH frame
        return self.raw[5] if len(self.raw) >= 6 else 0

    def short(self, *, sender: str = "") -> str:
        prefix = f"{sender:>6} | " if sender else ""
        enc = "ENC  " if self.encrypted else "PLAIN"
        flags = " [INJECTED]" if self.injected else (
            " [DROPPED]" if self.dropped else "")
        ct_hex = (self.ciphertext[:8].hex() + "…") if self.ciphertext else "—"
        mac_hex = (self.mac[:6].hex() + "…") if self.mac else "—"
        return (f"{prefix}seq={self.seq:02d} | {enc} | {msg_name(self.msg_type):<28}"
                f"| ct={ct_hex:<19}| mac={mac_hex}{flags}")


# ── SSH peer ───────────────────────────────────────────────────────────────────

class SSHPeer:
    def __init__(self, name: str, strict_kex: bool = False):
        self.name = name
        self.send_seq = 0
        self.recv_seq = 0
        self.strict_kex = strict_kex
        # send_enc: True after we send our own NEWKEYS  (guards outbound cipher)
        # recv_enc: True after we receive peer's NEWKEYS (guards inbound decipher)
        # These MUST be separate: receiving peer's NEWKEYS must NOT activate our outbound.
        self.send_enc = False
        self.recv_enc = False
        self.cipher:    Optional[CipherEngine] = None  # outbound cipher
        self.decipher:  Optional[CipherEngine] = None  # inbound  cipher
        self.log:       List[str] = []
        self.extensions: Dict[str, str] = {}

    # ── Sending ────────────────────────────────────────────────────────────────

    def send(self, msg_type: int, payload: bytes = b"") -> WirePacket:
        raw = encode_packet(msg_type, payload)
        seq = self.send_seq
        self.send_seq += 1

        if self.cipher and self.send_enc:
            ct, mac = self.cipher.encrypt(seq, raw)
            pkt = WirePacket(seq=seq, encrypted=True,
                             raw=raw, ciphertext=ct, mac=mac)
        else:
            pkt = WirePacket(seq=seq, encrypted=False, raw=raw)

        direction = "→ s" if self.name == "client" else "→ c"
        self.log.append(f"[{self.name}] SEND {direction}  {pkt.short()}")
        return pkt

    def send_newkeys(self) -> WirePacket:
        # send_enc still False → NEWKEYS goes out PLAIN
        pkt = self.send(SSH_MSG_NEWKEYS)
        self.send_enc = True               # activate outbound encryption from next packet on
        return pkt

    def send_ext_info(self) -> WirePacket:
        return self.send(SSH_MSG_EXT_INFO, encode_ext_info(_SERVER_EXTENSIONS))

    # ── Receiving ──────────────────────────────────────────────────────────────

    def receive(self, pkt: WirePacket) -> bool:
        """
        Process an incoming wire packet.
        Returns True on success, False on MAC failure or strict-KEX violation.
        """
        expected_seq = self.recv_seq

        # strict-KEX: only handshake messages allowed before we receive peer's NEWKEYS
        if self.strict_kex and not self.recv_enc:
            allowed = {SSH_MSG_KEXINIT, SSH_MSG_KEXECDH_INIT,
                       SSH_MSG_KEXECDH_REPLY, SSH_MSG_NEWKEYS}
            if pkt.msg_type not in allowed:
                self.log.append(
                    f"[{self.name}] ✗ STRICT-KEX VIOLATION: {msg_name(pkt.msg_type)} "
                    f"during handshake – connection aborted"
                )
                return False

        # MAC verification for encrypted packets
        if pkt.encrypted and self.decipher:
            ok = self.decipher.verify_mac(
                expected_seq, pkt.ciphertext, pkt.mac)
            if not ok:
                self.log.append(
                    f"[{self.name}] ✗ MAC FAIL  seq_expected={expected_seq:02d} "
                    f"sender_used_seq={pkt.seq:02d} "
                    f"for {msg_name(pkt.msg_type)} → connection broken"
                )
                return False
            plaintext = self.decipher.decrypt(expected_seq, pkt.ciphertext)
            # rebuild WirePacket with decrypted raw content for message parsing
            pkt = WirePacket(seq=expected_seq, encrypted=True, raw=plaintext,
                             ciphertext=pkt.ciphertext, mac=pkt.mac)

        self.recv_seq += 1
        mt = pkt.msg_type

        if mt == SSH_MSG_NEWKEYS:
            self.recv_enc = True   # peer's outbound is now encrypted; activate our inbound
            self.log.append(
                f"[{self.name}] RECV ✓  {pkt.short()} ← encrypted channel active")
        elif mt == SSH_MSG_EXT_INFO:
            _, payload = decode_packet(pkt.raw)
            self.extensions = decode_ext_info(payload)
            ext_list = ", ".join(self.extensions.keys())
            self.log.append(
                f"[{self.name}] RECV ✓  {pkt.short()} ← extensions: {ext_list}")
        else:
            self.log.append(f"[{self.name}] RECV ✓  {pkt.short()}")

        return True


# ── MITM proxy ────────────────────────────────────────────────────────────────

class MITMProxy:
    """
    Active network MITM operating at the SSH binary packet level.

    Terrapin strategy – BOTH manipulations in the SERVER→CLIENT channel
    -------------------------------------------------------------------
    Step 1  INJECT (plaintext phase, before server's NEWKEYS):
        Slip one SSH_MSG_IGNORE into the S→C stream immediately before the
        server's NEWKEYS.  The client receives and counts the IGNORE, so its
        S→C recv_seq becomes N+1 where N is where the server will actually
        start its encrypted send_seq.  The C→S channel is untouched.

    Step 2  DROP (encrypted phase, first S→C packet):
        Silently discard the server's SSH_MSG_EXT_INFO.  The client's recv_seq
        is NOT incremented for this message, pulling it back from N+1 to N.

    Net effect:
        client S→C recv_seq == server S→C send_seq  → all MACs verify  ✓
        EXT_INFO is gone → security extensions silently lost  → downgrade
    """

    def __init__(self, *, inject_ignore: bool = True, drop_ext_info: bool = True):
        self.inject_ignore = inject_ignore
        self.drop_ext_info = drop_ext_info
        self._injected = False
        self.log: List[str] = []

    def intercept_c2s(self, pkt: WirePacket) -> List[WirePacket]:
        # The C→S channel is never manipulated in the Terrapin attack.
        return [pkt]

    def intercept_s2c(self, pkt: WirePacket) -> List[WirePacket]:
        # Step 1 – inject IGNORE just before server's NEWKEYS (plaintext)
        if self.inject_ignore and not self._injected and pkt.msg_type == SSH_MSG_NEWKEYS:
            ignore_seq = pkt.seq    # occupies this sequence slot on the client side
            ignore_raw = encode_packet(
                SSH_MSG_IGNORE, _ssh_pack_string(b"terrapin"))
            ignore_pkt = WirePacket(
                seq=ignore_seq, encrypted=False, raw=ignore_raw, injected=True)

            # Renumber NEWKEYS one slot forward so the client's recv_seq lands at N+1
            newkeys_shifted = WirePacket(
                seq=pkt.seq + 1, encrypted=pkt.encrypted,
                raw=pkt.raw, ciphertext=pkt.ciphertext, mac=pkt.mac,
            )
            self._injected = True
            self.log.append(
                f"[MITM] INJECT  SSH_MSG_IGNORE at seq={ignore_seq:02d} in S→C "
                f"(NEWKEYS renumbered to seq={newkeys_shifted.seq:02d} for client)"
            )
            return [ignore_pkt, newkeys_shifted]

        # Step 2 – drop EXT_INFO (first encrypted S→C packet) to cancel the +1
        if self.drop_ext_info and pkt.msg_type == SSH_MSG_EXT_INFO:
            if self._injected:
                note = "cancels the +1 from IGNORE; MACs stay aligned; extensions gone"
            else:
                note = "no IGNORE injected → seq desync; next encrypted MAC will fail"
            self.log.append(
                f"[MITM] DROP    SSH_MSG_EXT_INFO (seq={pkt.seq:02d}) – {note}"
            )
            return []   # silently discarded

        return [pkt]


# ── Orchestrator ───────────────────────────────────────────────────────────────

class TerrapinDemo:
    """
    Drives a simplified SSH handshake + post-auth exchange.

    A simulated ECDH produces a random shared secret and session ID from which
    real AES-128-CTR + HMAC-SHA256-ETM keys are derived and handed to both peers.
    """

    def __init__(self, *, strict_kex: bool = False, mitm: Optional[MITMProxy] = None):
        self.client = SSHPeer("client", strict_kex=strict_kex)
        self.server = SSHPeer("server", strict_kex=strict_kex)
        self.mitm = mitm

    # ── Key setup ──────────────────────────────────────────────────────────────

    def _setup_keys(self):
        shared_secret = os.urandom(32)
        session_id = hashlib.sha256(shared_secret + b"session-id").digest()
        keys = derive_session_keys(shared_secret, session_id)

        self.client.cipher = CipherEngine(
            keys["c2s_enc_key"], keys["c2s_enc_iv"], keys["c2s_mac_key"])
        self.client.decipher = CipherEngine(
            keys["s2c_enc_key"], keys["s2c_enc_iv"], keys["s2c_mac_key"])
        self.server.cipher = CipherEngine(
            keys["s2c_enc_key"], keys["s2c_enc_iv"], keys["s2c_mac_key"])
        self.server.decipher = CipherEngine(
            keys["c2s_enc_key"], keys["c2s_enc_iv"], keys["c2s_mac_key"])

        print(f"  [KEX] shared_secret = {shared_secret.hex()[:40]}…")
        print(f"  [KEX] session_id    = {session_id.hex()[:40]}…")
        print(f"  [KEX] c2s_enc_key   = {keys['c2s_enc_key'].hex()}")
        print(f"  [KEX] c2s_mac_key   = {keys['c2s_mac_key'].hex()}")
        print(f"  [KEX] s2c_enc_key   = {keys['s2c_enc_key'].hex()}")
        print(f"  [KEX] s2c_mac_key   = {keys['s2c_mac_key'].hex()}")

    # ── Delivery helpers ───────────────────────────────────────────────────────

    def _c2s(self, pkt: WirePacket) -> bool:
        pkts = self.mitm.intercept_c2s(pkt) if self.mitm else [pkt]
        for p in pkts:
            if not self.server.receive(p):
                return False
        return True

    def _s2c(self, pkt: WirePacket) -> bool:
        pkts = self.mitm.intercept_s2c(pkt) if self.mitm else [pkt]
        for p in pkts:
            if not self.client.receive(p):
                return False
        return True

    # ── Main handshake + session ───────────────────────────────────────────────

    def run(self) -> Tuple[bool, str]:
        # Algorithm negotiation
        if not self._c2s(self.client.send(SSH_MSG_KEXINIT)):
            return False, "KEXINIT c→s"
        if not self._s2c(self.server.send(SSH_MSG_KEXINIT)):
            return False, "KEXINIT s→c"

        # ECDH key exchange messages
        if not self._c2s(self.client.send(SSH_MSG_KEXECDH_INIT)):
            return False, "KEXECDH_INIT"
        if not self._s2c(self.server.send(SSH_MSG_KEXECDH_REPLY)):
            return False, "KEXECDH_REPLY"

        # Both sides independently derive session keys from the ECDH output
        self._setup_keys()

        # Switch to encrypted channel
        if not self._c2s(self.client.send_newkeys()):
            return False, "NEWKEYS c→s"
        if not self._s2c(self.server.send_newkeys()):
            return False, "NEWKEYS s→c"

        # First post-NEWKEYS server packet: EXT_INFO  ← Terrapin target
        if not self._s2c(self.server.send_ext_info()):
            return False, "EXT_INFO (MAC error – seq desync)"

        # Post-auth service exchange
        if not self._c2s(self.client.send(SSH_MSG_SERVICE_REQUEST)):
            return False, "SERVICE_REQUEST (MAC error)"
        if not self._s2c(self.server.send(SSH_MSG_SERVICE_ACCEPT)):
            return False, "SERVICE_ACCEPT (MAC error)"
        if not self._c2s(self.client.send(SSH_MSG_USERAUTH_REQUEST)):
            return False, "USERAUTH_REQUEST (MAC error)"

        return True, "session established"

    # ── Report ─────────────────────────────────────────────────────────────────

    def print_report(self, ok: bool, message: str):
        status = "✓ SUCCESS" if ok else "✗ FAILURE"
        print(f"\n{'═'*72}")
        print(f"  Result : {status}")
        print(f"  Message: {message}")
        print(f"{'═'*72}")

        if self.mitm and self.mitm.log:
            print("\n  ── MITM log ─────────────────────────────────────────────────")
            for line in self.mitm.log:
                print(f"    {line}")

        print("\n  ── Server log ───────────────────────────────────────────────")
        for line in self.server.log:
            print(f"    {line}")

        print("\n  ── Client log ───────────────────────────────────────────────")
        for line in self.client.log:
            print(f"    {line}")

        print("\n  ── Post-handshake state ─────────────────────────────────────")
        ext_c = list(self.client.extensions.keys())
        if ext_c:
            ext_label = str(ext_c)
        elif ok:
            ext_label = "∅  ← ATTACK SUCCEEDED: EXT_INFO silently dropped, downgrade possible"
        else:
            ext_label = "∅  (session aborted before EXT_INFO was received)"
        print(f"    client extensions : {ext_label}")
        print(f"    client recv_seq   : {self.client.recv_seq}")
        print(f"    server recv_seq   : {self.server.recv_seq}")


# ── Scenarios ──────────────────────────────────────────────────────────────────

def run_scenario(title: str, **kwargs):
    width = 72
    print(f"\n{'#'*width}")
    print(f"#  {title}")
    print(f"{'#'*width}")
    demo = TerrapinDemo(**kwargs)
    ok, msg = demo.run()
    demo.print_report(ok, msg)


if __name__ == "__main__":
    print(textwrap.dedent("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║          Terrapin Attack – Binary-Level Simulation                   ║
    ║          CVE-2023-48795  ·  Prefix Truncation Attack                 ║
    ║          Cipher: AES-128-CTR + HMAC-SHA256-ETM                       ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """))

    # 1 ── Baseline: clean connection, no MITM
    run_scenario(
        "Scenario 1 – Clean handshake (no MITM)",
        mitm=None,
    )

    # 2 ── Naive attack: drop EXT_INFO without injecting IGNORE
    #      The server's seq counter is now 1 behind the client's expectation,
    #      causing MAC verification to fail on the very next encrypted message.
    run_scenario(
        "Scenario 2 – Partial attack: drop EXT_INFO only (seq desync → MAC fail)",
        mitm=MITMProxy(inject_ignore=False, drop_ext_info=True),
    )

    # 3 ── Full Terrapin: inject IGNORE (c→s) + drop EXT_INFO (s→c)
    #      The ±1 offsets balance perfectly; MACs all verify, but the client
    #      never sees EXT_INFO → server-sig-algs, ping, no-flow-control all gone.
    run_scenario(
        "Scenario 3 – Full Terrapin: inject IGNORE + drop EXT_INFO (silent downgrade)",
        mitm=MITMProxy(inject_ignore=True, drop_ext_info=True),
    )

    # 4 ── Countermeasure: kex-strict@openssh.com
    #      The injected SSH_MSG_IGNORE is rejected immediately because it arrives
    #      during the handshake phase where only KEX messages are permitted.
    run_scenario(
        "Scenario 4 – Countermeasure: strict-KEX (kex-strict@openssh.com)",
        strict_kex=True,
        mitm=MITMProxy(inject_ignore=True, drop_ext_info=True),
    )
