from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SSHPacket:
    sender: str
    kind: str
    encrypted: bool = False
    payload: str = ""
    seq: Optional[int] = None

    def short(self):
        enc = "ENC" if self.encrypted else "PLAIN"
        return f"{self.sender:>6} | seq={self.seq:02d} | {enc:5} | {self.kind}"


class SSHPeer:
    def __init__(self, name: str, strict_kex: bool = False):
        self.name = name
        self.send_seq = 0
        self.recv_seq = 0
        self.encryption_on = False
        self.strict_kex = strict_kex
        self.kex_finished = False
        self.received_encrypted = []
        self.log = []

    def send(self, kind: str, encrypted: bool = False, payload: str = "") -> SSHPacket:
        pkt = SSHPacket(
            sender=self.name,
            kind=kind,
            encrypted=encrypted,
            payload=payload,
            seq=self.send_seq
        )
        self.send_seq += 1
        return pkt

    def receive(self, pkt: SSHPacket):
        self.log.append(f"[{self.name}] received -> {pkt.short()}")

        if pkt.seq != self.recv_seq:
            self.log.append(
                f"[{self.name}] WARNING: expected seq={self.recv_seq}, got seq={pkt.seq}"
            )
        self.recv_seq = pkt.seq + 1

        if self.strict_kex and not self.kex_finished:
            allowed = {"VERSION", "KEXINIT", "KEX_ECDH_INIT", "KEX_ECDH_REPLY", "NEWKEYS"}
            if pkt.kind not in allowed:
                raise Exception(
                    f"[{self.name}] strict KEX violation: unexpected packet {pkt.kind} during handshake"
                )

        if pkt.kind == "NEWKEYS":
            self.encryption_on = True
            self.kex_finished = True
            self.log.append(f"[{self.name}] secure channel activated")
            return

        if pkt.encrypted:
            self.received_encrypted.append(pkt.kind)


class MITMProxy:
    def __init__(self, enabled=True, drop_ext_info=True, inject_ignore=True):
        self.enabled = enabled
        self.drop_ext_info = drop_ext_info
        self.inject_ignore = inject_ignore
        self.injected = False
        self.log = []

        self.client_view_server_seq_offset = 0
        self.server_view_client_seq_offset = 0

    def intercept_c2s(self, pkt: SSHPacket) -> List[SSHPacket]:
        out = []

        if not self.enabled:
            out.append(pkt)
            return out

        # inject one IGNORE before NEWKEYS to disturb sequence alignment
        if self.inject_ignore and not self.injected and pkt.kind == "NEWKEYS":
            injected = SSHPacket(
                sender="client",
                kind="IGNORE",
                encrypted=False,
                payload="mitm-noise",
                seq=pkt.seq
            )
            self.log.append(f"[MITM] Injecting packet toward server: {injected.short()}")

            shifted_real = SSHPacket(
                sender=pkt.sender,
                kind=pkt.kind,
                encrypted=pkt.encrypted,
                payload=pkt.payload,
                seq=pkt.seq + 1
            )

            self.injected = True
            self.server_view_client_seq_offset += 1
            out.append(injected)
            out.append(shifted_real)
            return out

        if self.server_view_client_seq_offset:
            pkt = SSHPacket(
                sender=pkt.sender,
                kind=pkt.kind,
                encrypted=pkt.encrypted,
                payload=pkt.payload,
                seq=pkt.seq + self.server_view_client_seq_offset
            )

        out.append(pkt)
        return out

    def intercept_s2c(self, pkt: SSHPacket) -> List[SSHPacket]:
        out = []

        if not self.enabled:
            out.append(pkt)
            return out

        if self.drop_ext_info and pkt.kind == "EXT_INFO":
            self.log.append(f"[MITM] Dropping packet from server: {pkt.short()}")
            self.client_view_server_seq_offset += 1
            return out

        if self.client_view_server_seq_offset:
            pkt = SSHPacket(
                sender=pkt.sender,
                kind=pkt.kind,
                encrypted=pkt.encrypted,
                payload=pkt.payload,
                seq=pkt.seq + self.client_view_server_seq_offset
            )

        out.append(pkt)
        return out


class SSHDemo:
    def __init__(self, strict_kex=False, mitm_enabled=True):
        self.client = SSHPeer("client", strict_kex=strict_kex)
        self.server = SSHPeer("server", strict_kex=strict_kex)
        self.mitm = MITMProxy(enabled=mitm_enabled)

    def deliver_c2s(self, pkt: SSHPacket):
        packets = self.mitm.intercept_c2s(pkt)
        for p in packets:
            self.server.receive(p)

    def deliver_s2c(self, pkt: SSHPacket):
        packets = self.mitm.intercept_s2c(pkt)
        for p in packets:
            self.client.receive(p)

    def run(self):
        try:
            # protocol version exchange
            self.deliver_c2s(self.client.send("VERSION"))
            self.deliver_s2c(self.server.send("VERSION"))

            # key exchange negotiation
            self.deliver_c2s(self.client.send("KEXINIT"))
            self.deliver_s2c(self.server.send("KEXINIT"))
            self.deliver_c2s(self.client.send("KEX_ECDH_INIT"))
            self.deliver_s2c(self.server.send("KEX_ECDH_REPLY"))

            # switch to encrypted channel
            self.deliver_c2s(self.client.send("NEWKEYS"))
            self.deliver_s2c(self.server.send("NEWKEYS"))

            # first encrypted packets
            self.deliver_s2c(self.server.send("EXT_INFO", encrypted=True))
            self.deliver_c2s(self.client.send("SERVICE_REQUEST", encrypted=True))
            self.deliver_s2c(self.server.send("SERVICE_ACCEPT", encrypted=True))
            self.deliver_c2s(self.client.send("USERAUTH_REQUEST", encrypted=True))

            return True, "session completed"
        except Exception as e:
            return False, str(e)

    def print_report(self, ok, message):
        print("\n==================== MITM LOG ====================")
        for line in self.mitm.log:
            print(line)

        print("\n==================== CLIENT LOG ====================")
        for line in self.client.log:
            print(line)

        print("\n==================== SERVER LOG ====================")
        for line in self.server.log:
            print(line)

        print("\n==================== SUMMARY ====================")
        print("Result:", "SUCCESS" if ok else "ABORTED")
        print("Message:", message)
        print("Client received encrypted packets:", self.client.received_encrypted)
        print("Server received encrypted packets:", self.server.received_encrypted)


if __name__ == "__main__":
    print("=== Scenario 1: vulnerable session, MITM active, no strict KEX ===")
    demo1 = SSHDemo(strict_kex=False, mitm_enabled=True)
    ok1, msg1 = demo1.run()
    demo1.print_report(ok1, msg1)

    print("\n\n=== Scenario 2: protected session, MITM active, strict KEX enabled ===")
    demo2 = SSHDemo(strict_kex=True, mitm_enabled=True)
    ok2, msg2 = demo2.run()
    demo2.print_report(ok2, msg2)

    print("\n\n=== Scenario 3: normal session, no MITM ===")
    demo3 = SSHDemo(strict_kex=False, mitm_enabled=False)
    ok3, msg3 = demo3.run()
    demo3.print_report(ok3, msg3)