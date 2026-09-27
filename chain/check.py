"""Offline adversarial fixtures. Optional --endpoint runs real SDK reads with stdin policy."""
import asyncio
import hashlib
import json
import sys
from unittest.mock import patch

import observe

A = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
P = dict(genesis="a"*64, netuid=2, creationHeight=10, creationHash="b"*64,
         owner=A, ownerHotkey=A, runtime=424, metadataSha256=hashlib.sha256(b"fixture").hexdigest(),
         hotkeys=[A], validator=A)


def rejects(fn):
    try:
        fn()
    except (ValueError, TypeError):
        return
    raise AssertionError("Accepted adversarial input")


class Socket:
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def send(self, message): self.request = json.loads(message)
    async def recv(self):
        r = self.request
        results = {"chain_getFinalizedHead": "0x"+"c"*64, "chain_getHeader": {"number": "0x14"},
                   "state_getRuntimeVersion": {"specVersion": 424}, "state_getMetadata": "0x"+b"fixture".hex()}
        value = ("0x"+("a" if r["params"] == [0] else "b")*64) if r["method"] == "chain_getBlockHash" else results[r["method"]]
        return json.dumps(dict(jsonrpc="2.0", id=r["id"], result=value))


class SDK:
    values = dict(NetworksAdded=True, NetworkRegisteredAt=10, SubnetOwner=A, SubnetOwnerHotkey=A,
                  SubnetworkN=1, ValidatorPermit=[True], Uids=0, Keys=A, BlockAtRegistration=10, Owner=A)
    def __init__(self, url, head, policy):
        assert head == '0x'+'c'*64
    async def connect(self): pass
    async def close(self): pass
    async def block_hash(self, height): return "0x"+("a" if height == 0 else "b")*64
    async def query(self, module, storage, params, block_hash):
        assert module == "SubtensorModule" and block_hash == "0x"+"c"*64
        return self.values[storage]


async def fixtures():
    with patch.object(observe, "direct_connect", lambda *a, **k: Socket()), patch.object(observe, "PinnedSubstrate", SDK):
        result = await observe.bounded_observe("ws://127.0.0.1:9944", P)
        assert result["members"][0]["uid"] == 0
        for field, bad in [("NetworksAdded", False), ("NetworkRegisteredAt", 9), ("SubnetOwner", "bad"),
                           ("SubnetOwnerHotkey", "bad"), ("Uids", None), ("Uids", True), ("Uids", 1),
                           ("Keys", "bad"), ("BlockAtRegistration", 9), ("BlockAtRegistration", 21),
                           ("ValidatorPermit", [False]), ("Owner", None), ("SubnetworkN", 0)]:
            with patch.dict(SDK.values, {field: bad}):
                try: await observe.bounded_observe("ws://127.0.0.1:9944", P)
                except ValueError: pass
                else: raise AssertionError(field)
        for field, bad in [("genesis", "d"*64), ("creationHash", "d"*64), ("runtime", 425), ("metadataSha256", "d"*64)]:
            p = dict(P, **{field: bad})
            try: await observe.bounded_observe("ws://127.0.0.1:9944", p)
            except ValueError: pass
            else: raise AssertionError(field)


async def transport_checks():
    hits = []
    async def redirect(reader, writer):
        await reader.read(8192)
        writer.write(f'HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:{target.sockets[0].getsockname()[1]}\r\nContent-Length: 0\r\n\r\n'.encode())
        await writer.drain();writer.close();await writer.wait_closed()
    async def destination(reader, writer):
        hits.append(True);writer.close();await writer.wait_closed()
    target = await asyncio.start_server(destination, '127.0.0.1', 0)
    source = await asyncio.start_server(redirect, '127.0.0.1', 0)
    url = f'ws://127.0.0.1:{source.sockets[0].getsockname()[1]}'
    try:
        for sdk_mode in [False, True]:
            sdk = observe.PinnedSubstrate(url, '0x'+'c'*64, P)
            try:
                if sdk_mode: await sdk.connect()
                else:
                    async with observe.direct_connect(url): raise AssertionError('redirect accepted')
            except Exception as error:
                assert not isinstance(error, AssertionError)
            else: raise AssertionError('redirect accepted')
            finally: await sdk.close()
        assert not hits
    finally:
        source.close();target.close();await source.wait_closed();await target.wait_closed()
    class Session:
        mismatch = False
        async def request(self, method, params):
            if method == 'chain_getBlockHash': return '0x'+'a'*64
            if method == 'chain_getHeader': return {'parentHash':'0x'+'b'*64}
            if method == 'state_getRuntimeVersion':
                return dict(specVersion=425 if self.mismatch and params==['0x'+'b'*64] else 424,transactionVersion=1,specName='fixture')
            return '0x'+b'wrong-metadata'.hex()
    for mismatch in [False, True]:
        session=Session();session.mismatch=mismatch
        runtime=observe.PinnedRuntime(session,'0x'+'c'*64,P)
        try: await runtime.codec_at('0x'+'c'*64)
        except ValueError as error: assert ('runtime mismatch' if mismatch else 'digest mismatch') in str(error)
        else: raise AssertionError('decoder policy bypass')


assert observe.policy(json.dumps(P)) == P
for mutation in [dict(endpoint="wss://evil.invalid"), dict(netuid=True), dict(hotkeys=[A, A]), dict(wallet="secret"), dict(runtime=-1)]:
    rejects(lambda: observe.policy(json.dumps(dict(P, **mutation))))
for raw in ['{"genesis":1,"genesis":2}', "[]", " "*65537]:
    rejects(lambda: observe.policy(raw))
for url in ["ws://remote.invalid", "wss://user:pass@host", "wss://host/?token=x", "https://host", "wss://host/path", "wss://host/#x"]:
    rejects(lambda: observe.endpoint(url))
asyncio.run(fixtures())
asyncio.run(transport_checks())
print("Offline adversarial fixtures passed; no chain qualification claimed")
if len(sys.argv) > 1:
    assert len(sys.argv) == 3 and sys.argv[1] == "--endpoint"
    p = observe.policy(sys.stdin.buffer.read(observe.LIMIT + 1))
    result = asyncio.run(observe.bounded_observe(observe.endpoint(sys.argv[2]), p))
    print("Real read-only SDK observation passed at finalized height", result["finalizedHeight"])
