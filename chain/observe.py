"""Read-only, finalized SDK identity observation; no wallet or submission API."""
import argparse
import asyncio
import hashlib
import json
import re
import signal
import sys
from importlib.metadata import version
from urllib.parse import urlsplit

from bittensor import RpcSubstrate
from websockets.asyncio.client import connect
from bittensor._transport.interface import SubstrateConnection
from bittensor._transport.runtime import RuntimeManager

LIMIT = 65536
HEX = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS = re.compile(r"[1-9A-HJ-NP-Za-km-z]{48}\Z")


class DirectConnect(connect):
    def process_redirect(self, exc):
        return exc  # Never follow even same-origin redirects.


def direct_connect(url):
    return DirectConnect(endpoint(url), max_size=16*1024*1024, max_queue=4,
                         proxy=None, open_timeout=10, close_timeout=2)


class PinnedRuntime(RuntimeManager):
    """Pinned SDK profile: fresh metadata, native codec, no ambient disk cache."""
    def __init__(self, session, head, policy):
        super().__init__(session, ss58_format=42)
        self.head, self.policy = head, policy
        self.pinned = None

    async def codec_at(self, block_hash):
        require(block_hash in (None, self.head), "Unapproved decoder block")
        if self.pinned is not None:
            return self.pinned
        p = self.policy
        genesis = await self._session.request("chain_getBlockHash", [0])
        require(digest_hash(genesis) == p["genesis"], "Decoder genesis mismatch")
        header = await self._session.request("chain_getHeader", [self.head])
        parent = header["parentHash"]
        digest_hash(parent)
        current = await self._session.request("state_getRuntimeVersion", [self.head])
        previous = await self._session.request("state_getRuntimeVersion", [parent])
        require(current == previous and type(current["specVersion"]) is int
                and current["specVersion"] == p["runtime"], "Decoder upgrade boundary or runtime mismatch")
        metadata = await self._session.request("state_getMetadata", [self.head])
        parent_metadata = await self._session.request("state_getMetadata", [parent])
        require(metadata == parent_metadata and type(metadata) is str and metadata.startswith("0x"), "Decoder metadata boundary")
        raw = bytes.fromhex(metadata[2:])
        require(hashlib.sha256(raw).hexdigest() == p["metadataSha256"], "Decoder metadata digest mismatch")
        self.pinned = self._make_codec(raw, current["specVersion"], current["transactionVersion"], spec_name=current["specName"])
        return self.pinned


class PinnedSubstrate(RpcSubstrate):
    def __init__(self, url, head, policy):
        require(version("bittensor") == "11.1.0" and version("bittensor-core") == "0.1.3"
                and version("websockets") == "16.1.1", "Unsupported SDK transport profile")
        super().__init__(url, fallback_endpoints=[], archive_endpoints=[], retry_forever=False)
        self.head, self.policy = head, policy

    def _interface(self, url, fallbacks):
        require(url == self.endpoint and not fallbacks, "Unapproved SDK endpoint")
        raw = SubstrateConnection(url, ss58_format=42, fallback_urls=[], retry_forever=False,
                                  max_retries=0, response_timeout=10, connect_factory=direct_connect)
        raw._runtimes = PinnedRuntime(raw._session, self.head, self.policy)
        return raw


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def policy(raw):
    require(len(raw) <= LIMIT, "Policy byte limit")
    p = json.loads(raw, object_pairs_hook=unique)
    require(type(p) is dict and set(p) == {
        "genesis", "netuid", "creationHeight", "creationHash", "owner",
        "ownerHotkey", "runtime", "metadataSha256", "hotkeys", "validator",
    }, "Exact operator policy required")
    for key in ("genesis", "creationHash", "metadataSha256"):
        require(type(p[key]) is str and HEX.fullmatch(p[key]), "Invalid policy digest")
    for key, ceiling in (("netuid", 65535), ("creationHeight", 2**32-1), ("runtime", 2**32-1)):
        require(type(p[key]) is int and 0 <= p[key] <= ceiling, "Invalid policy integer")
    require(type(p["hotkeys"]) is list and 1 <= len(p["hotkeys"]) <= 100, "Hotkey limit")
    for address in [p["owner"], p["ownerHotkey"], p["validator"], *p["hotkeys"]]:
        require(type(address) is str and ADDRESS.fullmatch(address), "Invalid address shape")
    require(len(set(p["hotkeys"])) == len(p["hotkeys"]), "Duplicate hotkey")
    require(p["validator"] in p["hotkeys"], "Validator must be observed")
    return p


def endpoint(value):
    u = urlsplit(value)
    require(u.scheme in ("ws", "wss") and u.hostname and not u.username and not u.password
            and not u.query and not u.fragment and u.path in ("", "/"), "Invalid operator endpoint")
    require(u.scheme == "wss" or u.hostname in ("127.0.0.1", "::1"), "Plaintext requires loopback")
    require(u.port is None or 1 <= u.port <= 65535, "Invalid endpoint port")
    return value


def digest_hash(value):
    require(type(value) is str and value.startswith("0x") and HEX.fullmatch(value[2:]), "Invalid chain hash")
    return value[2:]


async def observe(url, p):
    # ponytail: single operator-selected RPC trust; independent quorum belongs upstream.
    async with direct_connect(url) as ws:
        sequence = 0

        async def rpc(method, params):
            nonlocal sequence
            require(method in {"chain_getFinalizedHead", "chain_getHeader", "chain_getBlockHash",
                               "state_getRuntimeVersion", "state_getMetadata"}, "Read-only RPC required")
            sequence += 1
            await ws.send(json.dumps(dict(jsonrpc="2.0", id=sequence, method=method, params=params)))
            reply = json.loads(await ws.recv(), object_pairs_hook=unique)
            require(reply.get("jsonrpc") == "2.0" and reply.get("id") == sequence
                    and "error" not in reply and "result" in reply, "RPC response rejected")
            return reply["result"]

        head = await rpc("chain_getFinalizedHead", [])
        finalized_hash = digest_hash(head)
        genesis = digest_hash(await rpc("chain_getBlockHash", [0]))
        require(genesis == p["genesis"], "Genesis mismatch")
        header = await rpc("chain_getHeader", [head])
        height = int(header["number"], 16)
        require(p["creationHeight"] <= height, "Creation not finalized")
        runtime = await rpc("state_getRuntimeVersion", [head])
        require(type(runtime["specVersion"]) is int and runtime["specVersion"] == p["runtime"], "Runtime mismatch")
        metadata = await rpc("state_getMetadata", [head])
        require(type(metadata) is str and metadata.startswith("0x"), "Invalid metadata")
        require(hashlib.sha256(bytes.fromhex(metadata[2:])).hexdigest() == p["metadataSha256"], "Metadata mismatch")
        creation_hash = digest_hash(await rpc("chain_getBlockHash", [p["creationHeight"]]))
        require(creation_hash == p["creationHash"], "Subnet creation hash mismatch")

    sdk = PinnedSubstrate(url, head, p)
    try:
        await sdk.connect()
        require(digest_hash(await sdk.block_hash(0)) == genesis, "SDK endpoint genesis mismatch")

        async def query(name, params):
            return await sdk.query("SubtensorModule", name, params, block_hash=head)

        n = p["netuid"]
        require(await query("NetworksAdded", [n]) is True, "Subnet absent")
        created = await query("NetworkRegisteredAt", [n])
        require(type(created) is int and created == p["creationHeight"], "Subnet incarnation mismatch")
        require(await query("SubnetOwner", [n]) == p["owner"], "Subnet owner mismatch")
        require(await query("SubnetOwnerHotkey", [n]) == p["ownerHotkey"], "Subnet owner hotkey mismatch")
        count = await query("SubnetworkN", [n])
        require(type(count) is int and 1 <= count <= 65536, "Invalid subnet size")
        permits = await query("ValidatorPermit", [n])
        require(type(permits) is list and len(permits) == count and all(type(v) is bool for v in permits), "Invalid permits")
        members, uids = [], set()
        for hotkey in sorted(p["hotkeys"]):
            uid = await query("Uids", [n, hotkey])
            require(type(uid) is int and 0 <= uid < count and uid not in uids, "Hotkey UID absent or invalid")
            require(await query("Keys", [n, uid]) == hotkey, "Hotkey UID reverse mismatch")
            registered = await query("BlockAtRegistration", [n, uid])
            require(type(registered) is int and created <= registered <= height, "Registration block invalid")
            owner = await query("Owner", [hotkey])
            require(type(owner) is str and ADDRESS.fullmatch(owner), "Missing hotkey owner")
            registration_hash = digest_hash(await sdk.block_hash(registered))
            require(hotkey != p["validator"] or permits[uid], "Validator permit absent")
            members.append(dict(hotkey=hotkey, uid=uid, owner=owner, registrationHeight=registered,
                                registrationHash=registration_hash, validatorPermit=permits[uid]))
            uids.add(uid)
        return dict(schema="sentinel-chain-observation/v1", genesis=genesis, netuid=n,
                    finalizedHeight=height, finalizedHash=finalized_hash,
                    creationHeight=created, creationHash=creation_hash, owner=p["owner"],
                    ownerHotkey=p["ownerHotkey"], runtime=p["runtime"], metadataSha256=p["metadataSha256"],
                    validator=p["validator"], members=members,
                    limitation="RPC-observed finalized identity; not economic permission, Sentinel registration, weights or rewards.")
    finally:
        await sdk.close()


async def bounded_observe(url, p):
    async with asyncio.timeout(45):
        return await observe(url, p)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, type=endpoint, help="Operator-controlled RPC; never supplied by miners")
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(60)
    try:
        p = policy(sys.stdin.buffer.read(LIMIT + 1))
        result = asyncio.run(bounded_observe(args.endpoint, p))
        body = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        # Digest covers exact UTF-8 observation JSON, not the enclosing envelope.
        print(json.dumps(dict(sha256=hashlib.sha256(body).hexdigest(), observation=result), sort_keys=True, separators=(",", ":")))
    except Exception:
        # RPC errors may contain private endpoint/provider details. Keep stderr private-safe.
        print("Chain observation rejected; check private operator policy and RPC availability", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
