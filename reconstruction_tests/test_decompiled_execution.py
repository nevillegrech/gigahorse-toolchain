"""Execute the printed decompiled view and compare it with independent Py-EVM runs.

DecompiledMachine runs exactly the statement trees in decompiled.sol.txt; hidden
memory plumbing is not executed. Matching outputs, reverts, logs, storage and
external calls on these inputs checks the view's expressions *and* abstractions
on those paths. External results are replayed from the EVM. This is bounded
validation with synthetic storage, not an equivalence proof.
"""

import hashlib

import pytest

pytest.importorskip("eth_tester", reason="install the validation extra for independent EVM tests")
from eth_abi import encode
from eth_hash.auto import keccak

from reconstruction.highlevel.interpreter import DecompiledMachine
from reconstruction.validation import ExternalOutcome
from reconstruction_tests.decompiled_support import DEPLOYED_NEXT, deployed_fixture
from reconstruction_tests.test_execution import EVMReference
from reconstruction_tests.test_interaction_execution import trace_call
from reconstruction_tests.test_weth_execution import deploy_runtime

MASK = (1 << 256) - 1


class Harness:
    def __init__(self, decompiled, reference, initial, monkeypatch):
        self.decompiled, self.reference, self.monkeypatch = decompiled, reference, monkeypatch
        self.state = dict(initial)
        self.initial = initial
        self.cases = self.calls = self.logs = self.reverts = 0

    def check(self, data, *, sender, value=0, code_sizes=None):
        reference = self.reference
        reference.sender = sender
        output, reverted, observed, _gas = trace_call(reference, data, value, self.monkeypatch)
        expected_logs = [
            (int.from_bytes(address), tuple(topics), payload)
            for address, topics, payload in reference.logs
        ]
        pending = iter(observed)

        def replay(invocation):
            actual = next(pending)
            for name in ("opcode", "target", "value", "calldata"):
                assert getattr(invocation, name) == actual[name], (data.hex(), name)
            return ExternalOutcome(actual["returndata"], actual["success"])

        machine = DecompiledMachine(self.decompiled, external_handler=replay)
        result = machine.execute(
            data,
            storage=self.state,
            caller=int(sender, 16),
            address=int(reference.address, 16),
            value=value,
            code_sizes=code_sizes,
        )
        assert next(pending, None) is None, data.hex()
        assert (result.output, result.reverted) == (output, reverted), (data.hex(), sender)
        assert [(log.address, log.topics, log.data) for log in result.logs] == expected_logs
        assert reference.commit(data, value) == int(not reverted)
        touched = set(self.initial) | set(result.storage)
        for slot in touched:
            assert result.storage.get(slot, 0) == reference.storage(slot), (data.hex(), slot)
        self.state = result.storage
        self.cases += 1
        self.calls += len(observed)
        self.logs += len(expected_logs)
        self.reverts += reverted


def test_weth_decompiled_view_matches_evm(tmp_path, monkeypatch, record_property):
    _, decompiled, runtime = deployed_fixture(DEPLOYED_NEXT, "weth9", tmp_path / "relations")
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    user, recipient, spender = reference.tester.get_accounts()[:3]
    zero = "0x" + "00" * 20
    user_slot = int.from_bytes(keccak(int(user, 16).to_bytes(32) + (3).to_bytes(32)))
    initial = {2: 18, user_slot: 1000}
    deploy_runtime(reference, runtime, initial)
    harness = Harness(decompiled, reference, initial, monkeypatch)

    def check(selector="", types=(), arguments=(), *, sender=user, value=0, raw=None):
        data = raw if raw is not None else bytes.fromhex(selector) + encode(types, arguments)
        harness.check(data, sender=sender, value=value)

    check("2e1a7d4d", ["uint256"], [1])  # ETH transfer fails with an empty balance.
    check(value=7)
    check(raw=b"\x00", value=3)
    check("deadbeef", value=11)
    for value in (0, 5, 17):
        check("d0e30db0", value=value)
    for account in (user, recipient, zero):
        check("70a08231", ["address"], [account])
    for amount in (0, 5, MASK):
        check("095ea7b3", ["address", "uint256"], [spender, amount])
        check("dd62ed3e", ["address", "address"], [user, spender])
        for transferred in (0, 3, 8, 2000):
            check(
                "23b872dd",
                ["address", "address", "uint256"],
                [user, recipient, transferred],
                sender=spender,
            )
    for account in (user, recipient, zero):
        for amount in (0, 1, 100000):
            check("a9059cbb", ["address", "uint256"], [account, amount])
    for amount in (0, 2, 1000, MASK):
        check("2e1a7d4d", ["uint256"], [amount])
    check("2e1a7d4d", ["uint256"], [0], value=1)
    check("a9059cbb", raw=bytes.fromhex("a9059cbb"))
    # Dirty upper address bits: the old compiler masks at every use.
    check("a9059cbb", ["uint256", "uint256"], [(1 << 200) | int(recipient, 16), 1])
    check("313ce567")
    assert harness.calls >= 3 and harness.logs > 10 and harness.reverts > 10
    record_property("decompiled_weth_cases", harness.cases)
    record_property("decompiled_weth_external_calls", harness.calls)
    record_property("decompiled_weth_logs", harness.logs)
    record_property("decompiled_weth_reverted_cases", harness.reverts)
    record_property("bytecode_sha256", hashlib.sha256(runtime).hexdigest())


def test_nft_token_uri_string_handling_matches_evm(tmp_path, monkeypatch, record_property):
    """tokenURI exercises storage-string copies, toString and concatenation (MCOPY idioms)."""
    from reconstruction.highlevel.idioms import sample, storage_string
    from reconstruction_tests.decompiled_support import DEPLOYED_NEXT as CORPUS

    _, decompiled, runtime = deployed_fixture(CORPUS, "erc721-collection", tmp_path / "relations")
    reference = EVMReference({"creation_bytecode": "60006000f3"})
    user = reference.tester.get_accounts()[0]

    def mapping_slot(key: int, slot: int) -> int:
        return int.from_bytes(keccak(key.to_bytes(32) + slot.to_bytes(32)))

    cases = 0
    for base_length in (0, 7, 31, 45):
        for uri_length in (0, 3, 40):
            for token in (0, 7, 1234567, (1 << 256) - 1):
                initial: dict[int, int] = {}
                if base_length:
                    initial.update(storage_string(9, b"ipfs://" + sample(base_length - 7, 9)))
                initial[mapping_slot(token, 3)] = 1  # token exists (EnumerableMap index)
                if uri_length:
                    initial.update(
                        storage_string(mapping_slot(token, 8), sample(uri_length, token & 255))
                    )
                reference = EVMReference({"creation_bytecode": "60006000f3"})
                deploy_runtime(reference, runtime, initial)
                harness = Harness(decompiled, reference, initial, monkeypatch)
                harness.check(bytes.fromhex("c87b56dd") + encode(["uint256"], [token]), sender=user)
                cases += 1
    record_property("decompiled_nft_token_uri_cases", cases)


def test_pair_skim_split_shared_regions_match_evm(tmp_path, monkeypatch, record_property):
    """skim enters deduplicated balanceOf/sub/_safeTransfer code from two call sites.

    The native CFG merges both sites into one region left by multi-target JUMPs;
    the view prints one tail-duplicated copy per site. Stub tokens return a fixed
    word from slot 0 for every call (balance, and the transfer result), return
    nothing, or revert.
    """
    from reconstruction_tests.decompiled_support import DEPLOYED

    _, decompiled, runtime = deployed_fixture(DEPLOYED, "uniswap-v2-pair", tmp_path / "relations")
    returning = bytes.fromhex("60005460005260206000f3")  # return SLOAD(0)
    empty, reverting = bytes.fromhex("00"), bytes.fromhex("60006000fd")
    cases = calls = reverts = 0
    for locked in (False, True):
        for reserves in ((0, 0), (10, 7)):
            for stubs in (
                ((returning, 10), (returning, 7)),
                ((returning, 15), (returning, 9)),
                ((returning, 9), (returning, 7)),  # balance below reserve: sub underflow
                ((returning, 12), (returning, 6)),
                ((returning, 0), (returning, 0)),  # transfer returns false
                ((empty, 0), (returning, 9)),
                ((returning, 11), (reverting, 0)),
            ):
                reference = EVMReference({"creation_bytecode": "60006000f3"})
                user, recipient = reference.tester.get_accounts()[:2]
                tokens = []
                for code, balance in stubs:
                    deploy_runtime(reference, code, {0: balance} if balance else {})
                    tokens.append(int(reference.address, 16))
                packed = reserves[0] | (reserves[1] << 112) | (1234 << 224)
                initial = {6: tokens[0], 7: tokens[1], 8: packed, 12: int(not locked)}
                deploy_runtime(reference, runtime, initial)
                harness = Harness(decompiled, reference, initial, monkeypatch)
                sizes = {
                    token: len(reference.backend.get_code(token.to_bytes(20))) for token in tokens
                }
                harness.check(
                    bytes.fromhex("bc25cf77") + encode(["address"], [recipient]),
                    sender=user,
                    code_sizes=sizes,
                )
                cases += 1
                calls += harness.calls
                reverts += harness.reverts
    # Both copies ran (two balanceOf + two transfer calls) and failure paths in each.
    assert calls >= 4 * 4 and 0 < reverts < cases
    record_property("decompiled_pair_skim_cases", cases)
    record_property("decompiled_pair_skim_external_calls", calls)


MORPHO = 0xD50F2DFFFD62F94EE4AED9CA05C61D0753268ABC


def returning(blob: bytes) -> bytes:
    """Runtime that returns `blob` for every call (CODECOPY of its own tail)."""
    size = len(blob).to_bytes(2)
    return (
        b"\x61"
        + size
        + bytes.fromhex("600e600039")
        + b"\x61"
        + size
        + bytes.fromhex("6000f3")
        + blob
    )


def words(*values: int) -> bytes:
    return b"".join(v.to_bytes(32) for v in values)


class StubbedReference(EVMReference):
    """Py-EVM with stub contracts placed at fixed addresses (e.g. a hard-coded Morpho)."""

    def __init__(self, codes: dict[int, bytes]):
        from eth_tester import EthereumTester, PyEVMBackend

        state = PyEVMBackend.generate_genesis_state(num_accounts=4)
        for address, code in codes.items():
            # Funded: spoofed senders (e.g. Morpho's address) pay for gas.
            state[address.to_bytes(20)] = {
                "balance": 10**21,
                "nonce": 0,
                "code": code,
                "storage": {},
            }
        self.backend = PyEVMBackend(genesis_state=state)
        self.tester = EthereumTester(backend=self.backend)
        self.sender = self.tester.get_accounts()[0]


def test_morpho_liquidator_view_matches_evm(tmp_path, monkeypatch, record_property):
    """The Dedaub-comparison contract: callback ABI decoding, approvals, liquidate and swap
    calls, the owner entry point with flash loan and min-profit check, and sweep.

    Morpho and the tokens are stubs that return a fixed blob for every call; the
    other parties are code-less accounts (calls to them succeed with no data).
    None of these functions writes storage, so cases are compared without commits.
    """
    from reconstruction_tests.decompiled_support import DEDAUB

    _, decompiled, runtime = deployed_fixture(DEDAUB, "morpho-liquidator", tmp_path / "relations")
    token_one, token_zero, token_seven = 0x1001, 0x1000, 0x1007
    reverter, swapper, borrower, collateral = 0xDEAD, 0xBEEF, 0xB0B, 0xC011
    tuple_type = "(bytes32,address,uint256,address,bytes,address,address)"
    stats = {"cases": 0, "calls": 0, "reverts": 0}

    def a(address: int) -> bytes:
        return address.to_bytes(20)

    def run(reference, data, sender, sizes):
        reference.sender = "0x" + sender.to_bytes(20).hex()
        output, reverted, observed, _gas = trace_call(reference, data, 0, monkeypatch)
        pending = iter(observed)

        def replay(invocation):
            actual = next(pending)
            for name in ("opcode", "target", "value", "calldata"):
                assert getattr(invocation, name) == actual[name], (data.hex(), name)
            return ExternalOutcome(actual["returndata"], actual["success"])

        machine = DecompiledMachine(decompiled, external_handler=replay)
        result = machine.execute(
            data,
            storage=dict(initial),
            caller=sender,
            address=int(reference.address, 16),
            code_sizes=sizes,
        )
        assert next(pending, None) is None, data.hex()
        assert (result.output, result.reverted) == (output, reverted), data.hex()
        assert result.logs == [] and not reference.logs
        stats["cases"] += 1
        stats["calls"] += len(observed)
        stats["reverts"] += reverted

    blobs = {
        "valid": words(token_one, collateral, 0x0AC1E, 0x1A4, 86 * 10**16),
        "dirty-address": words((1 << 200) | token_one, collateral, 0, 0, 0),
        "short": words(token_one, collateral),
    }
    for blob in blobs.values():
        codes = {
            MORPHO: returning(blob),
            token_one: returning(words(1)),
            token_zero: returning(words(0)),
            token_seven: returning(words(7)),
            reverter: bytes.fromhex("60006000fd"),
            borrower: b"",  # a funded account without code (also a non-owner sender)
        }
        reference = StubbedReference(codes)
        owner = int(reference.tester.get_accounts()[1], 16)
        initial = {0: owner}
        deploy_runtime(reference, runtime, initial)
        sizes = {address: len(code) for address, code in codes.items()}
        sizes |= {swapper: 0, collateral: 0, owner: 0}

        # onMorphoFlashLoan(uint256 assets, bytes data): only Morpho may call it.
        for swap_data in (b"", b"\x01" * 5, bytes(range(40)), bytes(range(100))):
            for target, token_a, token_b in (
                (swapper, swapper, collateral),
                (reverter, swapper, collateral),  # swap fails
                (swapper, reverter, collateral),  # first approve fails
                (swapper, swapper, reverter),  # second approve fails
            ):
                callback = encode(
                    [tuple_type],
                    [(b"\x11" * 32, a(borrower), 77, a(target), swap_data, a(token_a), a(token_b))],
                )
                data = bytes.fromhex("31f57072") + encode(["uint256", "bytes"], [5, callback])
                run(reference, data, MORPHO, sizes)
            run(reference, data, owner, sizes)  # !morpho
        # Malformed callbacks: truncated tuple head, offset past the end.
        good = encode(
            [tuple_type],
            [(b"\x11" * 32, a(borrower), 77, a(swapper), b"ab", a(swapper), a(swapper))],
        )
        for callback in (good[:200], words(0x1000) + good[32:]):
            data = bytes.fromhex("31f57072") + encode(["uint256", "bytes"], [5, callback])
            run(reference, data, MORPHO, sizes)

        # 0x441c1495(id, borrower, seized, flash amount, swap target, swap data, min profit).
        for sender in (owner, borrower):
            for min_profit in (0, 1, 2):
                for swap_data in (b"", bytes(range(37))):
                    data = bytes.fromhex("441c1495") + encode(
                        ["bytes32", "address", "uint256", "uint256", "address", "bytes", "uint256"],
                        [b"\x22" * 32, a(borrower), 9, 1000, a(swapper), swap_data, min_profit],
                    )
                    run(reference, data, sender, sizes)

        # sweep(token): balance and transfer through stub tokens.
        for token in (token_one, token_zero, token_seven, reverter):
            for sender in (owner, borrower):
                data = bytes.fromhex("01681a62") + encode(["address"], [a(token)])
                run(reference, data, sender, sizes)
        run(reference, bytes.fromhex("8da5cb5b"), owner, sizes)  # owner()
        run(reference, bytes.fromhex("3acb5624"), owner, sizes)  # MORPHO()
        run(reference, b"", owner, sizes)

    assert stats["calls"] > 100 and 0 < stats["reverts"] < stats["cases"]
    record_property("decompiled_morpho_cases", stats["cases"])
    record_property("decompiled_morpho_external_calls", stats["calls"])
    record_property("decompiled_morpho_reverted_cases", stats["reverts"])
