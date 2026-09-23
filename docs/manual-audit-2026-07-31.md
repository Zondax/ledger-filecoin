# Manual Security & Code-Quality Review — ledger-filecoin

**Repository:** Zondax/ledger-filecoin  
**Branch:** `audit/filecoin-main-2026-07-31` (from `origin/main`)  
**Commit:** `f35a2533`  
**Date:** 2026-07-31  
**App version:** 2.3.12  
**Language:** C (native FIL CBOR + FEVM / ERC20 / EIP-191 via zxlib EVM)  
**Method:** Same ledger-app-audit pipeline as cosmos/ICP (recon → parallel hunt → refute → report). Focus on full APDU→parse→display→sign paths, including non-obvious valid txs (InvokeEVM, raw bytes, map params, EIP-1559 ERC20).

**No application source was modified.** Artifacts under untracked `.audit/`.

---

## Executive summary

ledger-filecoin has a **`review_pending` gate** for successful async reviews (CLA APDUs rejected while true). Residual risk clusters:

1. **Async error UI without the lock (High / Critical-candidate UX race)** — expert-mode and blindsign **error** screens set `IO_ASYNCH_REPLY` but **never set `review_pending`**. Host can start another sign while the error modal is up (worse over BLE).
2. **Cross-INS / cross-CLA chunk sessions (High)** — separate FIL vs EVM `tx_initialized` flags on one buffer; CLA_ETH can drive some FIL INS; multi-chunk assembly unlocked.
3. **WYSIWYS gaps (High)** — ETH ERC20 clear-sign can hide **native value**; **params trailing bytes** and **map param under-display**; item count overflow → **empty review**.
4. **Crypto mostly sound** — Blake2b+CID domain separation, key zeroize, ERC20 exact 68-byte gate, f0 high-byte checks, outer CBOR EOF. Residuals: unchecked `blake_hash` return, ETH EIP-191 first-chunk length under-subtract, raw_bytes session hygiene.

**Correction (remediation pass):** F07 was filed under (3) as a fee-label
issue. It is actually a **NULL-pointer dereference at parse time on any
EIP-1559 ERC20 transfer** — a live defect for ordinary users, not an
adversarial one, and the highest-priority item in this report. See
[F07](#f07).

| Severity | Count |
|---|---:|
| Critical | **1** (F07, re-rated; error-UI race remains High / Critical-candidate) |
| High | **7** |
| Medium | **8** |
| Low | **1** |
| Info | **3** |

### Critical *candidates*

| ID | Why |
|---|---|
| F01+F02 | Unlocked async error UI → substitute review under user buttons (esp. BLE) |
| F04 | Clear-sign ERC20 while attaching native value (theft if user trusts token amount only) |
| F08 | Empty review after item-count overflow |

---

## Findings index

| # | Sev | Finding | Location |
|---|---|---|---|
| [F01](#f01) | High | Expert/blindsign error UI without `review_pending` | `apdu_handler.c:226` |
| [F02](#f02) | High | ETH blindsign error never sets `review_pending` | `apdu_handler.c:402` |
| [F03](#f03) | High | FIL vs EVM separate chunk flags, shared buffer | `apdu_handler.c` + zxlib EVM |
| [F04](#f04) | High | ERC20 clear-sign allows non-zero native value | `zxlib/evm/evm_erc20.c` |
| [F05](#f05) | High | Trailing bytes inside `params` signed unshown | `parser_impl.c:275` |
| [F06](#f06) | High | Map params: pairs vs item walk under-displays | `parser_impl.c:283` |
| [F07](#f07) | **Critical** | EIP-1559 ERC20 clear-sign dereferences a NULL `gasPrice` at parse time | `parser_impl_evm_specific.c` |
| [F08](#f08) | High | `num_items` overflow → 0 → empty validate | `parser_impl.c:434` |
| [F09](#f09) | Medium | Gas Limit shown as FIL with 18 decimals | `parser.c:231` |
| [F10](#f10) | Medium | InvokeEVM ERC20 hides fee cap non-expert | `parser_invoke_evm.c` |
| [F11](#f11) | Medium | Shared `tx_initialized` FIL vs raw_bytes | `apdu_handler.c` |
| [F12](#f12) | Medium | IO_RESET incomplete session clear | `apdu_handler.c:428` |
| [F13](#f13) | Medium | CLA_ETH can drive FIL INS | `apdu_handler.c:329` |
| [F14](#f14) | Medium | raw_bytes `msg_counter` / session hygiene | `apdu_handler.c:245` |
| [F15](#f15) | Medium | ETH path weaker than FIL (no hardened account) | zxlib `apdu_handler_evm.c` |
| [F17](#f17) | Medium | ETH EIP-191 first-chunk length under-subtract | zxlib `apdu_handler_evm.c` |
| [F16](#f16) | Low | `crypto_sign` ignores `blake_hash` return | `crypto.c:194` |
| [F18](#f18) | Info | ERC20 exact 68-byte gate (trailing OK) | `evm_erc20.c` |
| [F19](#f19) | Info | Success-path `review_pending` present | `apdu_handler.c:338` |
| [F20](#f20) | Info | `print0xToF0` high-byte zeros | `fil_utils.c:93` |

---

<a name="f01"></a>
## F01 — High — Async error UI without review lock

**Site:** `app/src/apdu_handler.c:226-232` (expert), `274-279` (raw blindsign), `303-308` (FVM EIP-191)

Sets `IO_ASYNCH_REPLY` + error UI, then `THROW` **without** `review_pending = true`. Success paths set the flag at L239/L287/L316. While the modal is up, `handleApdu` does not reject new APDUs.

### Suggested improvement

Set `review_pending` before every async UI; clear only in `app_reply_error` / reject paths.

---

<a name="f02"></a>
## F02 — High — ETH blindsign errors skip lock assignment

**Site:** `apdu_handler.c:402-405`  

`review_pending` is assigned **after** `handleSignEth` returns; blindsign failures `THROW` inside the handler, so the assignment never runs.

---

<a name="f03"></a>
## F03 — High — Dual chunk flags / shared buffer

FIL (`apdu_handler.c`) and ETH (zxlib `apdu_handler_evm.c`) maintain separate `tx_initialized` while using the same buffering. Mid-stream interleaving is possible because multi-chunk assembly is not locked.

---

<a name="f04"></a>
## F04 — High — ERC20 clear-sign + native value

**Site:** `deps/ledger-zxlib/evm/evm_erc20.c` `validateERC20`  

No check that RLP `value` is empty. UI shows token transfer only. **InvokeEVM** path correctly requires `value.len == 0`.

---

<a name="f05"></a>
## F05 — High — Params trailing bytes

Outer message EOF is checked (`parser_impl.c:397`). The **params** blob’s root CBOR item is not required to consume the whole params buffer — suffix garbage is signed and not listed as its own field.

---

<a name="f06"></a>
## F06 — High — Map params display

`numparams = mapLength` (pairs) but `_printParam` walks **single** CBOR items. With N pairs (2N items), only N screens → incomplete map review.

---

<a name="f07"></a>
## F07 — Critical — EIP-1559 ERC20 dereferences a NULL `gasPrice`

Originally filed as a display issue ("prints legacy `gasPrice`, often 0"). Code
review during remediation showed it is worse: `gasPrice` for a type 0x02
transaction is not zero, it is **unset**.

`_readEth` (`parser_impl_evm.c:203`) zeroes `eth_tx_obj`, and `parse_1559`
(`:150-171`) reads `max_priority_fee_per_gas` / `max_fee_per_gas` and never
touches `gasPrice`. Since `RLP_KIND_BYTE == 0` (`rlp_def.h:27`), the zeroed
field is `{kind: RLP_KIND_BYTE, ptr: NULL, rlpLen: 0}`, which
`rlp_readUInt256` handles as `tmpBuffer[31] = *rlp->ptr` (`rlp.c:141`) — a read
through a NULL pointer.

Reached from `printERC20TransferAppSpecific` case 4, which passed `&gasPrice`
for every transaction type. `parser_validate_eth` walks all items at parse
time, so it triggers **before any UI**, on an ordinary EIP-1559 ERC20 transfer
on FEVM (chain 314 / 314159). No attacker required.

**Fixed** by branching the fee screen on `tx_type` so `gasPrice` is never read
for 1559. The NULL guard in `rlp_readUInt256` belongs in zxlib and is still
open — see the cross-app queue.

---

<a name="f08"></a>
## F08 — High — Item count overflow → empty review

`_getNumItems` returns **0** when total > 255; `parser_getNumItems` accepts 0; `parser_validate` loops zero times and returns OK. Large param arrays can approve with **no fields**.

---

## Medium / low (condensed)

| ID | Issue | Fix sketch |
|---|---|---|
| F09 | Gas Limit as FIL 18-dec | Integer gas units |
| F10 | InvokeEVM hides fee cap non-expert | Always show fee cap |
| F11 | Shared FIL/raw `tx_initialized` | Per-INS session |
| F12 | IO_RESET incomplete reset | Full session clear |
| F13 | CLA_ETH → FIL INS | CLA allowlists |
| F14 | raw_bytes msg_counter hygiene | Reset on error/INIT |
| F15 | ETH path no hardened account | Match FIL policy |
| F17 | ETH EIP-191 length under-subtract | Reject body > declared |
| F16 | Unchecked `blake_hash` | `CHECK_ZXERR` |

---

## What looks solid

- Success-path **`review_pending`** for reviews  
- Outer FIL CBOR **EOF** check  
- **ERC20 exact 68-byte** clear-sign gate (no trailing calldata on clear path)  
- InvokeEVM ERC20 **requires zero native value**  
- **f0** rendering requires `0xFF` + high zeros  
- FIL path: 44'/461' or testnet + **hardened account**  
- Sign: Blake2b → CID-prefixed Blake2b → ECDSA; key buffers wiped with `sizeof`  
- Distinct FVM vs ETH personal-message domains  
- Raw-bytes requires **blindsign** mode  

---

## Adversarial / full-path matrix

| Scenario | Original outcome | Status |
|---|---|---|
| BLE CLA APDU during **success** review | **SAFE** — rejected | unchanged |
| APDU during **expert/blindsign error** UI | **UNSAFE** — F01/F02 | **FIXED** |
| Interleave FIL/ETH chunks | **UNSAFE** — F03 | **FIXED** (re-rated, see below) |
| ERC20 + native value (ETH) | **UNSAFE** — F04 | **FIXED** app-side |
| Params with trailing garbage | **UNSAFE** — F05 | **FIXED** |
| Map-encoded params | **UNDER-DISPLAY** — F06 | **FIXED** |
| EIP-1559 ERC20 clear-sign | **MISLEADING FEES** — F07 | **FIXED** — was a NULL deref, see below |
| Huge params array (item wrap) | **EMPTY REVIEW** — F08 | **FIXED** |
| ERC20 + trailing calldata >68 | **SAFE** — not clear-signed | unchanged |
| InvokeEVM ERC20 + value | **SAFE** — rejected | unchanged |
| Non-canonical f0 address | **SAFE** — print fails closed | unchanged |
| Raw-bytes without blindsign | **SAFE** — mode required | unchanged |

### Re-rating after code review of the matrix rows

**F07 is not a display bug — it is a NULL-pointer dereference.** `_readEth`
zeroes `eth_tx_obj` and `parse_1559` never assigns `gasPrice`, so for a type
0x02 transaction that field is `{kind: RLP_KIND_BYTE (== 0), ptr: NULL,
rlpLen: 0}`. The old ERC20 screen passed it to `printRLPNumber` unconditionally
→ `rlp_readUInt256` → `rlp.c:141` `tmpBuffer[31] = *rlp->ptr`. It fires inside
`parser_validate_eth`, which walks every item at **parse** time, so it is
reached before any UI on any EIP-1559 ERC20 transfer — an ordinary FEVM
transaction, no attacker needed. It survived because every one of the 500
vectors in `tests/testvectors/evm.json` is legacy (`f8…`) and the two 1559
vectors in `eth_tests.test.ts` are ERC-721, which fails `validateERC20` and
takes the blind-sign hash path.

**F03 is weaker than rated.** Every `P1_INIT` / `P1_ETH_FIRST` already calls
`tx_reset()`, and the `!tx_initialized` guard blocks finishing an ETH stream
with a FIL `P1_LAST`; no display-vs-signed mismatch could be constructed from
FIL↔ETH interleaving. The real hole was in the **FIL ↔ raw_bytes** pair
(F11/F14), which shared `tx_initialized` *and* `msg_counter`: a failed
`raw_bytes_init` left `msg_counter == 1` with the hasher live but the
`"Filecoin Sign Bytes:\n"` prefix unchecked, so a later `P1_ADD` took the
`tx_rawbytes_update` branch. That prefix is the only domain separation between
raw-byte signing and transaction signing — `crypto_sign` and `_readRawBytes`
both produce `CID(blake2b(..))` for the same `_sign`. Exploitation needs
blind-sign enabled and control of the aliased `total`/`current` through the
`parser_tx_obj` union, so: hard to reach, but the fix is cheap.

Because the residual FIL↔ETH exposure is not a WYSIWYS break — whichever kind
closes the stream is the kind the buffer is parsed, displayed and signed as —
the remediation does **not** track a per-payload-kind stream owner. It uses the
same three-state machine as `ledger-cosmos`, which blocks opening a second
stream while one is in flight, and closes the prefix bypass separately with the
raw-bytes `initialized` flag. `ledger-icp` carries only the review-lock half of
this (`g_review_pending`); its chunk handling still uses a bare
`tx_initialized` bool, so F03/F11/F14 remain open there.

---

## Fixes applied

App-only; `deps/ledger-zxlib` is untouched.

| ID | Fix | File |
|---|---|---|
| F01, F02, F03, F11, F13, F14 | Adopted the `tx_state_e` state machine from `ledger-cosmos` (`24ccb719`): one `g_tx_state` of `IDLE` / `RECEIVING` / `REVIEWING` replaces the old `review_pending` and `tx_initialized` flags. `P1_INIT` requires `IDLE`, continuation chunks require `RECEIVING`, `REVIEWING` is the lock and is claimed only once `view_review_show()` returns, and only the reply paths in `actions.h` hand the state back. `CATCH_OTHER` promotes to `REVIEWING` whenever a handler threw with `IO_ASYNCH_REPLY` set — that is the F01/F02 fix, covering the error modals here and in zxlib — and otherwise resets to `IDLE` except on OK / `COMMAND_NOT_ALLOWED`. FIL instructions are additionally gated to `CLA`. | `apdu_handler.c`, `common/actions.h` |
| F14 | raw-bytes state carries an `initialized` flag set only after the prefix check passes; `raw_bytes_update` and `_readRawBytes` refuse a session without it, replacing the `msg_counter == 1` sentinel | `parser_raw_bytes.c`, `parser_txdef.h` |
| F04 | `isClearSignableERC20` additionally requires a zero native `value`; a transfer carrying FIL falls back to the blind-sign hash (with the warning UI re-armed) instead of showing only the token amount | `evm/parser_impl_evm_specific.c` |
| F05 | the root params item must end exactly at `params + params_len`, so a suffix cannot be signed without a screen | `parser_impl.c` |
| F06 | map params count `2 * mapLength` screens, so keys and values are both reviewed | `parser_impl.c` |
| F07 | the ERC20 fee screen branches on `tx_type`: 1559 shows *Max fee per gas* + *Max priority fee*, legacy/2930 keep *Gas price*; `gasPrice` is never read for 1559 | `evm/parser_impl_evm_specific.c` |
| F08 | `parser_getNumItems` rejects a zero item count for `fil_tx`, mirroring `parser_evm.c:57` | `parser.c` |

### Regression tests added

`tests_zemu/tests/eth_tests.test.ts` had no EIP-1559 ERC20 coverage at all:

- `erc20_transfer_1559` (clear-sign) — the F07 crash path. Renders To / Value /
  Nonce / Max fee per gas / Max priority fee / Gas limit.
- `erc20_transfer_with_native_value` (blind-sign) — the F04 path. Must show the
  blind-sign warning and `Eth-Hash`, never a clear-signed token amount.

Snapshots generated for all five models (`sp`, `x`, `st`, `fl`, `ap`).

`tests_zemu/tests/apdu.test.ts` is new, ported from `ledger-cosmos`. It drives
the request state machine through raw APDU exchanges — no snapshots, one
container per device — covering: continuation chunks with no flow running, a
second `P1_INIT` against a flow in progress, get-address and a raw-bytes or ETH
first chunk arriving mid-flow, the Filecoin instructions rejected under
`CLA_ETH`, a truncated HD path leaving the device idle rather than locked, and
an unrelated error aborting a half-received transaction while
`COMMAND_NOT_ALLOWED` leaves it intact.

Verified as a real regression test: it passes on all five models with these
fixes and fails against unmodified HEAD at `raw-bytes under the eth class`,
where the unfixed app answers `0x9000` — an Ethereum-class APDU driving
Filecoin raw-bytes signing (F13).

Two status words are used deliberately. A continuation chunk with no flow
running keeps the pre-existing `TX_NOT_INITIALIZED` (`0x6987`) so the wire
contract for that case is unchanged for integrators; only "another request owns
the device" is the new `COMMAND_NOT_ALLOWED` (`0x6986`), which is also the one
status that preserves in-flight state in `CATCH_OTHER`.

One incidental finding: `handle_generic_apdu` in zxlib answers the reserved
`E0 01 00 00` get-device-info probe before `handleApdu` runs, so that exact
header never reaches the app's class check. Expected Ledger dashboard behaviour,
noted here because it looks like a CLA-gating hole from the outside.

**Unrelated defect found while running these:** `eth_tests.test.ts` does
`require("js-sha3")` but the package was never declared in
`tests_zemu/package.json`. Under yarn's flat hoisting it resolved transitively;
the pnpm migration (`c598f8ee`) made it strict, so every ETH clear-sign test had
been failing with `Cannot find module 'js-sha3'`. Added as a devDependency.

### Test status

Full zemu suite in CI with these fixes: **259 passed, 1 failed**. The single
failure is `Standard › Parse Bytes Params - issue #173 for nanox` failing with
`Timeout waiting to connect` inside `Zemu.start` — the emulator container never
came up, so no assertion ever ran. Infrastructure, not code.

Local runs during the audit were noisier — up to 9 failures across
`Standard InvokeEVM` / `InvokeEVM_ERC20Transfer` (`ExpertModeRequired`) and
`personal_sign_non_printable_msg` (`Blindsign Mode Required`). Those were
initially recorded here as pre-existing breakage, on the grounds that they
reproduce when every source change is stashed and the app is rebuilt from
unmodified HEAD.

**That conclusion was wrong, and CI corrects it.** Both groups pass in a clean
CI run. The stash-and-rebuild check only established that the failures were not
*caused* by this branch; it did not establish that they were deterministic. The
set of affected models moved between local runs, and the local Docker daemon
crashed twice during the audit. The failures track emulator instability under
concurrent container load, not a defect in the app or in the tests.

No separate issue is warranted. If the suite proves flaky in CI over time, the
lead is container startup under five-way concurrency, not the mode toggles.

---

## Cryptographic notes

| Control | Status |
|---|---|
| Domain: Blake2b + CID prefix for FIL tx/raw | OK |
| FVM `\x19Filecoin Signed Message:\n` vs ETH EIP-191 | Distinct |
| Private key zeroize | OK (`sizeof`) |
| Raw digest length must be 32 | OK |
| `blake_hash` return in `crypto_sign` | **Unchecked** (F16) |
| ETH EIP-191 first-chunk remaining math | **Weak** (F17) |

---

## Recommended fix order

1. Set `review_pending` on **all** async UI paths (including errors); full session reset on IO_RESET.  
2. Unify chunk session across FIL/ETH/raw; CLA allowlists.  
3. ERC20: require zero native value; fix 1559 fee display.  
4. Params: strict CBOR consume; fix map item counts; reject num_items overflow/0.  
5. Gas Limit label; fee cap always for InvokeEVM; hash return checks.

---

## Appendix A — Architectural brief

See `.audit/brief.md`.

## Coverage

| Area | Status |
|---|---|
| APDU / review_pending / CLA | Hunted |
| process_chunk / raw_bytes / ETH chunk | Hunted |
| FIL CBOR / params / InvokeEVM | Hunted |
| ERC20 / EIP-1559 / EIP-191 | Hunted |
| Crypto Blake2b / sign / path | Hunted |
| Device PoC / fuzz | Not run |

Machine findings: `.audit/findings.jsonl`  
Cross-app: `.audit/cross-app-queue.jsonl`
