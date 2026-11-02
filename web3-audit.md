# Moraa — Web3 / smart-contract audit (Immunefi, Code4rena, Sherlock, Cantina, CodeHawks)

> Different economics from web2: payouts are TVL-scaled ($10K–$10M+), PoC-required norms are strict
> (runnable Foundry test, not a written description), and "centralization risk" (owner could
> theoretically rug) is a **design choice, not a bug** — don't report it. THE ONE RULE still
> decides: can an attacker do this RIGHT NOW with a runnable exploit test? If you can't write the
> Foundry PoC, you don't have a finding.

---

## 0. Target scoring — kill bad targets before reading code (10 min)

```
HARD KILL: TVL < $500K              → even Critical caps at 10% TVL = too small for the effort
HARD KILL: 2+ top-tier audits       → Trail of Bits/Halborn/Cyfrin/OZ catch 70-80% of classic bugs
                                       (exception: audit >1yr old + major code changes since)
HARD KILL: protocol < 500 LOC,      → single A→B→C flow, minimal attack surface
           single function flow
HARD KILL: max_realistic_payout     → formula: min(10% × TVL, program_cap). If < $10K, skip.
           below floor
```

**Score ≥6/10 to proceed** (else skip, 6-8 = 1-2 days, 9-10 = up to a week):
TVL >$10M (+2) · Immunefi Critical ≥$50K (+2) · no top-tier audit on current version (+2) ·
deployed <30 days ago (+1) · protocol you've hunted before (+1) · source + NatSpec available (+1) ·
upgradeable proxies present (+1).

## 1. Recon / scoping phase

```bash
git clone <target-repo> && cd target/
cloc src/ --include-lang=Solidity          # scope, line count
forge build && forge test                  # must compile; note existing coverage gaps
forge coverage --report summary            # untested paths = where bugs hide
git log --oneline -20                       # recent changes = under-reviewed code
```
1. **Docs first** — whitepaper, README, NatSpec. Gap between stated intent and implementation = bugs.
2. **Privileged roles** — owner, multisig, governance, any `onlyOwner`/`onlyRole` — who holds them,
   what can they do, is that centralization or an actual bypass of an *intended* restriction.
3. **Oracle dependencies** — Chainlink feed? Uniswap TWAP? Spot price? Note every price source now.
4. **Etherscan/Solscan**: verified source on the deployed address (unverified = decompile via Dedaub
   or skip), deployer wallet history, prior audit reports linked on the program page.
5. **Search Solodit** (solodit.cyfrin.io, 50K+ findings) for prior bugs on this protocol *type* —
   don't rediscover a known AMM/vault pattern from scratch.

## 2. Static analysis pass (15 min, before manual review)

```bash
slither . --exclude-low --filter-paths "test|lib|node_modules"
slither . --detect reentrancy-eth,unprotected-upgrade,arbitrary-send-eth,missing-protection
aderyn . --output report.md                      # Foundry-native, fast AST pass
myth analyze src/Contract.sol --max-depth 6       # symbolic execution, slower/deeper

# grep quick-hits — run before line-by-line review
grep -rn "tx\.origin" src/                                   # never valid for auth
grep -rn "\.call{value\|\.call(\|\.transfer(\|\.send(" src/  # external-call surface
grep -rn "nonReentrant\|ReentrancyGuard" src/                 # where guards DO exist (gaps = rest)
grep -rn "slot0\b\|getReserves()" src/                        # AMM spot price = manipulable
grep -rn "latestRoundData\|latestAnswer" src/ -A5 | grep -v "updatedAt"   # Chainlink w/o staleness
grep -rn "unchecked {" src/                                    # manually verify each block
grep -rn "delegatecall" src/                                   # target user-controlled?
grep -rn "ecrecover\|ECDSA\.recover" src/ -B5 | grep -v "chainId\|nonces"  # sig w/o replay guard
grep -rn "initialize(" src/ | grep -v "test"                   # proxy init — protected?
```

**If a Claude-native MCP audit tool is available** (`solidity-audit-mcp` — Slither+Aderyn+86 SWC
detectors+gas, `npm install -g solidity-audit-mcp`): `get_contract_info` first for the attack-surface
map (payable functions, delegatecall usage, external fns without modifiers), then
`analyze_contract(analyzers:[slither,aderyn,slang], detectorPreset:"defi")` for the merged,
deduped, severity-sorted report, then `generate_invariants(protocolType:"vault"|"amm"|"lending")`
for ready-to-paste Foundry invariant tests. `explain_finding("<SWC-id>"|keyword)` gives full
exploit-scenario + vulnerable/fixed code + PoC template for anything suspicious you hit manually.

## 3. THE ONE RULE

> **Read ALL sibling functions.** If `vote()` has a modifier, check `poke()`, `reset()`,
> `harvest()`. The missing modifier on the sibling IS the bug. Explains ~19% of all Criticals.

## 4. The 10 bug classes

### 1 — Accounting state desync (#1 Critical class, ~28% of all Criticals)
Two state vars must stay in sync; one code path updates A but not B; later code trusts stale B.
```solidity
// Alchemix pattern — early return skips state updates the "slow path" does correctly:
function claimRedemption(uint256 tokenId) external {
    if (transmuter.balance >= amount) {
        transmuter.transfer(user, amount); _burn(tokenId);
        return;   // cumulativeEarmarked, _redemptionWeight, totalDebt never updated
    }
    alchemist.redeem(...);   // slow path updates everything correctly
}
```
```bash
grep -rn "totalSupply\|totalShares\|totalAssets\|totalDebt\|cumulativeReward" src/
grep -rn "\breturn\b" src/ -B3 | grep -B3 "if\b"    # early returns — what state update do they skip?
```

### 2 — Access control (#2 Critical, ~19%, $953M lost in 2024)
```solidity
// Missing modifier on a sibling — Alchemix poke() had no onlyNewEpoch() → infinite FLUX inflation
function vote(uint256 id) external onlyNewEpoch(id) {}     // guarded
function poke(uint256 id) external {}                       // NOT guarded

// Existence check ≠ ownership check (ZeroLend split())
_requireOwned(tokenId);   // token EXISTS — doesn't mean caller owns it

// Silent modifier — non-admin falls through instead of reverting
modifier onlyAdmin() { if (msg.sender == admin) { _; } }    // should be require(...), _;

// Uninitialized proxy (Wormhole, $10M paid)
function initialize(address _owner) public { owner = _owner; }  // missing `initializer` modifier
```
```bash
grep -rn "function vote\|function poke\|function reset\|function claim\|function harvest" src/ -A2
grep -rn "_requireOwned\|ownerOf\|_isApprovedOrOwner" src/ -B5
grep -rn "modifier\b" src/ -A8 | grep -B3 "if (" | grep -v "require\|revert"
grep -rn "function initialize\b" src/ -A3; grep -rn "_disableInitializers()" src/
```

### 3 — Incomplete code path (#3 Critical, ~17%)
Function-family comparison: list A's (deposit/place/create) state changes, check B (withdraw/
update/cancel) reverses each one.
```solidity
// MetaPool: mint() bypasses the validation deposit() has
function deposit(uint256 assets, address r) public override { shares = _deposit(assets, r); }
function mint(uint256 shares, address r) public override {
    assets = convertToAssets(shares); _mint(r, shares);   // MISSING _deposit() validation
}
```
```bash
grep -rn "function place_\|function create_\|function add_" src/ -A5
grep -rn "function update_\|function modify_\|function cancel_" src/ -A5
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" src/ -A10
```

### 4 — Off-by-one / boundary conditions (#4 High, ~22%)
Mental test for every comparison: `if (A > B)` — what happens when `A == B`? Check: period/epoch
boundaries, timestamp==deadline, loop `break` conditions, `i <= array.length` (should be `<`),
exact-full-withdrawal boundary, rounding that can produce 0 where non-zero is expected.
```bash
grep -rn "Period\|Epoch\|Round\|Deadline" src/ -A3 | grep "[<>][^=]"
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" src/
```

### 5 — Oracle / price manipulation (12% of reports, largest individual payouts — $117M Mango, $70M Curve)
```solidity
// Missing staleness check — most common
(, int256 price,,,) = priceFeed.latestRoundData();  return uint256(price);   // VULNERABLE
// fix: require(block.timestamp - updatedAt <= MAX_PRICE_AGE); require(price > 0);

// Pyth: ignoring confidence interval
PythStructs.Price memory p = pyth.getPriceUnsafe(id); return p.price;        // ignores p.conf
// fix: require(p.conf * 10 <= uint64(p.price));  // conf >10% of price = untrustworthy

// TWAP too short (60s = flash-loan-manipulatable within the window; want ≥1800s/30min)
// Single-source oracle (Uniswap spot only) — want Chainlink primary + TWAP fallback, require agreement
```
```bash
grep -rn "latestRoundData" src/ -A5 | grep -v "updatedAt"
grep -rn "getPriceUnsafe\|getPrice\b" src/ -A8 | grep -v "conf"
grep -rn "secondsAgo\|TWAP\|cardinality" src/ -A5
```

### 6 — ERC4626 vault attacks
```solidity
// First-depositor / donation attack on a near-empty vault:
// 1. attacker deposits 1 wei → 1 share  2. donates a large amount via raw transfer (not deposit())
// 3. exchange rate skews  4. victim deposits → rounds down to 0 shares → free donation to attacker
// fix: OZ v4.9+ virtual shares — _decimalsOffset() returns 9 (adds 1e9 virtual shares+assets)

// transfer() moves shares but not the associated lock/stake record → shares stuck, permanent freeze
```
```bash
grep -rn "totalAssets\|convertToShares\|convertToAssets\|previewDeposit" src/
grep -rn "balanceOf(address(this))" src/     # raw balance read = donation-attack surface
```

### 7 — Reentrancy ($35.7M lost 2024; still found despite CEI being 8 years old)
Variants: single-function, cross-function (sibling has stale state), cross-contract (callback into
another protocol), **read-only** (a `view` fn returns stale data mid-callback — Curve, $70M).
```solidity
// VULNERABLE — interaction before effect:
function withdraw(uint256 amt) external {
    require(balances[msg.sender] >= amt);
    (bool ok,) = msg.sender.call{value: amt}("");     // INTERACTION first
    require(ok); balances[msg.sender] -= amt;         // EFFECT after → reentrancy window
}
// CORRECT — CEI: Check, Effect, then Interaction (effect before the external call)
```
```bash
grep -rn "\.call{value\|safeTransfer\|transfer(" src/ -B10 | grep -v "require\|revert"
grep -rn "function withdraw\|function redeem\|function claim" src/ -A2 | grep -v "nonReentrant"
```

### 8 — Flash-loan attacks (83.3% of eligible 2024 exploits used one)
Borrow huge amount → dump into a thin pool to crash/inflate spot price → protocol reads that spot
price as an oracle → exploit the mispriced state → repay loan same tx, keep profit. Any function
that reads a price AND acts on it within one transaction is a candidate; governance without a
snapshot delay is flash-loan-votable.
```bash
grep -rn "getReserves\|getAmountsOut\|slot0\b" src/ -A5
grep -rn "flashLoan\|onFlashLoan\|executeOperation" src/
```

### 9 — Signature replay
```solidity
// Missing nonce — same signature reusable indefinitely
bytes32 hash = keccak256(abi.encodePacked(owner, spender, value, deadline));  // no nonce
// Missing chainId — signature valid on mainnet AND every fork/testnet
bytes32 hash = keccak256(abi.encodePacked(params));   // no block.chainid
```
```bash
grep -rn "ecrecover\|ECDSA\.recover" src/ -B20   # does the hash include nonce+chainId+contract addr?
grep -rn "nonce\|_nonces\|nonces\[" src/
```

### 10 — Proxy / upgrade issues
Storage-slot collision (proxy slot 0 ≠ implementation slot 0), uninitialized implementation
(call `initialize()` directly on the impl, then `upgradeTo()` to replace logic — Wormhole $10M),
UUPS `_authorizeUpgrade()` missing access control, `delegatecall` to a target that becomes
attacker-controlled if the owner key is ever compromised.
```bash
grep -rn "function initialize\b\|_disableInitializers\|initializer" src/
grep -rn "delegatecall\b" src/ -B3 -A5
grep -rn "0x360894\|EIP1967\|_IMPLEMENTATION_SLOT" src/
```

## 5. Non-EVM quick reference

| Chain | Top vuln classes |
|---|---|
| **Solana/Anchor** | missing `.owner == program_id` check · missing `Signer<'info>` (using `AccountInfo`) · type cosplay (discriminator not checked) · PDA seed non-canonicalization (user-supplied bump) · arbitrary CPI (unverified program ID) · silent integer overflow in release builds (use `.checked_add()`) · sysvar spoofing (Wormhole $320M root cause) |
| **CosmWasm** | `load()` without matching `save()` on every path · missing `info.sender` check in `execute` handlers · address not run through `deps.api.addr_validate()` |
| **Move (Aptos/Sui)** | wrong ability (`copy` on a token = infinite mint, `drop` on a loan = skip repayment) · missing capability-resource gate on a `public` fn · `<<`/`>>` bitshift silently fills with zero instead of reverting |
| **Cross-chain bridges** ($2.8B+ stolen) | validator/multisig threshold too low · signature-verification bypass (threshold reducible to 0) · zero/default value treated as a trusted root (Nomad $200M) · message replay (missing nonce/nullifier) · deprecated sysvar functions (Wormhole $320M) |

## 6. Foundry PoC — required format, not optional

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "forge-std/Test.sol";

contract ExploitTest is Test {
    address constant TARGET = 0xVULNERABLE;
    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), 18000000);   // PIN the block
        vm.label(TARGET, "VulnerableProtocol");
    }
    function testExploit() public {
        console.log("Attacker before:", IERC20(TOKEN).balanceOf(address(this)));
        // --- exploit steps here ---
        console.log("Attacker after:", IERC20(TOKEN).balanceOf(address(this)));
        assertGt(IERC20(TOKEN).balanceOf(address(this)), 0, "Exploit failed");   // proves profit
    }
    receive() external payable {}
}
```
```bash
forge test --match-test testExploit -vvvv --fork-url $MAINNET_RPC_URL
```
Cheatcodes you'll actually use: `vm.prank`/`startPrank` (caller), `vm.deal`/`deal(token,...)`
(fund), `vm.warp`/`vm.roll` (time/block), `vm.createSelectFork(rpc, block)` (pin state),
`vm.expectRevert`, `vm.mockCall`, `vm.sign(pk, digest)` (forge a signature to test replay).
Also reproduce known hack patterns fast: `git clone github.com/SunWeb3Sec/DeFiHackLabs` — 572+
real exploits as runnable Foundry tests, good template source for a similar bug class.

**Invariant testing** (catches classes 1/6/7 fast — run after any manual finding to confirm blast radius):
```solidity
function invariant_totalAssetsMatchBalance() public { assertEq(vault.totalAssets(), token.balanceOf(address(vault))); }
```
```bash
forge test --match-test invariant_ -vvv
echidna test/EchidnaTest.sol --contract EchidnaTest
```

## 7. Submittable vs N/A (web3 gate is stricter than web2's `validate.md`)

| Finding | Verdict |
|---|---|
| Runnable Foundry PoC, forked at a real block, `assertGt` proves attacker profit | **Submittable** |
| "Theoretically reentrant" but a real `nonReentrant` guard is present and correctly placed | **N/A** — prove the guard is actually bypassable or drop it |
| "Owner could rug via X" (owner/multisig doing something only owner can do) | **N/A** — centralization risk is a design choice on Immunefi, not a bug |
| Bug already flagged in a linked prior audit report on the program page | **N/A** — known issue |
| Requires an already-leaked private key or admin compromise as a precondition | **N/A** |
| DoS where the attacker spends more gas than the value they extract | **N/A** — not economically viable |
| Written description / pseudocode only, no runnable test | **N/A on Immunefi** — PoC-required, not optional like web2 |
| Bug in a third-party dependency (Chainlink, OpenZeppelin) rather than the target's own code | **N/A** — report upstream instead |
| Read-only reentrancy, oracle staleness, ERC4626 first-depositor, sig replay — all with working PoC | **Submittable**, see payout table |

**Immunefi operational rules**: never test on mainnet/public testnet (local fork only — violation
is a permanent ban) · no AI-spray reports (instant ban) · 5 reports/48h rate limit · one bug per
report, don't bundle variants of the same root cause · don't contact the project directly, only
through the platform dashboard.

## 8. Payout benchmarks (2024-2025, Immunefi-scale)

| Bug class | Typical range |
|---|---|
| Access control — direct fund theft | $50K–$15M (Critical) |
| Flash loan + oracle manipulation | $50K–$5M (Critical) |
| Reentrancy — fund theft | $50K–$3M (Critical) |
| ERC4626 inflation attack | $10K–$500K (High/Critical) |
| Price oracle manipulation | $10K–$2M (High/Critical) |
| Read-only reentrancy | $10K–$500K (High) |
| Signature replay | $5K–$50K (High) |
| Missing staleness check | $1K–$20K (Medium) |

Immunefi severity floor: **Critical** = direct theft/permanent freeze/unauthorized mint, min $10K
or 10% TVL. **High** = temp freeze >24h or theft of unclaimed yield, $5K–$100K. **Medium** =
block-stuffing/griefing, $1K–$5K. **Low** = fails to deliver promised (non-fund) behavior, $200–$1K.

## 9. Report format (Immunefi)

```
Title: [Vuln Class] in [Contract::function()] leads to [Impact]
Bug Description: root cause + exact file/function/line
Impact: SELECT from the program's "Impacts in Scope" list; quantify "$X TVL at risk" with the calc
Proof of Concept: runnable Foundry fork test, pinned block, console.log before/after, assertGt
Remediation: concrete fix
```

## 10. Tool map

| Need | Tool | Install |
|---|---|---|
| Static analysis (93 detectors) | Slither | `pip3 install slither-analyzer` |
| Foundry-native fast AST pass | Aderyn | `cyfrinup` |
| Symbolic execution (deep, slow) | Mythril | `pip3 install mythril` |
| Property/stateful fuzzing | Echidna | `brew install echidna` |
| Next-gen ToB fuzzer | Medusa | GitHub releases |
| Symbolic testing | Halmos | `pip install halmos` |
| Claude-native unified pipeline (Slither+Aderyn+86 SWC+invariant-gen) | `solidity-audit-mcp` | `npm install -g solidity-audit-mcp`, wire into `.mcp.json` |
| Tx trace debugger | Phalcon | blocksec.com |
| Fork + simulate | Tenderly | tenderly.co |
| Decompile unverified bytecode | Dedaub | dedaub.com |
| Searchable prior findings (50K+) | Solodit | solodit.cyfrin.io |
| Real-hack reproductions (572+, runnable) | DeFiHackLabs | `github.com/SunWeb3Sec/DeFiHackLabs` |
| Audit checklist | solcurity | `github.com/transmissions11/solcurity` |

Once you have a confirmed bug: `validate.md`-equivalent gate is §7 above (stricter — PoC required),
then write it up per §9 and submit through the platform (Immunefi/Code4rena/Sherlock/Cantina/
CodeHawks) dashboard, never direct contact. Rug-pull/token-specific audits (mint authority, LP
lock, honeypot, bonding curve) → `meme-coin-audit.md`.
