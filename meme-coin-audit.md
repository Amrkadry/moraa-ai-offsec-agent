# Moraa — Meme coin / token rug-pull audit (EVM + Solana)

> Different game from `web3-audit.md`: you're not hunting a subtle accounting bug in a mature
> protocol, you're checking whether a specific privileged operation exists that lets the deployer
> steal from holders. **THE ONE RULE: check every retained authority and owner function — the
> retained authority IS the rug vector.** Every rug requires one of: mint, blacklist, fee change,
> LP removal, or authority abuse. Find the privilege, you found the bug.

---

## 0. Pre-dive kill signals (before reading a single line)

**Hard kill — skip the audit:**
- Contract not verified on Etherscan/Solscan → can't audit source, can't trust it
- Deployer wallet has prior rug history (check its Etherscan tx history)
- Token age <1h and no known team → too early, no data yet
- Solana: mint authority retained with no cap → infinite mint, certain rug
- Solana: freeze authority retained on a meme coin → honeypot, confirmed
- Token-2022: mutable transfer hook, or permanent-delegate extension present → can steal any holder's tokens

**Soft kill — proceed with caution:** top holder >20% of supply (excl. DEX pools) · LP not
burned/locked in a verified locker · upgradeable/proxy contract with retained admin · <$5K pool
liquidity · anonymous deployer, no social presence, no prior history.

## 1. The 8 token-specific bug classes

### 1 — Hidden mint / unlimited supply (~35% of rugs)
```bash
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib"
grep -rn "MintTo\|mint_to\|mint_authority" src/ --include="*.rs" | grep -v "test\|target"
```
Kill (clean) if: `MAX_SUPPLY` enforced on every mint path, or the mint function was removed entirely.

### 2 — Honeypot / transfer restriction (~25% of scams — buy works, sell blocked)
```bash
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|tradingEnabled" src/ --include="*.sol"
grep -rn "freeze_authority\|transfer_hook\|TransferHook\|permanent_delegate" src/ --include="*.rs"
```
Kill if: no blacklist mapping, no transfer hooks, no freeze authority.

### 3 — Fee manipulation (~20% of rugs — sell fee jumps to 99% after initial buys)
```bash
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="
```
Kill if: fee setter has `require(fee <= MAX_FEE)` with `MAX_FEE <= 10%`.

### 4 — Liquidity pool drain
```bash
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
```
Kill if: LP tokens burned to `0xdead`/`address(0)`, no migration function, no pair setter.

### 5 — Bonding-curve manipulation (pump.fun-style)
```bash
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
```
Kill if: curve parameters immutable, graduation is permissionless.

### 6 — Authority retention (Solana)
```bash
grep -rn "mint_authority\|freeze_authority\|update_authority\|close_authority" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"    # good sign — revocation present
```
Kill if: all authorities verified `None` on-chain.

### 7 — Fake renounce / hidden ownership
```bash
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
```
Kill if: `renounceOwnership` NOT overridden, no second admin role, no `selfdestruct`.

### 8 — Sandwich amplification by design
Contract makes its own holders maximally sandwichable — not external MEV (not a bug bounty target
on its own), but a contract-level bug when it amplifies profitability:
```solidity
// Zero-slippage auto-swap — accumulated tax tokens dumped with 0 minOut
function swapTokensForETH(uint256 amount) private {
    router.swapExactTokensForETHSupportingFeeOnTransferTokens(amount, 0 /* ZERO minOut */, path, address(this), block.timestamp);
}
```
```bash
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"
grep -rn "swapThreshold\|_rebase\|mandatoryPool" src/ --include="*.sol"
grep -rn "\.sync()\|IUniswapV2Pair.*sync" src/ --include="*.sol"    # direct-transfer-then-sync = atomic price manip
```
Kill if: auto-swap has real slippage protection, no rebase mechanics.

## 2. DEX/LP manipulation (contract-level bugs, not raw MEV)

Standard sandwiching/frontrunning is a market issue, not a bug bounty target. These are **bugs in
how the token contract itself interacts with the DEX layer** that create or amplify rug potential:

| Pattern | What to check | Grep |
|---|---|---|
| **Pool-creation sniping** | Is `addLiquidity` and `enableTrading` one atomic tx, or two separate calls with a snipe-window gap between them? | `enableTrading\|tradingEnabled\|launchBlock` |
| **LP token destination** | Auto-LP from tax sent to owner (VULNERABLE) vs `0xdead`/burned (safe) | `addLiquidityETH` `-A5` then check for `owner()` vs `0xdead` |
| **LP-lock backdoor** | Lock contract has an `extend()`/`emergencyWithdraw()` that resets `unlockTime` early | `unlockTime\|emergencyWithdraw\|extend.*unlock` |
| **Concentrated-liquidity (Uni V3/Whirlpool/DLMM) engineered rug** | Creator opens a narrow-range CL position around launch price; organic buys push price out of range → position becomes 100% quote asset → creator withdraws, holders left illiquid. Narrow range (`tickUpper - tickLower < 200`) is the rug signal | `NonfungiblePositionManager\|tickLower\|tickUpper` |
| **Pool/router migration** | `setPair()`/`migrate()` lets owner swap the recognized pair or router, stranding old-pair holders whose sell logic breaks | `setPair\|setNewPair\|function migrate` |
| **Flash-loan on thin pool as oracle** | Any protocol reading this token's price from raw `getReserves()`/`slot0` as an oracle is flash-loan-manipulatable given typical $10K-$100K meme-coin liquidity | `getReserves()\|getTokenPrice\|price.*reserve` |

```
Quick audit flow: which DEX(es) does it touch → LP token destination → migration functions →
auto-swap slippage → direct pair.sync() calls → CL position range → price oracle source (spot vs TWAP)
```

| DEX | Chain | Key vector | Grep target |
|---|---|---|---|
| Uniswap V2 / PancakeSwap | ETH/BSC | LP removal, `pair.sync()` | `IUniswapV2Pair\|sync()` |
| Uniswap V3 | ETH | CL position manipulation | `NonfungiblePositionManager\|tickLower` |
| Raydium CPMM/CLMM | Solana | LP-burn check, pool-init snipe | `raydium_amm\|create_pool` |
| Orca Whirlpools | Solana | Narrow tick-range rug | `Whirlpool\|tick_lower_index` |
| Meteora DLMM | Solana | Bin liquidity manipulation | `LbPair\|active_bin` |
| pump.fun | Solana | Graduation snipe, bundled buys | `bonding_curve\|graduate` |

## 3. On-chain checks when there's no source (Solana, or unverified EVM)

```
1. MINT AUTHORITY   solana account <MINT> --output json   → mint_authority must be null
                     Some(pubkey) → CRITICAL, infinite mint possible
2. FREEZE AUTHORITY same command, freeze_authority          → must be null, else honeypot confirmed
3. LP STATUS        check Raydium/Orca pool: burned (sent to 111...111)? locked in a verified,
                     backdoor-free locker? held by deployer wallet → CRITICAL, instant-rug capable
4. TOP HOLDERS       Birdeye/Solscan holders tab — top 10 <30% of supply excl. pools; check the
                     creator wallet's own first transactions
5. PROGRAM UPGRADE   is the program itself upgradeable? upgrade authority should be None for an
                     immutable program
6. TOKEN-2022        any transfer hook (potential honeypot)? permanent delegate (CRITICAL — can
                     move any holder's tokens without consent)?
```
EVM equivalent when unverified: Dedaub decompile, then re-run the grep patterns above against the
decompiled output; treat anything you can't fully resolve as a soft kill, not a clean bill.

## 4. Foundry PoC template

```solidity
function test_hiddenMint_rug() public {
    vm.startPrank(victim); /* buy on Uniswap */ vm.stopPrank();
    vm.startPrank(owner);
    uint256 before = token.totalSupply();
    token.mint(owner, 1_000_000_000e18);
    assertGt(token.totalSupply(), before, "supply should increase");
    /* sell minted tokens */ vm.stopPrank();
    // assert token price crashed / victim's holdings devalued
}

function test_honeypot_blacklist() public {
    vm.startPrank(victim); /* buy */ vm.stopPrank();
    vm.prank(owner); token.blacklist(victim);
    vm.startPrank(victim);
    vm.expectRevert("Blacklisted");
    token.transfer(address(1), 100e18);           // proves the sell-block, not just the flag
    vm.stopPrank();
}
```

## 5. Submittable vs N/A

| Finding | Verdict |
|---|---|
| Retained authority (mint/freeze/blacklist) with working PoC that it's actually exercised or exercisable | **Submittable** — see `web3-audit.md §7` for the general web3 gate |
| "Owner *could* rug" with no PoC of the mechanism being callable/unbounded | Weak — need the concrete unbounded fee-setter/mint/LP-pull, not just "owner exists" |
| Contract audited, mint capped, LP burned, ownership renounced (verified `require` not `if`) | Clean — move on, don't manufacture a finding |
| Sandwich/MEV with no contract-level amplification bug | **N/A** — that's market structure, not a bug |
| Pure holder-distribution concentration with no code bug | **N/A** — due-diligence flag, not a vulnerability |

## 6. Automated first pass

If the target repo ships a token-specific scanner, run it before the manual grep sweep — it
covers all 8 classes via regex and flags what to look at first (does not verify on-chain state:
still confirm authority/LP status manually per §3). Otherwise the grep patterns in §1-2 cover the
same ground by hand.

Once through the token layer, if the bug reaches the DEX/pool contracts themselves (not just the
token), cross-reference `web3-audit.md` classes 5 (oracle) and 8 (flash loan) — those apply
directly to a manipulated thin meme-coin pool.
