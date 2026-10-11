# AutonomousRenewableEnergyPpaEscrow
### Autonomous Renewable Energy PPA Curtailment & Grid Interconnection Escrow
**Protocol Standard**: GenLayer Intelligent Contract v0.2.1  
**Repository**: [https://github.com/theshahali/autonomous-renewable-energy-ppa-escrow](https://github.com/theshahali/autonomous-renewable-energy-ppa-escrow)  
**Execution Environment**: GenLayer Studio Testnet  
**Contract Address**: [`0xF2D8B2867448dBfE5219c2CAedd53DF7B7E4320e`](https://explorer-studio.genlayer.com/address/0xF2D8B2867448dBfE5219c2CAedd53DF7B7E4320e)  

---

## 1. Executive Summary & Energy Transition Settlement Dilemma

In global clean energy markets, utility-scale renewable energy developers (operating 100MW+ solar PV farms, offshore wind turbines, and utility-scale battery energy storage systems) enter into long-term **Power Purchase Agreements (PPAs)** and Grid Interconnection Contracts with corporate offtakers (e.g. hyperscale data centers requiring 24/7 carbon-free energy, industrial facilities, municipal utilities).

Offtakers prepay monthly generation procurement collateral into escrow ($100,000 to $2,000,000+ per billing cycle). However, modern power grids face acute physical transmission bottlenecks:
1. **Transmission Line Curtailment**: When regional transmission lines become congested or local renewable supply surges, regional transmission operators (CAISO, ERCOT, PJM, MISO, SPP) issue emergency or economic curtailment orders—directing renewable plants to immediately cease generation to avoid thermal line overloads.
2. **Deemed Generation Disputes**: Under standard PPA clauses, if curtailment is mandated by the ISO as an **Emergency Reliability Order** or **Transmission Constraint**, the generator is contractually entitled to "Deemed Generation" compensation (the offtaker must pay for the clean energy that would have been generated, plus lost environmental attribute value). Conversely, if the shutdown was caused by unexcused plant maintenance or inverter trips, no compensation is owed.
3. **Multi-Year Energy Arbitration**: Disputing whether an outage was an ISO-directed Reliability Order versus unexcused plant maintenance requires analyzing official ISO dispatch notices, emergency operating declarations, and transmission congestion alerts published on official grid portals (`caiso.com`, `ercot.com`, `pjm.com`, `ferc.gov`). Parties end up trapped in multi-year FERC or commercial arbitration.
4. **Oracle Inadequacy**: Traditional smart contracts cannot ingest or parse unstructured ISO dispatch notices, balancing authority directives, or regional transmission emergency advisories.

### The GenLayer Intelligent Solution
`AutonomousRenewableEnergyPpaEscrow` provides an autonomous, verifiable legal-financial bridge on GenLayer:
- Escrows monthly PPA generation capital backed 100% by payable native funds (`@gl.public.write.payable`).
- Integrates multi-validator equivalence consensus (`gl.eq_principle.prompt_non_comparative` + `gl.nondet.web.render`) to ingest official dispatch notices directly from authoritative transmission grid endpoints (`caiso.com`, `ercot.com`, `pjm.com`, `misoenergy.org`, `spp.org`, `ferc.gov`).
- Employs strict consensus heuristics to classify grid dispatch orders:
  - **CURTAILMENT_CONFIRMED**: Confirms an official ISO Emergency Reliability Curtailment order ($\ge 10$ MWh curtailed) $\rightarrow$ Automatically disburses Deemed Generation indemnity from the escrow to the renewable generator and returns the claimant's dispute bond.
  - **CLAIM_REFUTED**: Frivolous or maintenance-caused claim $\rightarrow$ Slashes claim bond to the offtaker's indemnity reserve balance.
  - **Consensual Fulfillment**: Normal metered generation delivery confirmed by the offtaker immediately disburses funds to the generator.

---

## 2. Deterministic Protocol State Machine

```
+-------------------------------------------------------------------------------+
|                       PROTOCOL STATE TRANSITION MACHINE                       |
+-------------------------------------------------------------------------------+

   [OFFTAKER: PPA PROCUREMENT ESCROW]
              |
              v
   +----------------------+     Invalid Format     +-----------------------------+
   | Address & Capacity   | ---------------------> | REVERT: [ERR_ADDR_FORMAT]   |
   | Sanitization Filter  |                        | REVERT: [ERR_INVALID_CAP]   |
   +----------------------+                        +-----------------------------+
              | Valid 42-char Hex & Parameters
              v
   +----------------------+     Insufficient Funds +-----------------------------+
   | 100% Payable Escrow  | ---------------------> | REVERT: [ERR_MIN_RESERVE]   |
   | Verification Gate    |                        +-----------------------------+
   +----------------------+
              | Escrow Funded
              v
   +-----------------------------------------------------------------------------+
   | STATE: ACTIVE | ppa_collateral = gl.message.value | escrows[escrow_id]       |
   +-----------------------------------------------------------------------------+
              |
              +-------------------------------------------------+
              |                                                 |
              | Normal Metered Delivery                         | ISO Emergency Grid Curtailment
              v                                                 v
   +----------------------+                        +-----------------------------+
   | confirm_metered_deliv|                        | submit_curtailment_indemnity|
   | (Offtaker Confirm)   |                        | (Claimant + Payable Bond)   |
   +----------------------+                        +-----------------------------+
              |                                                 |
              v                                                 v
   +----------------------+                        +-----------------------------+
   | Disburse Collateral  |                        | SSRF & Host Whitelist Check |
   | to Renewable Gen.    |                        | (caiso.com / ercot.com)     |
   +----------------------+                        +-----------------------------+
              |                                                 |
              v                                                 v
   +----------------------+                        +-----------------------------+
   | STATE: FULFILLED     |                        | Multi-Validator LLM Consens |
   |                      |                        | (gl.eq_principle + nondet)  |
   +----------------------+                        +-----------------------------+
                                                                |
                                              +------------------+------------------+
                                              |                                     |
                                              v Confirmed Curtailment (>=10MWh, c>=70)v Refuted / Maintenance
                                   +----------------------+               +-----------------------+
                                   | Deemed Gen Indemnity |               | Slash Bond to         |
                                   | to Gen + Bond Return |               | Offtaker Indemnity    |
                                   +----------------------+               +-----------------------+
                                              |                                     |
                                              v                                     v
                                   +----------------------+               +-----------------------+
                                   | STATE: CURTAILMENT_  |               | STATE: ACTIVE         |
                                   | SETTLED              |               | (Claim: CLAIM_REFUTED)|
                                   +----------------------+               +-----------------------+
```

---

## 3. Core Hardcore Security Protections & Steward Invariants

1. **100% Backed Payable Funds**: PPA procurement deposits, top-ups, and dispute bonds are escrowed strictly via `@gl.public.write.payable` reading `gl.message.value`.
2. **Zero Synthetic Genesis Debt**: Initialized with zero unbacked allocations. Total Volume Locked strictly matches verified on-chain deposits.
3. **Storage Dataclasses**: All numerical variables in `@allow_storage` dataclasses are strictly typed as `u256` to avoid GenVM runtime overflow.
4. **Strict SSRF & URL Whitelist**: External dispatch ingestion strictly verifies that URLs match official grid operator domains (`caiso.com`, `ercot.com`, `pjm.com`, `misoenergy.org`, `spp.org`, `ferc.gov`). Disallows credentials (`@`), loopback addresses (`127.0.0.1`, `localhost`), and malformed schemes.
5. **Length-Prefixed Canonical Fingerprinting**: Prevents delimiter collision attacks across multiple string parameters using `L<len>:val|` formatting.
6. **Non-Admin Consensus Clock**: Evaluates deadlines strictly using consensus UTC timestamps (`datetime.datetime.now(datetime.timezone.utc).timestamp()`).
7. **Timeout Bond Safeguard**: Claimants can reclaim their bond after a 7-day timeout if dispatch endpoints become unreachable.
8. **Pull-Pattern Balance Recovery**: Failed native EVM disbursements automatically credit `claimable_balances[recipient]`. `withdraw_claimable()` optimistically zeroes the balance and restores it upon failure.
9. **Safe Fallback on Ingestion / Parsing Glitches (CRIT-01)**: If consensus JSON parsing or LLM response formatting errors occur, verdicts default strictly to `CLAIM_INCONCLUSIVE`, protecting claimant bonds from unjust slashing.
10. **Solvency Accounting Guarantee (CRIT-02)**: `total_volume_locked` is decremented strictly upon successful native transfer. Failed transfers retain TVL backing until funds are withdrawn via `withdraw_claimable()`, eliminating double decrements.
11. **Dispute State Locking (HIGH-01)**: Filing a dispute immediately transitions the escrow to `STATUS_DISPUTED`, locking the state and preventing front-running metered delivery releases or premature expiry reclamation.
12. **Prompt Sanitation Defense (HIGH-02)**: Strips HTML tags and script/style bloat via regex before prompt injection, preventing context truncation and false refutations.
13. **Dispute Deadline Enforcement (MED-03)**: Strictly verifies that claims are submitted before the billing deadline (`now_utc <= billing_deadline`).

---

## 4. Contract Methods & Public API

### State-Modifying Methods
- `create_ppa_escrow(generator_address: str, facility_node: str, contracted_capacity_mw: int, duration_seconds: int)`: Creates a new renewable PPA generation escrow.
- `topup_ppa_escrow(escrow_id: str)`: Tops up collateral for an active PPA escrow.
- `confirm_metered_delivery(escrow_id: str)`: Confirms delivery and disburses collateral to generator.
- `claim_expired_undelivered_escrow(escrow_id: str)`: Reclaims collateral if billing deadline elapsed without delivery or dispute.
- `submit_curtailment_indemnity_claim(escrow_id: str, dispatch_order_url: str, curtailed_mwh: int, nonce: str)`: Submits an official curtailment claim.
- `adjudicate_curtailment_claim(claim_id: str)`: Executes multi-validator AI consensus audit.
- `claim_abandoned_curtailment_bond(claim_id: str)`: Reclaims bond after 7-day unreachability timeout.
- `decommission_uncontested_escrow(escrow_id: str)`: Decommissions terminal escrow.
- `withdraw_claimable()`: Reclaims uncollected balances safely.

### View Methods
- `get_escrow(escrow_id: str) -> dict`: Returns full escrow status and parameters.
- `get_claim(claim_id: str) -> dict`: Returns curtailment claim details and adjudication verdict.
- `get_claimable_balance(account: str) -> u256`: Returns recoverable balance.
- `get_total_escrows() -> u256`: Returns total escrows created.
- `get_total_claims() -> u256`: Returns total claims filed.
- `get_total_volume_locked() -> u256`: Returns current active TVL.

---

## 5. Verification & Regression Test Suite

The contract is validated via a 15-phase Python regression test suite:

```bash
python test/test_renewable_energy_ppa_escrow.py
```

| Phase | Description | Result |
| :--- | :--- | :--- |
| **Phase 1** | Zero Genesis Invariants & Initial State | `PASSED` |
| **Phase 2** | Create Renewable PPA Escrow with 100% Backed Funds | `PASSED` |
| **Phase 3** | Reserve Top-Up Recording | `PASSED` |
| **Phase 4** | SSRF Defense & Grid Operator Domain Whitelist Validation | `PASSED` |
| **Phase 5** | Address Sanitation & Non-Zero Hex Enforcement | `PASSED` |
| **Phase 6** | Length-Prefixed Canonical Fingerprint Computation | `PASSED` |
| **Phase 7** | Curtailment Claim with Payable Bond & Dispute State Lock | `PASSED` |
| **Phase 8** | Replay Defense on Duplicate Dispatch Orders | `PASSED` |
| **Phase 9** | Consensus Adjudication: CURTAILMENT_CONFIRMED | `PASSED` |
| **Phase 10** | Consensus Adjudication: CLAIM_REFUTED | `PASSED` |
| **Phase 10b** | Safe Fallback on AI JSON Parse Error (CRIT-01) | `PASSED` |
| **Phase 11** | Fail-Closed Dispatch Order Ingestion Fallback | `PASSED` |
| **Phase 12** | 7-Day Timeout Claim Bond Recovery | `PASSED` |
| **Phase 13** | Consensual Metered Generation Delivery Release | `PASSED` |
| **Phase 14** | Expired Undelivered Collateral Refund | `PASSED` |
| **Phase 15** | Pull-Pattern Recovery with Balance Preservation & TVL Solvency | `PASSED` |

---

## 6. Live Deployment & Explorer Verification

- **Contract Address**: `0x5E24d4CF6Dc0da8128E0bc0f3369B1009f6FE66F`
- **Deployment Tx Hash**: `0x7c922e83ac55b978b1828d62d41edc1576661b279827118c4618f885f7bf34a5`
- **Network**: GenLayer Studio Testnet
- **Explorer URL**: [https://explorer-studio.genlayer.com/address/0x5E24d4CF6Dc0da8128E0bc0f3369B1009f6FE66F](https://explorer-studio.genlayer.com/address/0x5E24d4CF6Dc0da8128E0bc0f3369B1009f6FE66F)
- **RPC Endpoint**: `https://studio.genlayer.com/api`
