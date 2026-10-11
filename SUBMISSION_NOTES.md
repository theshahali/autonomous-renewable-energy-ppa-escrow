### Autonomous Renewable Energy PPA Escrow
Autonomous Renewable Energy PPA Curtailment & Grid Interconnection Escrow on GenLayer. Eliminates multi-year litigation over solar/wind Deemed Generation compensation by using multi-validator consensus to audit official ISO emergency curtailment orders (CAISO, ERCOT, PJM).

### Core Hardcore Security Protections
- Pinned Grid Telemetry & SSRF Defense: Queries official transmission ISO domains (caiso.com, ercot.com, etc.). Rejects SSRF, credentials (@), and non-42-char hex.
- 100% Backed Funds & Solvency: All deposits/bonds via @gl.public.write.payable. TVL accurately tracks live balances without synthetic debt or double-deduction.
- Dispute Locking: Active claims transition escrow to DISPUTED, blocking front-running releases.
- Safe Inconclusive Fallback: LLM parsing glitches preserve claimant bonds instead of slashing.
- Pull-Pattern Recovery: Failed transfers safely credit recoverable balances.
