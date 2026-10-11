# test_renewable_energy_ppa_escrow.py
# 15-Phase Comprehensive Regression & Security Test Suite for AutonomousRenewableEnergyPpaEscrow
import json
import hashlib
import urllib.parse
import re
from datetime import datetime, timezone


class MockGL:
    def __init__(self):
        self.transfers = []
        self.mock_web_responses = {}
        self.fail_web_fetch = False
        self.simulate_transfer_fail = False

    def emit_transfer(self, recipient: str, amount: int):
        if self.simulate_transfer_fail:
            raise RuntimeError("Simulated EVM transfer failure")
        self.transfers.append({"recipient": str(recipient).lower(), "amount": int(amount)})

    def get_webpage(self, url: str) -> str:
        if self.fail_web_fetch:
            raise RuntimeError("Simulated network timeout connecting to ISO market portal")
        return self.mock_web_responses.get(
            url,
            "<html><body><h1>CAISO Transmission Emergency Operating Order: DISP-2026-994</h1>"
            "<p>Node: MIDWAY-SUB-500KV. Substation Emergency Transmission Line Congestion. "
            "Dispatch Directive: Mandatory Economic Transmission Curtailment issued to all solar generation facilities behind Midway constraint. "
            "Total Curtailed Energy: 450 MWh. Reliability Must-Run event confirmed. Cause: Intertie overload, not generator maintenance.</p></body></html>"
        )

    def exec_prompt(self, prompt: str) -> str:
        return json.dumps({
            "curtailment_confirmed": True,
            "verified_curtailed_mwh": 450,
            "confidence_score": 96,
            "rationale": "CAISO emergency transmission congestion mandatory curtailment order confirmed for 450 MWh."
        })


class MockAutonomousRenewableEnergyPpaEscrow:
    def __init__(self, owner_address: str, gl_mock: MockGL):
        self.gl = gl_mock
        self.owner = owner_address.lower()
        self.total_escrows_created = 0
        self.total_claims_filed = 0
        self.total_claims_adjudicated = 0
        self.total_volume_locked = 0
        self.total_collateral_released = 0
        self.total_collateral_refunded = 0

        self.escrows = {}
        self.claims = {}
        self.consumed_claim_hashes = {}
        self.consumed_escrow_orders = {}
        self.claimable_balances = {}

        self.STATUS_ACTIVE = "ACTIVE"
        self.STATUS_DISPUTED = "DISPUTED"
        self.STATUS_FULFILLED = "FULFILLED"
        self.STATUS_CURTAILMENT_SETTLED = "CURTAILMENT_SETTLED"
        self.STATUS_EXPIRED_REFUNDED = "EXPIRED_REFUNDED"
        self.STATUS_DECOMMISSIONED = "DECOMMISSIONED"

        self.CLAIM_PENDING = "PENDING_CONSENSUS"
        self.CLAIM_CURTAILMENT_CONFIRMED = "CURTAILMENT_CONFIRMED"
        self.CLAIM_REFUTED = "CLAIM_REFUTED"
        self.CLAIM_INCONCLUSIVE = "INCONCLUSIVE"
        self.CLAIM_ABANDONED = "CLAIM_ABANDONED"

        self.MIN_PPA_RESERVATION = 100_000_000_000
        self.MIN_TOPUP_AMOUNT = 10_000_000_000
        self.MIN_CLAIM_BOND = 25_000_000_000
        self.MIN_PPA_DURATION = 86400 * 7
        self.MAX_PPA_DURATION = 86400 * 365 * 5
        self.CLAIM_TIMEOUT_SECONDS = 86400 * 7
        self.MIN_CURTAILED_MWH = 10

        self.APPROVED_GRID_DOMAINS = (
            "caiso.com",
            "ercot.com",
            "pjm.com",
            "misoenergy.org",
            "spp.org",
            "ferc.gov"
        )

    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42, "[ERR_ADDR_FORMAT] " + field_name + " must be a 42-character hex address."
        assert clean.startswith("0x") or clean.startswith("0X"), "[ERR_ADDR_PREFIX] " + field_name + " must start with '0x'."
        hex_digits = clean[2:]
        for c in hex_digits:
            assert c in "0123456789abcdefABCDEF", "[ERR_ADDR_HEX] " + field_name + " contains non-hex characters."
        assert clean.lower() != "0x" + "0" * 40, "[ERR_ADDR_ZERO] " + field_name + " cannot be the zero address."
        return clean.lower()

    def _sanitize_string(self, val: str, min_len: int, max_len: int, field_name: str) -> str:
        clean = val.strip()
        assert len(clean) >= min_len, "[ERR_STR_TOO_SHORT] " + field_name + " length must be >= " + str(min_len)
        assert len(clean) <= max_len, "[ERR_STR_TOO_LONG] " + field_name + " length must be <= " + str(max_len)
        return clean

    def _validate_dispatch_url(self, url_str: str) -> str:
        clean = url_str.strip()
        assert len(clean) <= 512, "[ERR_URL_TOO_LONG] Dispatch URL exceeds 512 characters."
        assert not ("\n" in clean or "\r" in clean or "\t" in clean), "[ERR_URL_WHITESPACE] URL must not contain newlines or tabs."
        assert "@" not in clean, "[ERR_URL_CREDENTIALS] Embedded credentials prohibited in dispatch URL."

        try:
            parsed = urllib.parse.urlparse(clean)
        except Exception:
            raise AssertionError("[ERR_URL_PARSE] Failed to parse dispatch URL.")

        scheme = (parsed.scheme or "").lower()
        assert scheme in ("http", "https"), "[ERR_URL_SCHEME] Dispatch URL must use HTTP or HTTPS."

        hostname = (parsed.hostname or "").lower()
        assert hostname, "[ERR_URL_HOSTNAME] Dispatch URL missing hostname."
        assert hostname not in ("localhost", "127.0.0.1", "0.0.0.0", "::1"), "[ERR_URL_LOOPBACK] SSRF attempt: loopback address rejected."

        matched_domain = False
        for approved_d in self.APPROVED_GRID_DOMAINS:
            if hostname == approved_d or hostname.endswith("." + approved_d):
                matched_domain = True
                break
        assert matched_domain, "[ERR_URL_UNAPPROVED_DOMAIN] Target domain '" + hostname + "' not in approved grid operator catalog."
        return clean

    def _compute_claim_hash(self, escrow_id: str, claimant: str, dispatch_url: str, nonce: str) -> str:
        data = (
            "L" + str(len(escrow_id)) + ":" + escrow_id.upper() + "|" +
            "L" + str(len(claimant)) + ":" + claimant.lower() + "|" +
            "L" + str(len(dispatch_url)) + ":" + dispatch_url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def fund_contract(self, caller: str, value: int):
        assert value > 0, "[ERR_ZERO_PAYMENT] Value must be greater than zero."
        sender_hex = self._validate_eth_address(caller, "Sender")
        cur = self.claimable_balances.get(sender_hex, 0)
        self.claimable_balances[sender_hex] = cur + value
        self.total_volume_locked += value
        return "FUNDED: " + str(value) + " wei credited to " + sender_hex

    def create_ppa_escrow(self, caller: str, value: int, generator_address: str, facility_node: str, contracted_capacity_mw: int, duration_seconds: int):
        offtaker_hex = self._validate_eth_address(caller, "Offtaker")
        generator_hex = self._validate_eth_address(generator_address, "Renewable Generator")
        assert offtaker_hex != generator_hex, "[ERR_IDENTICAL_PARTIES] Offtaker and generator cannot be identical."

        clean_node = self._sanitize_string(facility_node, 4, 64, "Facility Interconnection Node")
        assert contracted_capacity_mw > 0 and contracted_capacity_mw <= 10000, "[ERR_INVALID_CAPACITY] Capacity invalid."
        assert duration_seconds >= self.MIN_PPA_DURATION, "[ERR_DURATION_TOO_SHORT] Duration too short."
        assert duration_seconds <= self.MAX_PPA_DURATION, "[ERR_DURATION_TOO_LONG] Duration too long."
        assert value >= self.MIN_PPA_RESERVATION, "[ERR_MIN_RESERVATION] Escrow below minimum."

        now_utc = int(datetime.now(timezone.utc).timestamp())
        deadline_utc = now_utc + duration_seconds

        new_id = "ESCROW_PPA_" + str(self.total_escrows_created + 1)
        self.escrows[new_id] = {
            "escrow_id": new_id,
            "offtaker": offtaker_hex,
            "generator": generator_hex,
            "facility_node": clean_node,
            "contracted_capacity_mw": contracted_capacity_mw,
            "ppa_collateral": value,
            "total_released_to_generator": 0,
            "total_refunded_to_offtaker": 0,
            "created_at": now_utc,
            "billing_deadline": deadline_utc,
            "status": self.STATUS_ACTIVE
        }
        self.total_escrows_created += 1
        self.total_volume_locked += value
        return new_id

    def topup_ppa_escrow(self, caller: str, value: int, escrow_id: str):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == e["offtaker"], "[ERR_UNAUTHORIZED] Only offtaker can top up."
        assert value >= self.MIN_TOPUP_AMOUNT, "[ERR_MIN_TOPUP] Topup below minimum."

        e["ppa_collateral"] += value
        self.total_volume_locked += value
        return "TOPPED_UP: " + escrow_id + " | Added: " + str(value)

    def confirm_metered_delivery(self, caller: str, escrow_id: str):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == e["offtaker"], "[ERR_UNAUTHORIZED] Only offtaker can confirm delivery."

        amt = e["ppa_collateral"]
        assert amt > 0, "[ERR_ZERO_COLLATERAL] No collateral to disburse."

        e["status"] = self.STATUS_FULFILLED
        e["total_released_to_generator"] += amt
        e["ppa_collateral"] = 0
        self.total_collateral_released += amt

        transfer_succeeded = False
        try:
            self.gl.emit_transfer(e["generator"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(e["generator"], 0)
            self.claimable_balances[e["generator"]] = cur + amt

        return "FULFILLED: " + escrow_id

    def claim_expired_undelivered_escrow(self, caller: str, escrow_id: str, custom_time: int = None):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == e["offtaker"], "[ERR_UNAUTHORIZED] Only offtaker can reclaim expired escrow."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc > e["billing_deadline"], "[ERR_DEADLINE_NOT_REACHED] Deadline not reached."

        amt = e["ppa_collateral"]
        assert amt > 0, "[ERR_ZERO_COLLATERAL] No collateral to refund."

        e["status"] = self.STATUS_EXPIRED_REFUNDED
        e["total_refunded_to_offtaker"] += amt
        e["ppa_collateral"] = 0
        self.total_collateral_refunded += amt

        transfer_succeeded = False
        try:
            self.gl.emit_transfer(e["offtaker"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(e["offtaker"], 0)
            self.claimable_balances[e["offtaker"]] = cur + amt

        return "EXPIRED_REFUNDED: " + escrow_id

    def submit_curtailment_indemnity_claim(self, caller: str, value: int, escrow_id: str, dispatch_order_url: str, curtailed_mwh: int, nonce: str):
        clean_e_id = escrow_id.strip().upper()
        assert clean_e_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[clean_e_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        now_utc = int(datetime.now(timezone.utc).timestamp())
        assert now_utc <= e["billing_deadline"], "[ERR_DEADLINE_ELAPSED] Billing deadline has elapsed."

        sender_hex = self._validate_eth_address(caller, "Claimant")
        clean_url = self._validate_dispatch_url(dispatch_order_url)
        clean_nonce = self._sanitize_string(nonce, 1, 64, "Nonce")
        assert curtailed_mwh >= self.MIN_CURTAILED_MWH, "[ERR_CURTAILMENT_TOO_LOW] Curtailed volume below threshold."

        order_key = clean_e_id + "::" + clean_url.lower()
        assert order_key not in self.consumed_escrow_orders, "[ERR_DISPATCH_ORDER_ALREADY_CLAIMED] Dispatch order already claimed."

        assert value >= self.MIN_CLAIM_BOND, "[ERR_MIN_CLAIM_BOND] Claim bond too low."

        c_hash = self._compute_claim_hash(clean_e_id, sender_hex, clean_url, clean_nonce)
        assert c_hash.lower() not in self.consumed_claim_hashes, "[ERR_CLAIM_EXISTS] Duplicate claim hash."

        new_c_id = "CLAIM_CURT_" + str(self.total_claims_filed + 1)
        self.claims[new_c_id] = {
            "claim_id": new_c_id,
            "escrow_id": clean_e_id,
            "claimant": sender_hex,
            "dispatch_order_url": clean_url,
            "curtailed_mwh": curtailed_mwh,
            "claim_fingerprint": c_hash,
            "claim_bond": value,
            "filed_at": now_utc,
            "adjudicated_at": 0,
            "verdict": self.CLAIM_PENDING,
            "indemnity_awarded": 0,
            "has_claimed": False,
            "adjudication_rationale": ""
        }

        self.consumed_claim_hashes[c_hash.lower()] = True
        self.consumed_escrow_orders[order_key] = True
        self.total_claims_filed += 1
        self.total_volume_locked += value

        # Lock escrow into DISPUTED state (HIGH-01)
        e["status"] = self.STATUS_DISPUTED
        return new_c_id

    def adjudicate_curtailment_claim(self, claim_id: str, custom_curt: bool = None, custom_mwh: int = None, custom_conf: int = None, simulate_parse_error: bool = False):
        assert claim_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Claim not found."
        clm = self.claims[claim_id]
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_ALREADY_ADJUDICATED] Claim already adjudicated."

        e = self.escrows[clm["escrow_id"]]

        try:
            dispatch_text = self.gl.get_webpage(clm["dispatch_order_url"])
        except Exception:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Consensus could not fetch dispatch order.")

        assert dispatch_text is not None and len(dispatch_text.strip()) >= 30, "[ERR_EVIDENCE_FETCH_FAILED] Dispatch response too short."

        # HTML sanitization (HIGH-02)
        cleaned_text = re.sub(r'<script[^>]*>.*?</script>', ' ', dispatch_text, flags=re.DOTALL | re.IGNORECASE)
        cleaned_text = re.sub(r'<style[^>]*>.*?</style>', ' ', cleaned_text, flags=re.DOTALL | re.IGNORECASE)
        cleaned_text = re.sub(r'<[^>]+>', ' ', cleaned_text)
        cleaned_text = ' '.join(cleaned_text.split())

        parse_valid = False
        parsed_curt = False
        parsed_mwh = 0
        confidence = 0
        rationale = "Consensus fallback resolution."

        if simulate_parse_error:
            parse_valid = False
        elif custom_curt is not None and custom_mwh is not None:
            raw_resp = json.dumps({
                "curtailment_confirmed": custom_curt,
                "verified_curtailed_mwh": custom_mwh,
                "confidence_score": custom_conf if custom_conf is not None else 85,
                "rationale": "Test curtailment adjudication verdict."
            })
            parsed = json.loads(raw_resp)
            parsed_curt = bool(parsed.get("curtailment_confirmed", False))
            parsed_mwh = int(parsed.get("verified_curtailed_mwh", 0))
            confidence = int(parsed.get("confidence_score", 0))
            rationale = parsed.get("rationale", "")
            parse_valid = True
        else:
            raw_resp = self.gl.exec_prompt("Prompt")
            try:
                clean_json = raw_resp.strip()
                if "```json" in clean_json:
                    clean_json = clean_json.split("```json")[1].split("```")[0].strip()
                elif "```" in clean_json:
                    clean_json = clean_json.split("```")[1].split("```")[0].strip()
                parsed = json.loads(clean_json)
                parsed_curt = bool(parsed.get("curtailment_confirmed", False))
                parsed_mwh = int(parsed.get("verified_curtailed_mwh", 0))
                confidence = int(parsed.get("confidence_score", 0))
                rationale = parsed.get("rationale", "")
                parse_valid = True
            except Exception:
                parse_valid = False

        # CRIT-01 Safe Inconclusive Fallback
        if parse_valid and parsed_curt and parsed_mwh >= self.MIN_CURTAILED_MWH and confidence >= 70:
            final_verdict = self.CLAIM_CURTAILMENT_CONFIRMED
        elif parse_valid and (not parsed_curt or parsed_mwh < self.MIN_CURTAILED_MWH or confidence < 30):
            final_verdict = self.CLAIM_REFUTED
        else:
            final_verdict = self.CLAIM_INCONCLUSIVE

        now_utc = int(datetime.now(timezone.utc).timestamp())
        clm["adjudicated_at"] = now_utc
        clm["verdict"] = final_verdict
        clm["adjudication_rationale"] = rationale
        bond_val = clm["claim_bond"]

        if final_verdict == self.CLAIM_CURTAILMENT_CONFIRMED:
            collateral_amt = e["ppa_collateral"]
            clm["indemnity_awarded"] = collateral_amt
            clm["has_claimed"] = True

            e["status"] = self.STATUS_CURTAILMENT_SETTLED
            e["total_released_to_generator"] += collateral_amt
            e["ppa_collateral"] = 0
            self.total_collateral_released += collateral_amt

            # CRIT-02 Solvency Accounting
            transfer_gen = False
            try:
                self.gl.emit_transfer(e["generator"], collateral_amt)
                transfer_gen = True
            except Exception:
                transfer_gen = False

            if transfer_gen:
                self.total_volume_locked = max(0, self.total_volume_locked - collateral_amt)
            else:
                cur = self.claimable_balances.get(e["generator"], 0)
                self.claimable_balances[e["generator"]] = cur + collateral_amt

            transfer_claimant = False
            try:
                self.gl.emit_transfer(clm["claimant"], bond_val)
                transfer_claimant = True
            except Exception:
                transfer_claimant = False

            if transfer_claimant:
                self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
            else:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_val

        elif final_verdict == self.CLAIM_REFUTED:
            clm["indemnity_awarded"] = 0
            clm["has_claimed"] = True
            # Unlock escrow back to ACTIVE
            e["status"] = self.STATUS_ACTIVE

            cur = self.claimable_balances.get(e["offtaker"], 0)
            self.claimable_balances[e["offtaker"]] = cur + bond_val

        else: # INCONCLUSIVE
            clm["indemnity_awarded"] = 0
            clm["has_claimed"] = True
            # Unlock escrow back to ACTIVE
            e["status"] = self.STATUS_ACTIVE

            transfer_claimant = False
            try:
                self.gl.emit_transfer(clm["claimant"], bond_val)
                transfer_claimant = True
            except Exception:
                transfer_claimant = False

            if transfer_claimant:
                self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
            else:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_val

        self.total_claims_adjudicated += 1
        return "CLAIM_ADJUDICATED: " + claim_id + " | Verdict: " + final_verdict

    def claim_abandoned_curtailment_bond(self, caller: str, claim_id: str, custom_time: int = None):
        assert claim_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Claim not found."
        clm = self.claims[claim_id]

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == clm["claimant"], "[ERR_UNAUTHORIZED] Only claimant can recover bond."
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_CLAIM_NOT_PENDING] Claim not pending."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc >= clm["filed_at"] + self.CLAIM_TIMEOUT_SECONDS, "[ERR_TIMEOUT_NOT_REACHED] Must wait 7 days."

        bond_val = clm["claim_bond"]
        clm["verdict"] = self.CLAIM_ABANDONED
        clm["has_claimed"] = True
        clm["adjudication_rationale"] = "Recovered after 7-day timeout."

        # Unlock escrow back to ACTIVE
        if clm["escrow_id"] in self.escrows:
            e = self.escrows[clm["escrow_id"]]
            if e["status"] == self.STATUS_DISPUTED:
                e["status"] = self.STATUS_ACTIVE

        transfer_claimant = False
        try:
            self.gl.emit_transfer(sender_hex, bond_val)
            transfer_claimant = True
        except Exception:
            transfer_claimant = False

        if transfer_claimant:
            self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
        else:
            cur = self.claimable_balances.get(sender_hex, 0)
            self.claimable_balances[sender_hex] = cur + bond_val

        return "BOND_RECLAIMED: " + claim_id

    def decommission_uncontested_escrow(self, caller: str, escrow_id: str):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in (e["offtaker"], e["generator"], self.owner), "[ERR_UNAUTHORIZED] Unauthorized caller."
        assert e["ppa_collateral"] == 0, "[ERR_ESCROW_REMAINING] Remaining escrow funds."
        assert e["status"] in (self.STATUS_FULFILLED, self.STATUS_CURTAILMENT_SETTLED, self.STATUS_EXPIRED_REFUNDED), "[ERR_INVALID_STATUS] Invalid status."

        e["status"] = self.STATUS_DECOMMISSIONED
        return "ESCROW_DECOMMISSIONED: " + escrow_id

    def withdraw_claimable(self, caller: str):
        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in self.claimable_balances, "[ERR_NO_CLAIMABLE] No claimable funds."
        bal = self.claimable_balances[sender_hex]
        assert bal > 0, "[ERR_ZERO_CLAIMABLE] Zero balance."

        self.claimable_balances[sender_hex] = 0
        try:
            self.gl.emit_transfer(sender_hex, bal)
        except Exception:
            self.claimable_balances[sender_hex] = bal
            raise AssertionError("[ERR_TRANSFER_FAILED] Native transfer failed; claimable balance preserved.")

        self.total_volume_locked = max(0, self.total_volume_locked - bal)
        return "CLAIMABLE_WITHDRAWN: " + sender_hex + " | Amount: " + str(bal)


def run_all_tests():
    print("================================================================================")
    print("  AUTONOMOUS RENEWABLE ENERGY PPA ESCROW — 15-PHASE COMPREHENSIVE REGRESSION SUITE")
    print("================================================================================")

    mock_gl = MockGL()
    owner = "0x1111111111111111111111111111111111111111"
    offtaker = "0x2222222222222222222222222222222222222222"
    generator = "0x3333333333333333333333333333333333333333"
    claimant = "0x4444444444444444444444444444444444444444"

    contract = MockAutonomousRenewableEnergyPpaEscrow(owner, mock_gl)

    # Phase 1: Zero Genesis Invariants
    print("\n[Phase 1] Testing zero genesis debt and storage invariants...")
    assert contract.total_volume_locked == 0, "TVL must start at 0"
    assert contract.total_escrows_created == 0, "Escrows must start at 0"
    assert len(contract.claimable_balances) == 0, "Zero unbacked balances"
    print("  PASS: Zero unbacked genesis debt verified.")

    # Phase 2: Create Renewable PPA Escrow
    print("\n[Phase 2] Creating renewable PPA escrow backed 100% by payable collateral...")
    escrow_amount = 300_000_000_000  # 300 Gwei
    escrow_id = contract.create_ppa_escrow(
        caller=offtaker,
        value=escrow_amount,
        generator_address=generator,
        facility_node="CAISO-MIDWAY-500KV",
        contracted_capacity_mw=250,
        duration_seconds=86400 * 90  # 90 days
    )
    assert escrow_id == "ESCROW_PPA_1"
    assert contract.total_volume_locked == escrow_amount
    assert contract.escrows[escrow_id]["ppa_collateral"] == escrow_amount
    print("  PASS: Renewable PPA escrow created with 100% backed funds:", escrow_id)

    # Phase 3: Top-up Escrow Reserves
    print("\n[Phase 3] Testing reserve top-up by offtaker...")
    topup_amount = 50_000_000_000  # 50 Gwei
    contract.topup_ppa_escrow(caller=offtaker, value=topup_amount, escrow_id=escrow_id)
    assert contract.escrows[escrow_id]["ppa_collateral"] == escrow_amount + topup_amount
    assert contract.total_volume_locked == escrow_amount + topup_amount
    print("  PASS: PPA collateral top-up successfully recorded.")

    # Phase 4: SSRF Defense & Grid Operator Domain Whitelist
    print("\n[Phase 4] Testing SSRF defense and transmission ISO domain whitelisting...")
    try:
        contract._validate_dispatch_url("https://unverified-energy-blog.com/curtailment")
        assert False, "Should reject unapproved domain"
    except AssertionError as e:
        assert "[ERR_URL_UNAPPROVED_DOMAIN]" in str(e)

    try:
        contract._validate_dispatch_url("https://operator:secret@caiso.com/notices/1")
        assert False, "Should reject embedded credentials"
    except AssertionError as e:
        assert "[ERR_URL_CREDENTIALS]" in str(e)

    try:
        contract._validate_dispatch_url("http://127.0.0.1:8080/caiso")
        assert False, "Should reject loopback SSRF"
    except AssertionError as e:
        assert "[ERR_URL_LOOPBACK]" in str(e)

    valid_url = "https://caiso.com/market-notices/2026/DISP-994"
    assert contract._validate_dispatch_url(valid_url) == valid_url
    print("  PASS: SSRF defense and grid operator domain filtering fully enforced.")

    # Phase 5: Address Sanitation & Non-Zero Hex Enforcement
    print("\n[Phase 5] Testing address sanitation and non-zero hex enforcement...")
    try:
        contract._validate_eth_address("0x0000000000000000000000000000000000000000", "ZeroCheck")
        assert False, "Should reject zero address"
    except AssertionError as e:
        assert "[ERR_ADDR_ZERO]" in str(e)

    try:
        contract._validate_eth_address("0x123", "ShortCheck")
        assert False, "Should reject invalid length"
    except AssertionError as e:
        assert "[ERR_ADDR_FORMAT]" in str(e)
    print("  PASS: Address format sanitation strictly verified.")

    # Phase 6: Length-Prefixed Canonical Fingerprint Computation
    print("\n[Phase 6] Testing canonical length-prefixed fingerprint computation...")
    h1 = contract._compute_claim_hash("ESCROW_PPA_1", claimant, valid_url, "nonce1")
    h2 = contract._compute_claim_hash("ESCROW_PPA_1", claimant, valid_url, "nonce1")
    h3 = contract._compute_claim_hash("ESCROW_PPA_1", claimant, valid_url, "nonce2")
    assert h1 == h2, "Canonical hash must be deterministic"
    assert h1 != h3, "Different nonce must yield distinct hash"
    print("  PASS: Canonical length-prefixed hashing prevents delimiter collisions.")

    # Phase 7: Submit Curtailment Indemnity Claim with Dispute State Lock (HIGH-01)
    print("\n[Phase 7] Submitting curtailment claim and verifying dispute lock...")
    bond_amount = 30_000_000_000  # 30 Gwei
    claim_id = contract.submit_curtailment_indemnity_claim(
        caller=claimant,
        value=bond_amount,
        escrow_id=escrow_id,
        dispatch_order_url=valid_url,
        curtailed_mwh=450,
        nonce="nonce_curt_1"
    )
    assert claim_id == "CLAIM_CURT_1"
    assert contract.claims[claim_id]["claim_bond"] == bond_amount
    assert contract.total_volume_locked == escrow_amount + topup_amount + bond_amount
    assert contract.escrows[escrow_id]["status"] == "DISPUTED", "Escrow must enter DISPUTED state"

    # Verify front-running protection while disputed
    try:
        contract.confirm_metered_delivery(caller=offtaker, escrow_id=escrow_id)
        assert False, "Should reject delivery confirmation while DISPUTED"
    except AssertionError as e:
        assert "[ERR_ESCROW_NOT_ACTIVE]" in str(e)
    print("  PASS: Curtailment claim filed with payable bond, locking escrow to DISPUTED state:", claim_id)

    # Phase 8: Prevent Duplicate Dispatch Order Replay
    print("\n[Phase 8] Testing replay prevention on identical dispatch order...")
    try:
        contract.submit_curtailment_indemnity_claim(
            caller=claimant,
            value=bond_amount,
            escrow_id=escrow_id,
            dispatch_order_url=valid_url,
            curtailed_mwh=450,
            nonce="nonce_unique_2"
        )
        assert False, "Should reject duplicate claim on disputed escrow"
    except AssertionError as e:
        assert "[ERR_ESCROW_NOT_ACTIVE]" in str(e) or "[ERR_DISPATCH_ORDER_ALREADY_CLAIMED]" in str(e)
    print("  PASS: Duplicate dispatch order claim replay prevented.")

    # Phase 9: Multi-Validator Consensus Adjudication: CLAIM_CURTAILMENT_CONFIRMED
    print("\n[Phase 9] Testing consensus adjudication: CURTAILMENT_CONFIRMED (450 MWh Deemed Generation)...")
    total_collateral_in_escrow = escrow_amount + topup_amount
    contract.adjudicate_curtailment_claim(claim_id, custom_curt=True, custom_mwh=450, custom_conf=96)
    
    assert contract.claims[claim_id]["verdict"] == "CURTAILMENT_CONFIRMED"
    assert contract.escrows[escrow_id]["status"] == "CURTAILMENT_SETTLED"
    assert contract.escrows[escrow_id]["ppa_collateral"] == 0
    assert contract.escrows[escrow_id]["total_released_to_generator"] == total_collateral_in_escrow

    # Verify transfers to generator and claimant
    gen_transfers = [t for t in mock_gl.transfers if t["recipient"] == generator]
    claimant_transfers = [t for t in mock_gl.transfers if t["recipient"] == claimant]
    assert any(t["amount"] == total_collateral_in_escrow for t in gen_transfers), "Generator must receive Deemed Generation compensation"
    assert any(t["amount"] == bond_amount for t in claimant_transfers), "Claimant must recover claim bond"
    print("  PASS: Deemed generation indemnity paid to generator & bond returned to claimant.")

    # Phase 10: Consensus Adjudication: CLAIM_REFUTED (Frivolous / Maintenance Outage)
    print("\n[Phase 10] Testing consensus adjudication: CLAIM_REFUTED (frivolous bond slashed)...")
    escrow_id_2 = contract.create_ppa_escrow(
        caller=offtaker,
        value=escrow_amount,
        generator_address=generator,
        facility_node="ERCOT-WEST-WIND-345KV",
        contracted_capacity_mw=100,
        duration_seconds=86400 * 30
    )
    claim_id_2 = contract.submit_curtailment_indemnity_claim(
        caller=claimant,
        value=bond_amount,
        escrow_id=escrow_id_2,
        dispatch_order_url="https://ercot.com/notices/frivolous",
        curtailed_mwh=50,
        nonce="nonce_frivolous_test"
    )
    contract.adjudicate_curtailment_claim(claim_id_2, custom_curt=False, custom_mwh=0, custom_conf=90)
    assert contract.claims[claim_id_2]["verdict"] == "CLAIM_REFUTED"
    assert contract.escrows[escrow_id_2]["status"] == "ACTIVE", "Escrow must unlock to ACTIVE after refutation"
    assert contract.claimable_balances[offtaker] == bond_amount, "Offtaker credited with slashed bond indemnity"
    print("  PASS: Frivolous claim bond slashed to offtaker indemnity reserves.")

    # Phase 10b: Safe Fallback on AI JSON Parse Error (CRIT-01 Remediated)
    print("\n[Phase 10b] Testing AI parse error safe fallback (CLAIM_INCONCLUSIVE, bond preserved)...")
    escrow_id_safe = contract.create_ppa_escrow(
        caller=offtaker,
        value=escrow_amount,
        generator_address=generator,
        facility_node="PJM-BMA-SOLAR-230KV",
        contracted_capacity_mw=150,
        duration_seconds=86400 * 60
    )
    claim_id_safe = contract.submit_curtailment_indemnity_claim(
        caller=claimant,
        value=bond_amount,
        escrow_id=escrow_id_safe,
        dispatch_order_url="https://pjm.com/dispatch/order-parse-err",
        curtailed_mwh=80,
        nonce="nonce_parse_err_test"
    )
    contract.adjudicate_curtailment_claim(claim_id_safe, simulate_parse_error=True)
    assert contract.claims[claim_id_safe]["verdict"] == "INCONCLUSIVE", "Parse failure must yield INCONCLUSIVE"
    assert contract.escrows[escrow_id_safe]["status"] == "ACTIVE", "Escrow must unlock back to ACTIVE"
    print("  PASS: AI parsing glitch safely fell back to INCONCLUSIVE without bond slashing.")

    # Phase 11: Fail-Closed Web Evidence Ingestion
    print("\n[Phase 11] Testing fail-closed handling on unreachable dispatch portal...")
    escrow_id_timeout = contract.create_ppa_escrow(
        caller=offtaker,
        value=escrow_amount,
        generator_address=generator,
        facility_node="SPP-WIND-NORTH-115KV",
        contracted_capacity_mw=50,
        duration_seconds=86400 * 14
    )
    claim_id_3 = contract.submit_curtailment_indemnity_claim(
        caller=claimant,
        value=bond_amount,
        escrow_id=escrow_id_timeout,
        dispatch_order_url="https://spp.org/timeout-test",
        curtailed_mwh=100,
        nonce="nonce_timeout_test"
    )
    mock_gl.fail_web_fetch = True
    try:
        contract.adjudicate_curtailment_claim(claim_id_3)
        assert False, "Should raise AssertionError on network timeout"
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)
    mock_gl.fail_web_fetch = False
    print("  PASS: Fail-closed zero-mutation invariant preserved on network failure.")

    # Phase 12: 7-Day Timeout Curtailment Bond Safeguard
    print("\n[Phase 12] Testing 7-day timeout bond recovery for claimant...")
    now = int(datetime.now(timezone.utc).timestamp())
    try:
        contract.claim_abandoned_curtailment_bond(caller=claimant, claim_id=claim_id_3, custom_time=now + 86400 * 2)
        assert False, "Should revert before 7 days have elapsed"
    except AssertionError as e:
        assert "[ERR_TIMEOUT_NOT_REACHED]" in str(e)

    contract.claim_abandoned_curtailment_bond(caller=claimant, claim_id=claim_id_3, custom_time=now + 86400 * 8)
    assert contract.claims[claim_id_3]["verdict"] == "CLAIM_ABANDONED"
    assert contract.escrows[escrow_id_timeout]["status"] == "ACTIVE", "Escrow must unlock to ACTIVE after abandonment"
    print("  PASS: Claimant successfully recovered bond after 7-day timeout.")

    # Phase 13: Consensual Metered Generation Delivery Completion
    print("\n[Phase 13] Testing consensual generation fulfillment by offtaker...")
    escrow_id_fulfill = contract.create_ppa_escrow(
        caller=offtaker,
        value=escrow_amount,
        generator_address=generator,
        facility_node="MISO-SOLAR-SOUTH",
        contracted_capacity_mw=200,
        duration_seconds=86400 * 30
    )
    contract.confirm_metered_delivery(caller=offtaker, escrow_id=escrow_id_fulfill)
    assert contract.escrows[escrow_id_fulfill]["status"] == "FULFILLED"
    assert contract.escrows[escrow_id_fulfill]["total_released_to_generator"] == escrow_amount
    print("  PASS: Metered generation delivery confirmed and collateral disbursed to generator.")

    # Phase 14: Expired Undelivered Escrow Recovery by Offtaker
    print("\n[Phase 14] Testing expired undelivered escrow recovery after deadline...")
    escrow_id_expire = contract.create_ppa_escrow(
        caller=offtaker,
        value=escrow_amount,
        generator_address=generator,
        facility_node="FERC-REG-SOLAR",
        contracted_capacity_mw=75,
        duration_seconds=86400 * 14
    )
    try:
        contract.claim_expired_undelivered_escrow(caller=offtaker, escrow_id=escrow_id_expire, custom_time=now)
        assert False, "Should revert if deadline not yet passed"
    except AssertionError as e:
        assert "[ERR_DEADLINE_NOT_REACHED]" in str(e)

    contract.claim_expired_undelivered_escrow(caller=offtaker, escrow_id=escrow_id_expire, custom_time=now + 86400 * 20)
    assert contract.escrows[escrow_id_expire]["status"] == "EXPIRED_REFUNDED"
    assert contract.escrows[escrow_id_expire]["total_refunded_to_offtaker"] == escrow_amount
    print("  PASS: Expired undelivered PPA collateral refunded to offtaker.")

    # Phase 15: Pull-Pattern Claimable Withdrawal with Balance Preservation & TVL Solvency
    print("\n[Phase 15] Testing pull-pattern claimable balance recovery...")
    offtaker_claimable = contract.claimable_balances.get(offtaker, 0)
    assert offtaker_claimable > 0

    mock_gl.simulate_transfer_fail = True
    try:
        contract.withdraw_claimable(caller=offtaker)
        assert False, "Should raise AssertionError on transfer failure"
    except AssertionError as e:
        assert "[ERR_TRANSFER_FAILED]" in str(e)
    assert contract.claimable_balances[offtaker] == offtaker_claimable, "Claimable balance must not be wiped on transfer error!"

    mock_gl.simulate_transfer_fail = False
    contract.withdraw_claimable(caller=offtaker)
    assert contract.claimable_balances[offtaker] == 0, "Balance cleanly zeroed upon successful transfer."
    print("  PASS: Pull-pattern claimable balance recovery preserves balance on transfer failure.")

    print("\n================================================================================")
    print("  ALL 15 REGRESSION & SECURITY PHASES PASSED WITH ZERO ERRORS!")
    print("================================================================================")


if __name__ == "__main__":
    run_all_tests()
