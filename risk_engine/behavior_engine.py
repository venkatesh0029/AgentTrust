"""
AI Agent Behavioral Intelligence Engine (UEBA for Autonomous AI Agents).

Extends AgentTrust beyond static RBAC and signatures by learning continuous
behavioral baselines for each registered agent:
1. Multi-factor statistical baseline modeling (amounts, velocity, destination peer-sets, temporal schedules).
2. Action sequence anomaly modeling (Markov transition probabilities).
3. Explainable anomaly scoring (0-100) with binary behavior indicator flags (0/1).
4. Automatic escalation: Suspicious behavioral anomalies trigger Human Approval tickets or stricter policy enforcement.
5. Invariant: The behavioral model only recommends additional restrictions or human escalation;
   it NEVER independently grants authorization.
"""

from __future__ import annotations

import collections
import datetime
import json
import math
import sqlite3
import threading
import time
import uuid
from typing import Any


class AgentBehaviorEngine:
    _instance: AgentBehaviorEngine | None = None
    _lock = threading.Lock()

    def __new__(cls) -> AgentBehaviorEngine:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: str = "agenttrust_persistent.db") -> None:
        if getattr(self, "_initialized", False):
            return
        self.db_path = db_path
        self._engine_lock = threading.RLock()
        self.profiles: dict[str, dict[str, Any]] = {}
        self.recent_events: list[dict[str, Any]] = []
        # In-memory sliding transaction window: agent_id -> list of timestamps
        self._sliding_windows: dict[str, collections.deque[float]] = collections.defaultdict(
            lambda: collections.deque(maxlen=200)
        )
        # Agent last action for Markov sequence modeling
        self._last_actions: dict[str, str] = {}
        self._init_db()
        self._load_or_seed()
        self._initialized = True

    # -------------------------------------------------------------------------
    # Database Initialization & Persistence
    # -------------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._engine_lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS agent_behavior_profiles (
                            agent_id TEXT PRIMARY KEY,
                            agent_name TEXT NOT NULL,
                            role TEXT NOT NULL,
                            sample_count INTEGER NOT NULL,
                            amount_mean REAL NOT NULL,
                            amount_std REAL NOT NULL,
                            amount_min REAL NOT NULL,
                            amount_max REAL NOT NULL,
                            daily_frequency_mean REAL NOT NULL,
                            daily_frequency_std REAL NOT NULL,
                            hourly_burst_threshold INTEGER NOT NULL,
                            known_destinations TEXT NOT NULL,
                            schedule_start_hour INTEGER NOT NULL,
                            schedule_end_hour INTEGER NOT NULL,
                            action_transitions TEXT NOT NULL,
                            baseline_risk_score INTEGER NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)

                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS agent_behavior_events (
                            event_id TEXT PRIMARY KEY,
                            request_id TEXT NOT NULL,
                            agent_id TEXT NOT NULL,
                            action TEXT NOT NULL,
                            resource TEXT NOT NULL,
                            amount REAL NOT NULL,
                            timestamp TEXT NOT NULL,
                            flag_unusual_amount INTEGER NOT NULL,
                            flag_unfamiliar_recipient INTEGER NOT NULL,
                            flag_unusual_schedule INTEGER NOT NULL,
                            flag_burst_velocity INTEGER NOT NULL,
                            flag_sequence_anomaly INTEGER NOT NULL,
                            anomaly_score INTEGER NOT NULL,
                            risk_level TEXT NOT NULL,
                            enforcement TEXT NOT NULL,
                            explainable_reasons TEXT NOT NULL,
                            insights_json TEXT NOT NULL
                        )
                    """)
                    conn.commit()
            except Exception as e:
                print(f"[BehaviorEngine] Warning: database init exception: {e}")

    # -------------------------------------------------------------------------
    # Baseline Profile Seeding & Loading
    # -------------------------------------------------------------------------

    def _load_or_seed(self) -> None:
        with self._engine_lock:
            loaded = self._load_from_db()
            if not loaded or len(self.profiles) == 0:
                self.reset_to_canonical_baselines()

    def _load_from_db(self) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM agent_behavior_profiles")
                rows = cursor.fetchall()
                if not rows:
                    return False

                self.profiles.clear()
                for r in rows:
                    destinations = json.loads(r["known_destinations"])
                    transitions = json.loads(r["action_transitions"])
                    self.profiles[r["agent_id"]] = {
                        "agent_id": r["agent_id"],
                        "agent_name": r["agent_name"],
                        "role": r["role"],
                        "sample_count": int(r["sample_count"]),
                        "amount_mean": float(r["amount_mean"]),
                        "amount_std": float(r["amount_std"]),
                        "amount_min": float(r["amount_min"]),
                        "amount_max": float(r["amount_max"]),
                        "daily_frequency_mean": float(r["daily_frequency_mean"]),
                        "daily_frequency_std": float(r["daily_frequency_std"]),
                        "hourly_burst_threshold": int(r["hourly_burst_threshold"]),
                        "known_destinations": destinations,
                        "schedule_start_hour": int(r["schedule_start_hour"]),
                        "schedule_end_hour": int(r["schedule_end_hour"]),
                        "action_transitions": transitions,
                        "baseline_risk_score": int(r["baseline_risk_score"]),
                    }

                cursor.execute("SELECT * FROM agent_behavior_events ORDER BY timestamp DESC LIMIT 200")
                event_rows = cursor.fetchall()
                self.recent_events.clear()
                for er in event_rows:
                    self.recent_events.append({
                        "event_id": er["event_id"],
                        "request_id": er["request_id"],
                        "agent_id": er["agent_id"],
                        "action": er["action"],
                        "resource": er["resource"],
                        "amount": float(er["amount"]),
                        "timestamp": er["timestamp"],
                        "flags": {
                            "unusual_amount": bool(er["flag_unusual_amount"]),
                            "unfamiliar_recipient": bool(er["flag_unfamiliar_recipient"]),
                            "unusual_schedule": bool(er["flag_unusual_schedule"]),
                            "burst_velocity": bool(er["flag_burst_velocity"]),
                            "sequence_anomaly": bool(er["flag_sequence_anomaly"]),
                        },
                        "anomaly_score": int(er["anomaly_score"]),
                        "risk_level": er["risk_level"],
                        "enforcement": er["enforcement"],
                        "explainable_reasons": json.loads(er["explainable_reasons"]),
                        "insights": json.loads(er["insights_json"]),
                    })
                return True
        except Exception as e:
            print(f"[BehaviorEngine] Load from DB error: {e}")
            return False

    def reset_to_canonical_baselines(self) -> dict[str, Any]:
        """
        Builds canonical behavioral profiles for enterprise agents:
        - FINANCE_AGENT_01 & FINANCE-AGENT-001 (matching prompt example):
          - Normally transfers ₹5,000–₹20,000 (mean: ₹12,500, std: ₹3,500)
          - Executes 5–10 transactions daily (hourly burst threshold: 10)
          - Three registered vendor accounts: SUPPLIER-101, SUPPLIER-102, SUPPLIER-103
          - Normal schedule: 09:00 - 18:00 UTC
        - PROCUREMENT-AGENT-002, TREASURY-AGENT-003, AUDIT-AGENT-005
        """
        with self._engine_lock:
            self.profiles.clear()
            self.recent_events.clear()
            self._sliding_windows.clear()
            self._last_actions.clear()

            # 1. Finance Agent (The canonical prompt archetype)
            finance_vendors = ["SUPPLIER-101", "SUPPLIER-102", "SUPPLIER-103", "TREASURY-DISBURSEMENT"]
            transitions_fin = {
                "QUERY_BALANCE": {"CREATE_PURCHASE_ORDER": 80, "TRANSFER_FUNDS": 15},
                "CREATE_PURCHASE_ORDER": {"TRANSFER_FUNDS": 70, "AUDIT_REVIEW": 25},
                "TRANSFER_FUNDS": {"AUDIT_REVIEW": 90, "QUERY_BALANCE": 10},
                "AUDIT_REVIEW": {"QUERY_BALANCE": 85, "CREATE_PURCHASE_ORDER": 15},
            }

            profile_fin = {
                "agent_id": "FINANCE_AGENT_01",
                "agent_name": "Treasury Despatch Bot",
                "role": "Treasury Operations Agent",
                "sample_count": 840,
                "amount_mean": 12500.0,
                "amount_std": 3500.0,
                "amount_min": 5000.0,
                "amount_max": 20000.0,
                "daily_frequency_mean": 7.5,
                "daily_frequency_std": 1.8,
                "hourly_burst_threshold": 10,
                "known_destinations": finance_vendors,
                "schedule_start_hour": 9,
                "schedule_end_hour": 18,
                "action_transitions": transitions_fin,
                "baseline_risk_score": 15,
            }
            self.profiles["FINANCE_AGENT_01"] = profile_fin

            # Also alias to FINANCE-AGENT-001
            profile_fin_001 = profile_fin.copy()
            profile_fin_001["agent_id"] = "FINANCE-AGENT-001"
            profile_fin_001["agent_name"] = "Finance Operations Agent"
            self.profiles["FINANCE-AGENT-001"] = profile_fin_001

            # 2. Procurement Agent
            self.profiles["PROCUREMENT-AGENT-002"] = {
                "agent_id": "PROCUREMENT-AGENT-002",
                "agent_name": "Global Procurement Bot",
                "role": "Procurement & Purchase Orders",
                "sample_count": 1250,
                "amount_mean": 28000.0,
                "amount_std": 6000.0,
                "amount_min": 10000.0,
                "amount_max": 45000.0,
                "daily_frequency_mean": 12.0,
                "daily_frequency_std": 2.5,
                "hourly_burst_threshold": 15,
                "known_destinations": ["SUPPLIER-101", "HARDWARE-DIRECT", "LOGISTICS-CORP", "OFFICE-SUPPLY-CO"],
                "schedule_start_hour": 8,
                "schedule_end_hour": 20,
                "action_transitions": transitions_fin,
                "baseline_risk_score": 10,
            }

            # 3. Treasury Liquidity Agent
            self.profiles["TREASURY-AGENT-003"] = {
                "agent_id": "TREASURY-AGENT-003",
                "agent_name": "Treasury Liquidity Agent",
                "role": "Inter-Bank Settlement",
                "sample_count": 520,
                "amount_mean": 45000.0,
                "amount_std": 12000.0,
                "amount_min": 15000.0,
                "amount_max": 75000.0,
                "daily_frequency_mean": 4.0,
                "daily_frequency_std": 1.2,
                "hourly_burst_threshold": 6,
                "known_destinations": ["CENTRAL-TREASURY-VAULT", "RESERVE-LIQUIDITY-POOL", "SUPPLIER-101"],
                "schedule_start_hour": 10,
                "schedule_end_hour": 17,
                "action_transitions": transitions_fin,
                "baseline_risk_score": 20,
            }

            # Pre-seed realistic historical baseline events
            now = datetime.datetime.now(datetime.UTC)
            sample_events = [
                ("FINANCE_AGENT_01", "TRANSFER_FUNDS", "SUPPLIER-101", 11200.0, -120, False, False, False, False, False, 12, "LOW", "ALLOW", ["Matches normal baseline amount and recipient"]),
                ("FINANCE_AGENT_01", "CREATE_PURCHASE_ORDER", "SUPPLIER-102", 14500.0, -85, False, False, False, False, False, 14, "LOW", "ALLOW", ["Within normal procurement threshold"]),
                ("PROCUREMENT-AGENT-002", "CREATE_PURCHASE_ORDER", "HARDWARE-DIRECT", 27000.0, -45, False, False, False, False, False, 10, "LOW", "ALLOW", ["Verified vendor contract PO"]),
                ("TREASURY-AGENT-003", "TRANSFER_FUNDS", "RESERVE-LIQUIDITY-POOL", 42000.0, -15, False, False, False, False, False, 18, "LOW", "ALLOW", ["Scheduled inter-bank liquidity settlement"]),
            ]

            for aid, act, res, amt, min_offset, f_amt, f_rec, f_sch, f_burst, f_seq, score, r_lvl, enf, reasons in sample_events:
                ev_time = (now + datetime.timedelta(minutes=min_offset)).isoformat()
                ev_id = f"UEBA-EV-{uuid.uuid4().hex[:10].upper()}"
                self.recent_events.append({
                    "event_id": ev_id,
                    "request_id": f"REQ-HIST-{uuid.uuid4().hex[:6].upper()}",
                    "agent_id": aid,
                    "action": act,
                    "resource": res,
                    "amount": amt,
                    "timestamp": ev_time,
                    "flags": {
                        "unusual_amount": f_amt,
                        "unfamiliar_recipient": f_rec,
                        "unusual_schedule": f_sch,
                        "burst_velocity": f_burst,
                        "sequence_anomaly": f_seq,
                    },
                    "anomaly_score": score,
                    "risk_level": r_lvl,
                    "enforcement": enf,
                    "explainable_reasons": reasons,
                    "insights": {
                        "agent_insights": {"baseline_mean": amt, "profile_status": "LEARNED_STABLE"},
                        "activity_insights": {"risk_indicators": ["baseline_normal"]},
                    }
                })

            self._persist_all()
            return self.get_summary()

    def _persist_all(self) -> None:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                for p in self.profiles.values():
                    cursor.execute("""
                        INSERT INTO agent_behavior_profiles (
                            agent_id, agent_name, role, sample_count,
                            amount_mean, amount_std, amount_min, amount_max,
                            daily_frequency_mean, daily_frequency_std, hourly_burst_threshold,
                            known_destinations, schedule_start_hour, schedule_end_hour,
                            action_transitions, baseline_risk_score, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(agent_id) DO UPDATE SET
                            agent_name=excluded.agent_name,
                            role=excluded.role,
                            sample_count=excluded.sample_count,
                            amount_mean=excluded.amount_mean,
                            amount_std=excluded.amount_std,
                            amount_min=excluded.amount_min,
                            amount_max=excluded.amount_max,
                            daily_frequency_mean=excluded.daily_frequency_mean,
                            daily_frequency_std=excluded.daily_frequency_std,
                            hourly_burst_threshold=excluded.hourly_burst_threshold,
                            known_destinations=excluded.known_destinations,
                            schedule_start_hour=excluded.schedule_start_hour,
                            schedule_end_hour=excluded.schedule_end_hour,
                            action_transitions=excluded.action_transitions,
                            baseline_risk_score=excluded.baseline_risk_score,
                            updated_at=excluded.updated_at
                    """, (
                        p["agent_id"],
                        p["agent_name"],
                        p["role"],
                        p["sample_count"],
                        p["amount_mean"],
                        p["amount_std"],
                        p["amount_min"],
                        p["amount_max"],
                        p["daily_frequency_mean"],
                        p["daily_frequency_std"],
                        p["hourly_burst_threshold"],
                        json.dumps(p["known_destinations"]),
                        p["schedule_start_hour"],
                        p["schedule_end_hour"],
                        json.dumps(p["action_transitions"]),
                        p["baseline_risk_score"],
                        datetime.datetime.now(datetime.UTC).isoformat(),
                    ))

                for e in self.recent_events[:100]:
                    cursor.execute("""
                        INSERT INTO agent_behavior_events (
                            event_id, request_id, agent_id, action, resource, amount,
                            timestamp, flag_unusual_amount, flag_unfamiliar_recipient,
                            flag_unusual_schedule, flag_burst_velocity, flag_sequence_anomaly,
                            anomaly_score, risk_level, enforcement, explainable_reasons, insights_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(event_id) DO UPDATE SET
                            request_id=excluded.request_id,
                            agent_id=excluded.agent_id,
                            action=excluded.action,
                            resource=excluded.resource,
                            amount=excluded.amount,
                            timestamp=excluded.timestamp,
                            flag_unusual_amount=excluded.flag_unusual_amount,
                            flag_unfamiliar_recipient=excluded.flag_unfamiliar_recipient,
                            flag_unusual_schedule=excluded.flag_unusual_schedule,
                            flag_burst_velocity=excluded.flag_burst_velocity,
                            flag_sequence_anomaly=excluded.flag_sequence_anomaly,
                            anomaly_score=excluded.anomaly_score,
                            risk_level=excluded.risk_level,
                            enforcement=excluded.enforcement,
                            explainable_reasons=excluded.explainable_reasons,
                            insights_json=excluded.insights_json
                    """, (
                        e["event_id"],
                        e["request_id"],
                        e["agent_id"],
                        e["action"],
                        e["resource"],
                        e["amount"],
                        e["timestamp"],
                        int(e["flags"]["unusual_amount"]),
                        int(e["flags"]["unfamiliar_recipient"]),
                        int(e["flags"]["unusual_schedule"]),
                        int(e["flags"]["burst_velocity"]),
                        int(e["flags"]["sequence_anomaly"]),
                        e["anomaly_score"],
                        e["risk_level"],
                        e["enforcement"],
                        json.dumps(e["explainable_reasons"]),
                        json.dumps(e["insights"]),
                    ))
                conn.commit()
        except Exception as ex:
            print(f"[BehaviorEngine] Persist error: {ex}")

    # -------------------------------------------------------------------------
    # Multi-Factor Behavioral Anomaly Evaluation Core
    # -------------------------------------------------------------------------

    def analyze_request(
        self,
        agent_id: str,
        action: str,
        resource: str,
        amount: float = 0.0,
        request_timestamp_iso: str | None = None,
        request_id: str | None = None,
        simulate_window_burst: int = 0,
    ) -> dict[str, Any]:
        """
        Evaluates a request against the agent's learned dynamic behavioral baseline.
        Returns:
        - binary behavior flags (0/1)
        - composite anomaly score (0-100)
        - explainable natural language reasons
        - enforcement recommendation (ALLOW, ENHANCED_AUDIT, REQUIRE_HUMAN_APPROVAL, BLOCK_STRICT)
        - rich JSON-like enrichment insights (AgentInsights, ContextInsights, ActivityInsights)
        """
        with self._engine_lock:
            req_id = request_id or f"REQ-GW-{uuid.uuid4().hex[:6].upper()}"
            ts_iso = request_timestamp_iso or datetime.datetime.now(datetime.UTC).isoformat()
            now_epoch = time.time()

            # Fallback or default profile if agent not yet learned
            profile = self.profiles.get(agent_id)
            if not profile:
                profile = {
                    "agent_id": agent_id,
                    "agent_name": f"Agent {agent_id}",
                    "role": "Registered Autonomous Agent",
                    "sample_count": 50,
                    "amount_mean": 20000.0,
                    "amount_std": 10000.0,
                    "amount_min": 1000.0,
                    "amount_max": 50000.0,
                    "daily_frequency_mean": 10.0,
                    "daily_frequency_std": 3.0,
                    "hourly_burst_threshold": 15,
                    "known_destinations": ["SUPPLIER-101", "SUPPLIER-102", "DEFAULT-GATEWAY"],
                    "schedule_start_hour": 8,
                    "schedule_end_hour": 20,
                    "action_transitions": {},
                    "baseline_risk_score": 10,
                }
                self.profiles[agent_id] = profile

            # -----------------------------------------------------------------
            # 1. Amount Anomaly Detection (Statistical Z-Score)
            # -----------------------------------------------------------------
            flag_unusual_amount = False
            amount_score_inc = 0
            amount_explanation = None

            if amount > 0:
                mean = profile["amount_mean"]
                std = max(profile["amount_std"], 1.0)
                z_score = (amount - mean) / std

                if z_score >= 3.0 or amount > (profile["amount_max"] * 1.5):
                    flag_unusual_amount = True
                    amount_score_inc = min(45, int(z_score * 9))
                    amount_explanation = (
                        f"Transfer amount (₹{amount:,.2f}) is {z_score:.1f}σ above historical mean "
                        f"(₹{mean:,.2f} ± ₹{std:,.2f}, normal max: ₹{profile['amount_max']:,.2f})"
                    )
                elif z_score >= 2.0:
                    amount_score_inc = 20
                    amount_explanation = f"Transfer amount (₹{amount:,.2f}) moderately exceeds historical mean ({z_score:.1f}σ)"

            # -----------------------------------------------------------------
            # 2. Destination / Recipient Familiarity
            # -----------------------------------------------------------------
            flag_unfamiliar_recipient = False
            dest_score_inc = 0
            dest_explanation = None

            clean_resource = resource.strip().upper()
            known_destinations = [d.upper() for d in profile["known_destinations"]]

            # Resources like '*' or generic wildcards don't trigger destination alerts
            if clean_resource and clean_resource not in ("*", "ANY", "NONE"):
                if clean_resource not in known_destinations:
                    flag_unfamiliar_recipient = True
                    dest_score_inc = 30
                    dest_explanation = (
                        f"Unfamiliar recipient: '{resource}' has never been transacted with by {agent_id} "
                        f"(Trusted peers: {', '.join(profile['known_destinations'][:3])})"
                    )

            # -----------------------------------------------------------------
            # 3. Schedule & Off-Hours Detection
            # -----------------------------------------------------------------
            flag_unusual_schedule = False
            schedule_score_inc = 0
            schedule_explanation = None

            try:
                dt = datetime.datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                req_hour = dt.hour
                start_h = profile["schedule_start_hour"]
                end_h = profile["schedule_end_hour"]

                if req_hour < start_h or req_hour > end_h:
                    flag_unusual_schedule = True
                    schedule_score_inc = 20
                    schedule_explanation = (
                        f"Off-hours operation: Request submitted at {req_hour:02d}:{dt.minute:02d} UTC "
                        f"outside agent's normal schedule window ({start_h:02d}:00–{end_h:02d}:00 UTC)"
                    )
            except Exception:
                pass

            # -----------------------------------------------------------------
            # 4. Burst Velocity & Frequency Surge
            # -----------------------------------------------------------------
            flag_burst_velocity = False
            burst_score_inc = 0
            burst_explanation = None

            # Track in sliding 1-hour window
            window = self._sliding_windows[agent_id]
            window.append(now_epoch)
            # Prune events older than 3600 seconds
            cutoff = now_epoch - 3600
            while window and window[0] < cutoff:
                window.popleft()

            effective_window_count = len(window) + simulate_window_burst
            burst_threshold = profile["hourly_burst_threshold"]

            if effective_window_count > burst_threshold:
                flag_burst_velocity = True
                burst_score_inc = min(35, 15 + int((effective_window_count - burst_threshold) * 1.5))
                burst_explanation = (
                    f"Velocity surge: {effective_window_count} actions in sliding window "
                    f"(Hourly burst cap: {burst_threshold}, Daily average: {profile['daily_frequency_mean']:.1f})"
                )

            # -----------------------------------------------------------------
            # 5. Action Sequence & Transition Anomaly (Markov Transition)
            # -----------------------------------------------------------------
            flag_sequence_anomaly = False
            seq_score_inc = 0
            seq_explanation = None

            last_action = self._last_actions.get(agent_id)
            if last_action and profile.get("action_transitions"):
                trans_map = profile["action_transitions"].get(last_action, {})
                if trans_map:
                    total_trans = sum(trans_map.values())
                    prob = trans_map.get(action, 0) / max(total_trans, 1)
                    if prob < 0.05 and action != last_action:
                        flag_sequence_anomaly = True
                        seq_score_inc = 20
                        seq_explanation = (
                            f"Suspicious action sequence: '{last_action}' -> '{action}' has near-zero historical probability (p = {prob:.3f})"
                        )
            self._last_actions[agent_id] = action

            # -----------------------------------------------------------------
            # Composite Behavioral Anomaly Score & Explainability
            # -----------------------------------------------------------------
            base_risk = profile.get("baseline_risk_score", 10)
            total_anomaly_score = min(
                100,
                base_risk + amount_score_inc + dest_score_inc + schedule_score_inc + burst_score_inc + seq_score_inc
            )

            # Collect explainable reasons
            reasons: list[str] = []
            if amount_explanation:
                reasons.append(amount_explanation)
            if dest_explanation:
                reasons.append(dest_explanation)
            if burst_explanation:
                reasons.append(burst_explanation)
            if schedule_explanation:
                reasons.append(schedule_explanation)
            if seq_explanation:
                reasons.append(seq_explanation)

            if not reasons:
                reasons.append("Behavior conforms to established baseline across amount, recipient, frequency, and schedule.")

            # Determine Risk Level & Enforcement Recommendation
            if total_anomaly_score >= 80:
                risk_level = "CRITICAL DEVIATION"
                enforcement = "REQUIRE_HUMAN_APPROVAL"
            elif total_anomaly_score >= 60:
                risk_level = "HIGH ANOMALY"
                enforcement = "REQUIRE_HUMAN_APPROVAL"
            elif total_anomaly_score >= 35:
                risk_level = "MODERATE DEVIATION"
                enforcement = "ENHANCED_AUDIT"
            else:
                risk_level = "LOW / NORMAL"
                enforcement = "ALLOW"

            # Rich JSON-like enrichment (Matching Microsoft Sentinel UEBA Inspector)
            insights = {
                "agent_insights": {
                    "agent_id": agent_id,
                    "agent_name": profile["agent_name"],
                    "role": profile["role"],
                    "historical_samples": profile["sample_count"],
                    "learned_mean": profile["amount_mean"],
                    "learned_std": profile["amount_std"],
                    "baseline_status": "LEARNED_STABLE",
                },
                "destination_insights": {
                    "resource": resource,
                    "is_familiar": not flag_unfamiliar_recipient,
                    "trusted_peer_count": len(profile["known_destinations"]),
                    "trusted_peers": profile["known_destinations"],
                },
                "activity_insights": {
                    "operation_volume_1h": effective_window_count,
                    "burst_threshold": burst_threshold,
                    "execution_hour_utc": dt.hour if "dt" in locals() else 12,
                    "schedule_normal": not flag_unusual_schedule,
                    "risk_indicators": [
                        k for k, v in {
                            "unusual_amount": flag_unusual_amount,
                            "unfamiliar_recipient": flag_unfamiliar_recipient,
                            "burst_velocity": flag_burst_velocity,
                            "unusual_schedule": flag_unusual_schedule,
                            "sequence_anomaly": flag_sequence_anomaly,
                        }.items() if v
                    ],
                }
            }

            event_record = {
                "event_id": f"UEBA-EV-{uuid.uuid4().hex[:10].upper()}",
                "request_id": req_id,
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
                "amount": amount,
                "timestamp": ts_iso,
                "flags": {
                    "unusual_amount": flag_unusual_amount,
                    "unfamiliar_recipient": flag_unfamiliar_recipient,
                    "unusual_schedule": flag_unusual_schedule,
                    "burst_velocity": flag_burst_velocity,
                    "sequence_anomaly": flag_sequence_anomaly,
                },
                "anomaly_score": total_anomaly_score,
                "risk_level": risk_level,
                "enforcement": enforcement,
                "explainable_reasons": reasons,
                "insights": insights,
            }

            # Update recent events list (keep 150)
            self.recent_events.insert(0, event_record)
            if len(self.recent_events) > 150:
                self.recent_events = self.recent_events[:150]

            # Ingest into online moving baseline if request is benign (< 40)
            if total_anomaly_score < 40 and amount > 0:
                self._update_online_stats(agent_id, amount, resource)

            self._persist_all()
            return event_record

    def _update_online_stats(self, agent_id: str, amount: float, resource: str) -> None:
        """
        Welford's online algorithm to continuously adapt rolling mean and variance
        without storing unbounded historical arrays.
        """
        profile = self.profiles.get(agent_id)
        if not profile:
            return

        n = profile["sample_count"] + 1
        old_mean = profile["amount_mean"]
        new_mean = old_mean + (amount - old_mean) / n
        old_var = profile["amount_std"] ** 2
        new_var = old_var + ((amount - old_mean) * (amount - new_mean) - old_var) / n

        profile["sample_count"] = n
        profile["amount_mean"] = round(new_mean, 2)
        profile["amount_std"] = max(100.0, round(math.sqrt(max(0.0, new_var)), 2))
        profile["amount_min"] = min(profile["amount_min"], amount)
        profile["amount_max"] = max(profile["amount_max"], amount)

        clean_res = resource.strip().upper()
        if clean_res and clean_res not in ("*", "ANY", "NONE"):
            if clean_res not in [d.upper() for d in profile["known_destinations"]]:
                profile["known_destinations"].append(clean_res)

    # -------------------------------------------------------------------------
    # High-Level Simulation Scenarios (Matching Prompt Example)
    # -------------------------------------------------------------------------

    def simulate_behavior_scenario(self, scenario_type: str) -> dict[str, Any]:
        """
        Demonstrates the exact scenario from user request:
        - A finance agent normally:
          - Transfers ₹5,000–₹20,000.
          - Executes 5–10 transactions daily.
          - Uses three registered vendor accounts.
        - Suddenly it starts:
          - Making 50 transactions.
          - Using unfamiliar recipients.
          - Operating outside its normal schedule (02:15 AM).
        """
        if scenario_type == "FINANCE_AGENT_DEVIATION":
            # Exact prompt example:
            # - Transfer of ₹95,000 (normal: ₹5k-₹20k)
            # - Unfamiliar recipient: UNKNOWN-OFFSHORE-CORP
            # - Outside normal schedule: 02:15 AM UTC
            # - 50th transaction in sliding window
            ts = datetime.datetime.now(datetime.UTC).replace(hour=2, minute=15).isoformat()
            return self.analyze_request(
                agent_id="FINANCE_AGENT_01",
                action="TRANSFER_FUNDS",
                resource="UNKNOWN-OFFSHORE-CORP-999",
                amount=95000.0,
                request_timestamp_iso=ts,
                request_id=f"REQ-SIM-DEV-{uuid.uuid4().hex[:6].upper()}",
                simulate_window_burst=48,  # Triggers burst > 50
            )

        elif scenario_type == "NORMAL_BASELINE_TRANSACTION":
            # Normal finance agent transaction: ₹12,500 to SUPPLIER-101 at 11:30 AM
            ts = datetime.datetime.now(datetime.UTC).replace(hour=11, minute=30).isoformat()
            return self.analyze_request(
                agent_id="FINANCE_AGENT_01",
                action="TRANSFER_FUNDS",
                resource="SUPPLIER-101",
                amount=12500.0,
                request_timestamp_iso=ts,
                request_id=f"REQ-SIM-NORM-{uuid.uuid4().hex[:6].upper()}",
                simulate_window_burst=0,
            )

        elif scenario_type == "UNFAMILIAR_RECIPIENT_ONLY":
            # Within static amount policy (₹15k), but targeting an unverified new supplier
            ts = datetime.datetime.now(datetime.UTC).replace(hour=14, minute=0).isoformat()
            return self.analyze_request(
                agent_id="FINANCE_AGENT_01",
                action="TRANSFER_FUNDS",
                resource="UNREGISTERED-VENDOR-X7",
                amount=15000.0,
                request_timestamp_iso=ts,
                request_id=f"REQ-SIM-REC-{uuid.uuid4().hex[:6].upper()}",
            )

        elif scenario_type == "BURST_VELOCITY_ONLY":
            # Normal amount and vendor, but submitted 45 times in 5 minutes
            ts = datetime.datetime.now(datetime.UTC).replace(hour=14, minute=30).isoformat()
            return self.analyze_request(
                agent_id="FINANCE_AGENT_01",
                action="CREATE_PURCHASE_ORDER",
                resource="SUPPLIER-101",
                amount=8500.0,
                request_timestamp_iso=ts,
                request_id=f"REQ-SIM-BURST-{uuid.uuid4().hex[:6].upper()}",
                simulate_window_burst=42,
            )

        else:
            raise ValueError(f"Unknown behavioral scenario: {scenario_type}")

    # -------------------------------------------------------------------------
    # Public Telemetry API
    # -------------------------------------------------------------------------

    def get_summary(self) -> dict[str, Any]:
        """
        Returns full UEBA telemetry summary matching Microsoft Sentinel dashboard layout.
        """
        with self._engine_lock:
            total_monitored = len(self.profiles)
            total_events = len(self.recent_events)
            high_anomalies = [e for e in self.recent_events if e["anomaly_score"] >= 70]
            moderate_anomalies = [e for e in self.recent_events if 35 <= e["anomaly_score"] < 70]

            # Top anomalous agents
            agent_max_scores: dict[str, int] = collections.defaultdict(int)
            for e in self.recent_events:
                aid = e["agent_id"]
                agent_max_scores[aid] = max(agent_max_scores[aid], e["anomaly_score"])

            top_entities = sorted(
                [{"agent_id": k, "max_anomaly_score": v, "profile": self.profiles.get(k)} for k, v in agent_max_scores.items()],
                key=lambda x: x["max_anomaly_score"],
                reverse=True
            )[:5]

            return {
                "monitored_agents": total_monitored,
                "total_events_analyzed": total_events,
                "anomalies_detected": len(high_anomalies) + len(moderate_anomalies),
                "critical_deviations_count": len(high_anomalies),
                "top_anomalous_entities": top_entities,
                "recent_events": self.recent_events[:50],
                "profiles": list(self.profiles.values()),
            }


# Singleton accessor
agent_behavior_engine = AgentBehaviorEngine()

