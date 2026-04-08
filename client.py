# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Cyber Triage Environment Client."""

from typing import Any, Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import CyberTriageAction, CyberTriageObservation


class CyberTriageEnv(
    EnvClient[CyberTriageAction, CyberTriageObservation, State]
):
    """
    Client for the Cyber Triage Environment.

    This client maintains a persistent WebSocket connection to the environment server,
    enabling efficient multi-step interactions with lower latency.
    Each client instance has its own dedicated environment session on the server.
    """

    def _step_payload(self, action: CyberTriageAction) -> Dict[str, Any]:
        return {
            "classification": action.classification,
            "quarantine_ip": action.quarantine_ip,
            "metadata": action.metadata,
        }

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[CyberTriageObservation]:
        obs_data = payload.get("observation", {})
        observation = CyberTriageObservation(
            log_id=obs_data.get("log_id", ""),
            source_ip=obs_data.get("source_ip", ""),
            protocol=obs_data.get("protocol", ""),
            payload_snippet=obs_data.get("payload_snippet", ""),
            failed_login_attempts=obs_data.get("failed_login_attempts", 0),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
