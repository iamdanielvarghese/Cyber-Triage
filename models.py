# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Data models for the Cyber Triage Environment."""

from typing import Literal, Optional

from openenv.core.env_server.types import Action, Observation
from pydantic import Field

ClassificationLabel = Literal["Safe", "Suspicious", "Critical Attack"]


class CyberTriageAction(Action):
    """Agent response: triage classification and optional IP quarantine."""

    classification: ClassificationLabel = Field(
        ...,
        description='One of "Safe", "Suspicious", or "Critical Attack".',
    )
    quarantine_ip: Optional[str] = Field(
        default=None,
        description="IP address to quarantine when blocking; omit if not quarantining.",
    )


class CyberTriageObservation(Observation):
    """Single security log line presented for triage (OpenEnv observation)."""

    log_id: str = Field(..., description="Identifier for this log event.")
    source_ip: str = Field(..., description="Origin IP for the event.")
    protocol: str = Field(..., description="Protocol or service (e.g. SSH, RDP).")
    payload_snippet: str = Field(
        ...,
        description="Short excerpt from the payload or message.",
    )
    failed_login_attempts: int = Field(
        ...,
        ge=0,
        description="Count of failed login attempts associated with this source.",
    )
