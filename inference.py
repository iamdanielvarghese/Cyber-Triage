"""
Inference script — Cyber Triage (OpenEnv CyberTriageEnvironment)
==================================================================
Environment variables (see project README / hackathon checklist):
    API_BASE_URL   LLM API base URL (OpenAI-compatible).
    MODEL_NAME     Model identifier.
    HF_TOKEN or API_KEY   API key.

STDOUT FORMAT (mandatory line types)
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

from __future__ import annotations

import json
import os
import re
import textwrap
from typing import Any, List, Optional

from openai import OpenAI

from models import CyberTriageAction, CyberTriageObservation
from server.cyber_triage_environment import (
    SCORE_FAIL,
    SCORE_FULL,
    CyberTriageEnvironment,
)

API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
BENCHMARK = os.getenv("CYBER_TRIAGE_BENCHMARK", "cyber_triage")
TEMPERATURE = 0.2
MAX_TOKENS = 512
SUCCESS_SCORE_THRESHOLD = 0.5


def clamp_task_score(value: float) -> float:
    """Keep reported scores strictly inside (0, 1) with same band as the environment."""
    return max(SCORE_FAIL, min(SCORE_FULL, float(value)))


# Deterministic seeds so each episode maps to Easy / Medium / Hard (see environment RNG).
EPISODE_PLAN: tuple[tuple[str, int], ...] = (
    ("brute_force_blocker", 1),
    ("payload_inspector", 0),
    ("multi_vector_anomaly", 5),
)

_CLASSIFICATIONS = frozenset({"Safe", "Suspicious", "Critical Attack"})

SYSTEM_PROMPT = textwrap.dedent(
    """
    You are an Enterprise Cybersecurity Analyst triaging security telemetry.
    Given a single log event, you must decide how to classify it and whether to quarantine the source IP.

    Respond with a valid JSON object ONLY (no markdown fences, no commentary). The object must contain exactly these two keys:
      "classification" — one of the strings: "Safe", "Suspicious", or "Critical Attack".
      "quarantine_ip" — a string containing the IPv4 address to block, or null if you are not quarantining an IP.

    Base your answer only on the evidence in the user message. Prefer quarantine when the activity clearly warrants containment.
    """
).strip()


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


def build_user_prompt(obs: CyberTriageObservation) -> str:
    return textwrap.dedent(
        f"""
        Security log event to triage:

        log_id: {obs.log_id}
        source_ip: {obs.source_ip}
        protocol: {obs.protocol}
        payload_snippet: {obs.payload_snippet}
        failed_login_attempts: {obs.failed_login_attempts}

        Output your JSON decision now.
        """
    ).strip()


def _extract_json_object(text: str) -> Optional[dict[str, Any]]:
    """Best-effort extraction of a JSON object from model output."""
    raw = text.strip()
    if not raw:
        return None
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw, re.IGNORECASE)
    if fence:
        raw = fence.group(1).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None


def parse_action_from_llm_text(text: str) -> CyberTriageAction:
    """
    Parse classification and quarantine_ip from the LLM response.
    On any failure, fall back to Safe with no quarantine.
    """
    data = _extract_json_object(text)
    if not isinstance(data, dict):
        return CyberTriageAction(classification="Safe", quarantine_ip=None)

    cls = data.get("classification")
    if not isinstance(cls, str) or cls not in _CLASSIFICATIONS:
        cls = "Safe"

    q = data.get("quarantine_ip")
    quarantine: Optional[str]
    if q is None or q == "null":
        quarantine = None
    elif isinstance(q, str):
        quarantine = q.strip() or None
    else:
        quarantine = None

    return CyberTriageAction(classification=cls, quarantine_ip=quarantine)


def get_model_message(client: OpenAI, user_prompt: str) -> str:
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        return (completion.choices[0].message.content or "").strip()
    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return "{}"


def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    env = CyberTriageEnvironment()

    rewards: List[float] = []
    grader_scores: List[float] = []
    steps_taken = 0
    success = False
    score = SCORE_FAIL

    global_step = 0

    try:
        for episode_idx, (expected_task, seed) in enumerate(EPISODE_PLAN, start=1):
            log_start(task=expected_task, env=BENCHMARK, model=MODEL_NAME)

            obs = env.reset(seed=seed)
            actual_task = obs.metadata.get("task", "unknown")
            if actual_task != expected_task:
                print(
                    f"[WARN] seed={seed} expected task {expected_task!r} but got {actual_task!r}",
                    flush=True,
                )

            user_prompt = build_user_prompt(obs)
            raw_reply = get_model_message(client, user_prompt)
            action = parse_action_from_llm_text(raw_reply)

            result_obs = env.step(action)
            global_step += 1
            steps_taken = global_step

            reward_raw = result_obs.reward
            reward = clamp_task_score(float(reward_raw)) if reward_raw is not None else SCORE_FAIL
            grader_raw = result_obs.metadata.get("grader_score")
            if grader_raw is None:
                grader_raw = reward_raw if reward_raw is not None else SCORE_FAIL
            grader = clamp_task_score(float(grader_raw))
            done = bool(result_obs.done)
            err: Optional[str] = None

            rewards.append(reward)
            grader_scores.append(grader)

            action_str = json.dumps(
                {
                    "classification": action.classification,
                    "quarantine_ip": action.quarantine_ip,
                },
                ensure_ascii=False,
            )
            log_step(
                step=global_step,
                action=action_str,
                reward=reward,
                done=done,
                error=err,
            )

            print(
                f"[EPISODE] index={episode_idx} task={actual_task} "
                f"reward={reward:.2f} grader_score={grader:.2f}",
                flush=True,
            )

        mean_grader = (
            sum(grader_scores) / len(grader_scores) if grader_scores else SCORE_FAIL
        )
        score = clamp_task_score(mean_grader)
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        try:
            env.close()
        except Exception as exc:
            print(f"[DEBUG] env.close() error: {exc}", flush=True)
        final_score = clamp_task_score(score)
        clamped_rewards = [clamp_task_score(r) for r in rewards]
        log_end(success=success, steps=steps_taken, score=final_score, rewards=clamped_rewards)


if __name__ == "__main__":
    main()
