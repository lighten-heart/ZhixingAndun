"""Run with an already installed, exact-version Hermes environment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from dotenv import load_dotenv

from adapters.sdk import GuardClient
from .adapter import HermesGuardAdapter, verify_baseline


def main():
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
    parser = argparse.ArgumentParser(description="AegisGuard pinned Hermes adapter")
    parser.add_argument("--hermes-root", required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--workspace")
    parser.add_argument("--intent")
    parser.add_argument("--model", default="")
    parser.add_argument("--provider", default=None)
    options = parser.parse_args()
    if options.verify_only:
        print(json.dumps(verify_baseline(options.hermes_root), ensure_ascii=False, indent=2))
        return
    if not options.workspace or not options.intent:
        parser.error("--workspace and --intent are required for a real run")
    with GuardClient() as client:
        adapter = HermesGuardAdapter(client, options.workspace)
        adapter.install(options.hermes_root)
        agent, session = adapter.create_agent(options.intent, model=options.model, provider=options.provider)
        try:
            print(json.dumps({"guard_session_id": session["id"], "baseline": adapter.baseline}, ensure_ascii=False))
            print(json.dumps(agent.run_conversation(options.intent), ensure_ascii=False, default=str))
        finally:
            agent.close()


if __name__ == "__main__":
    main()
