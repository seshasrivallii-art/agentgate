"""Minimal human approval interface.

    python scripts/approver_cli.py --user alice list
    python scripts/approver_cli.py --user alice show <approval_id>
    python scripts/approver_cli.py --user alice approve <approval_id>
    python scripts/approver_cli.py --user alice reject <approval_id>
"""
import argparse
import json
import os
import sys

import httpx

from agent.auth_client import bearer, human_token

GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:8000")


def show(view: dict) -> None:
    action = view["action"]
    print(f"Approval   {view['id']}  [{view['status']}]")
    print(f"Agent      {view['requested_by']}   Tenant {view['tenant_id']}")
    print(f"Operation  {view['tool']}   Resources {', '.join(action['resources'])}")
    print(f"Expires    {view['expires_at']}   Policy reason: {view['policy_reason']}")
    print("Exact payload:")
    print(json.dumps(action["arguments"], indent=2, ensure_ascii=False))
    print(f"Digest     {view['action_digest']}")
    if view.get("execution"):
        print(f"Execution  {view['execution']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default="alice")
    parser.add_argument("command", choices=["list", "show", "approve", "reject"])
    parser.add_argument("approval_id", nargs="?")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = parser.parse_args()

    headers = bearer(human_token(args.user))
    if args.command == "list":
        rows = httpx.get(f"{GATEWAY}/v1/approvals", headers=headers).json()
        for r in rows:
            print(f"{r['id']}  {r['requested_by']:15} {r['action']['arguments'].get('title', '')!r}  expires {r['expires_at']}")
        if not rows:
            print("No pending approvals.")
        return 0

    if not args.approval_id:
        parser.error("approval_id is required")
    response = httpx.get(f"{GATEWAY}/v1/approvals/{args.approval_id}", headers=headers)
    if response.status_code != 200:
        print(f"Cannot open approval: {response.status_code} {response.text}")
        return 1
    view = response.json()
    show(view)
    if args.command == "show":
        return 0

    if not args.yes and input(f"\n{args.command.upper()} this exact action? [y/N] ").strip().lower() != "y":
        print("Cancelled.")
        return 1
    # Echo back the digest of what was displayed: approval is bound to this exact action.
    response = httpx.post(f"{GATEWAY}/v1/approvals/{args.approval_id}/{args.command}",
                          headers=headers, json={"action_digest": view["action_digest"]})
    print(response.status_code, response.text)
    return 0 if response.status_code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
