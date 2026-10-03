"""Publish reviewed hardware results as discoverable #889 comment bundles.

GitHub credentials stay in the trusted operator process. No artifact directory,
candidate log or arbitrary file is uploaded. A private attempt record alone is
not publication; every comment is read back before publication is verified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

if __name__ == "__main__":
    # The trusted installation can replay publication before installing its
    # own CLI environment. Reuse only its stdlib process-identity helper in
    # this parent; no PYTHONPATH is forwarded to candidate subprocesses.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))

from .attempt_results import HardwareAttempt

REPOSITORY = "craigbalding/safeyolo"
ISSUE = 889
COMMENT_CHARACTERS = 28000


class GitHubResults:
    """Use the installed gh client and its existing approved GitHub principal."""

    def api(self, endpoint: str, method: str = "GET", body: str | None = None) -> dict:
        route = f"repos/{REPOSITORY}" + (f"/{endpoint}" if endpoint else "")
        command = ["gh", "api", route, "--method", method]
        options = {"capture_output": True, "text": True, "timeout": 60, "check": True}
        if body is not None:
            command += ["--input", "-"]
            options["input"] = json.dumps({"body": body})
        response = subprocess.run(command, **options)
        data = json.loads(response.stdout)
        if not isinstance(data, dict):
            raise ValueError("GitHub returned an invalid comment")
        return data

    def verify_index(self, body: str, comment_id: int) -> None:
        previous = self.api(f"issues/comments/{comment_id}")
        expected_url = f"https://github.com/{REPOSITORY}/issues/{ISSUE}#issuecomment-{comment_id}"
        if (previous.get("id") != comment_id or previous.get("html_url") != expected_url
                or not isinstance(previous.get("body"), str)
                or previous["body"].splitlines()[:1] != body.splitlines()[:1]):
            raise ValueError("index update does not belong to this hardware attempt")

    def comment(self, body: str, comment_id: int | None = None) -> dict:
        if comment_id is not None:
            self.verify_index(body, comment_id)
        endpoint = f"issues/{ISSUE}/comments" if comment_id is None else f"issues/comments/{comment_id}"
        response = self.api(endpoint, "POST" if comment_id is None else "PATCH", body)
        identifier = response["id"]
        if type(identifier) is not int or identifier <= 0:
            raise ValueError("GitHub returned an invalid comment identity")
        url = f"https://github.com/{REPOSITORY}/issues/{ISSUE}#issuecomment-{identifier}"
        if response.get("html_url") != url or response.get("body") != body:
            raise ValueError("GitHub comment response differs from submitted report")
        # API mutation success is insufficient: inspect the durable record.
        observed = self.api(f"issues/comments/{identifier}")
        if observed.get("id") != identifier or observed.get("html_url") != url or observed.get("body") != body:
            raise ValueError("published report could not be read back exactly")
        return {"id": identifier, "url": url, "sha256": hashlib.sha256(body.encode()).hexdigest()}


def index_body(attempt: HardwareAttempt, parts: list[dict], *, verified: bool) -> str:
    data = attempt.data
    selected = data["source_revision"]
    source = f"[{selected}](https://github.com/{REPOSITORY}/commit/{selected})" if selected else "not selected"
    state = ("complete paired execution" if attempt.execution_succeeded() else "failed or incomplete execution")
    if data["finished_at"] is None:
        state = "attempt in progress"
    publication = "read-back verified" if verified else "pending or failed; this attempt cannot pass"
    failures = ", ".join(f"{row['stage']} ({row['lane'] or 'paired'})" for row in data["failures"]) or "none recorded"
    limitations = sum((row.get("result") or {}).get("skipped_assertions", 0) for row in data["lanes"].values())
    links = "\n".join(f"- [Report part {number}]({row['url']})" for number, row in enumerate(parts, 1))
    return (f"Hardware attempt `{data['run_id']}` — {data['trigger']}\n\n"
            f"Selected source: {source}. Trusted installation: `{data['controller_revision']}`.\n\n"
            f"Execution: {state}. Publication: {publication}. Failures: {failures}. "
            f"Skipped assertions: {limitations}; skipped assertions remain unproved.\n\n"
            f"Owner: `{data['owner']}`. Started: {data['started_at']}. Finished: {data['finished_at'] or 'pending'}.\n\n"
            f"{links}\n\n"
            "Reports select installed identities, outcomes and trusted cleanup status. "
            "Independent issue acceptance remains with Lens. Private logs and instance state are excluded.")


def announce_attempt(attempt: HardwareAttempt, github: GitHubResults) -> None:
    """Leave a visible index before preflight or candidate fetch/execution."""
    try:
        receipt = github.comment(index_body(attempt, [], verified=False))
        attempt.data["publication"]["index"] = receipt
        attempt.save()
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        attempt.data["publication"]["verified"] = False
        attempt.fail("publication")
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt", type=Path, required=True,
                        help="existing trusted attempt directory outside candidate execution trees")
    args = parser.parse_args()
    try:
        attempt = HardwareAttempt.restore(args.attempt.resolve())
        publish_attempt(attempt, GitHubResults())
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as exc:
        print(f"Hardware publication remains unverified ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(json.dumps({"run_id": attempt.data["run_id"], "index": attempt.data["publication"]["index"]["url"],
                      "publication_verified": True, "attempt_passed": attempt.passed()}))
    return 0


@contextmanager
def managed_attempt(root: Path, controller_revision: str, trigger: str, github: GitHubResults):
    """Persist and announce first; publish failure while preserving shutdown."""
    attempt = HardwareAttempt(root, controller_revision, trigger)
    completed = False
    try:
        announce_attempt(attempt, github)
        yield attempt
        completed = True
    finally:
        if not completed and not attempt.data["failures"]:
            attempt.fail("execution")
        attempt.finish()
        if completed:
            publish_attempt(attempt, github)
        else:
            try:
                publish_attempt(attempt, github)
            except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
                pass  # The pending index/outbox records publication failure; preserve the caller's original exception.


def publish_attempt(attempt: HardwareAttempt, github: GitHubResults) -> None:
    """Retain failed originals; interrupted publication resumes verified parts."""
    publication = attempt.data["publication"]
    publication["verified"] = False
    attempt.save()
    try:
        if publication["index"] is None:
            announce_attempt(attempt, github)
        github.verify_index(index_body(attempt, [], verified=False), publication["index"]["id"])
        document = json.dumps(attempt.publication_result(), indent=2, sort_keys=True, ensure_ascii=True)
        chunks = [document[offset:offset + COMMENT_CHARACTERS] for offset in range(0, len(document), COMMENT_CHARACTERS)]
        parts = []
        for number, chunk in enumerate(chunks, 1):
            # Chunks are bounded text, together forming one JSON document.
            # Quotes/backticks inside observed test names cannot escape JSON.
            body = (f"Hardware attempt `{attempt.data['run_id']}` report part {number}/{len(chunks)}\n\n"
                    f"[Run index]({publication['index']['url']})\n\n```json\n{chunk}\n```")
            digest = hashlib.sha256(body.encode()).hexdigest()
            prior = next((part for part in publication["parts"] if part["sha256"] == digest), None)
            if prior is not None:
                observed = github.api(f"issues/comments/{prior['id']}")
                if observed.get("body") != body or observed.get("html_url") != prior["url"]:
                    raise ValueError("retained publication part changed or disappeared")
                receipt = prior
            else:
                receipt = github.comment(body)
                publication["parts"].append(receipt)
                attempt.save()
            parts.append(receipt)
        # A pending index with all links is recoverable if the final update
        # fails. No partially uploaded bundle is represented as a pass.
        github.comment(index_body(attempt, parts, verified=False), publication["index"]["id"])
        final = github.comment(index_body(attempt, parts, verified=True), publication["index"]["id"])
        publication.update(index=final, verified=True)
        attempt.save()
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        publication["verified"] = False
        attempt.fail("publication")
        # The initially published index remains a discoverable failure route.
        # A GitHub outage can also prevent this update; preserve the durable
        # attempt/outbox and propagate failure for the operator's retry.
        if publication["index"] is not None:
            try:
                github.comment(index_body(attempt, publication["parts"], verified=False), publication["index"]["id"])
            except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
                pass  # Publication already failed; the pending index/outbox remains and failure propagates below.
        raise


if __name__ == "__main__":
    raise SystemExit(main())
