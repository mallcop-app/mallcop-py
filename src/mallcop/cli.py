"""Mallcop CLI entrypoint."""

from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
import yaml

from mallcop.campfire_dispatch import CampfireDispatcher
from mallcop.config import load_config, BudgetConfig, DEFAULT_API_URL
from mallcop.cli_format import print_review_human, print_investigate_human, print_finding_human
from mallcop.cli_pipeline import run_scan_pipeline, run_detect_pipeline, run_retrospective_if_transitioning
from mallcop.telegram_bridge import TelegramCampfireBridge
from mallcop.cost_estimator import estimate_costs
from mallcop.patrol_cli import patrol
from mallcop.plugins import discover_plugins, get_search_paths, instantiate_connector
from mallcop.schemas import Finding, Severity
from mallcop.secrets import ConfigError, EnvSecretProvider
from mallcop.store import JsonlStore, Store


def _emit_error(message: str, human: bool) -> None:
    """Emit an error in the appropriate format."""
    if human:
        click.echo(f"ERROR: {message}", err=True)
    else:
        click.echo(json.dumps({"status": "error", "error": message}))


def _build_actor_runner(root: Path, backend: str = "anthropic"):
    """Build an actor runner from a deployment root. Returns None on failure."""
    from mallcop.actors.runtime import build_actor_runner
    from mallcop.llm import build_llm_client
    config = load_config(root)
    store = JsonlStore(root)
    llm_client = build_llm_client(config.llm, backend=backend, pro_config=config.pro)
    if llm_client is None:
        raise ValueError("No LLM client configured")
    return build_actor_runner(
        root=root, store=store, config=config, llm=llm_client,
        validate_paths=True,
    )


def _build_interactive_runner(root: Path, managed_client: Any, config: Any = None) -> Any:
    """Build an InteractiveRuntime from a deployment root and ManagedClient.

    ``config`` may be passed by container-mode callers that skip load_config
    because there is no mallcop.yaml on disk.  When omitted, config is loaded
    from the deployment root as usual.
    """
    from mallcop.actors.interactive_runtime import build_interactive_runtime
    from mallcop.actors.runtime import build_actor_runner
    if config is None:
        config = load_config(root)
    store = JsonlStore(root)
    actor_runner = build_actor_runner(
        root=root, store=store, config=config, llm=managed_client,
        validate_paths=False,
    )
    return build_interactive_runtime(
        root=root, store=store, config=config,
        llm=managed_client, actor_runner=actor_runner,
    )


def _warn_escalation_health(root: Path) -> None:
    """Check escalation paths and warn to stderr if broken.

    Non-blocking — just a warning. Called by any command that touches
    a deployment repo so the operator always knows if alerting is dead.
    """
    try:
        config = load_config(root)
    except Exception:
        return  # No config — not a deployment repo, nothing to check

    from mallcop.actors.runtime import check_escalation_health
    errors = check_escalation_health(config)
    if errors:
        click.echo("WARNING: Escalation paths are broken — findings cannot be delivered:", err=True)
        for e in errors:
            click.echo(f"  {e}", err=True)
        click.echo("Fix your mallcop.yaml or set TEAMS_WEBHOOK_URL.", err=True)



def _stub(name: str) -> None:
    """Output JSON stub response for an unimplemented command."""
    click.echo(json.dumps({"command": name, "status": "not_implemented"}))


def _parse_since(since: str) -> datetime:
    """Parse a time window string like '24h', '7d', '30m' into a datetime cutoff."""
    match = re.match(r"^(\d+)([hdm])$", since)
    if not match:
        raise click.BadParameter(f"Invalid time window: {since}. Use e.g. 24h, 7d, 30m")
    value, unit = int(match.group(1)), match.group(2)
    if unit == "h":
        delta = timedelta(hours=value)
    elif unit == "d":
        delta = timedelta(days=value)
    elif unit == "m":
        delta = timedelta(minutes=value)
    else:
        raise click.BadParameter(f"Unknown unit: {unit}")
    return datetime.now(timezone.utc) - delta


class _InstrumentedGroup(click.Group):
    """Click group that auto-instruments commands with telemetry logging."""

    def invoke(self, ctx: click.Context) -> Any:
        from mallcop.telemetry import is_enabled, _log_invocation
        import time as _time

        if not is_enabled():
            return super().invoke(ctx)

        sub = ctx.invoked_subcommand or ctx.info_name
        params = ctx.params or {}
        flags = [k for k, v in params.items() if v is not None and v is not False]

        t0 = _time.monotonic()
        exit_code = 0
        try:
            return super().invoke(ctx)
        except SystemExit as e:
            exit_code = e.code if isinstance(e.code, int) else 1
            raise
        except Exception:
            exit_code = 1
            raise
        finally:
            wall_ms = (_time.monotonic() - t0) * 1000
            _log_invocation(sub, flags, exit_code, wall_ms)


@click.group(cls=_InstrumentedGroup)
@click.version_option(package_name="mallcop")
def cli() -> None:
    """Mallcop: Security monitoring for small cloud operators."""
    import warnings as _warnings
    _warnings.warn(
        "Python mallcop is in maintenance mode. The active implementation is at "
        "github.com/mallcop-app/mallcop (Go). See README for migration notes.",
        DeprecationWarning,
        stacklevel=2,
    )


# Register sub-groups imported from other modules
cli.add_command(patrol)

# --- Core pipeline ---


def _detect_github_remote() -> str | None:
    """Detect a GitHub remote URL from the current git repo. Returns owner/repo or None."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        url = result.stdout.strip()
        # Parse GitHub remote: git@github.com:owner/repo.git or https://github.com/owner/repo.git
        import re
        m = re.match(r"(?:git@github\.com:|https://github\.com/)(.+?)(?:\.git)?$", url)
        return m.group(1) if m else None
    except Exception:
        return None


def _is_git_repo() -> bool:
    """Check if cwd is inside a git working tree."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _setup_github_app_installation(
    access_token: str, github_repo: str, interactive: bool,
) -> int | None:
    """Prompt user to install the mallcop GitHub App on their org.

    After installation, uses the user's token to look up the installation_id
    via the GitHub API. Returns the installation_id or None if skipped/failed.
    """
    import webbrowser

    import requests

    org = github_repo.split("/")[0] if "/" in github_repo else ""
    if not org:
        return None

    if not interactive:
        return None

    click.echo(
        "\nmallcop can monitor your org's audit log, secret scanning alerts,\n"
        "and Dependabot findings — but it needs the GitHub App installed.",
        err=True,
    )
    choice = click.prompt(
        "  [1] Install mallcop GitHub App now (opens browser)\n"
        "  [2] Skip (you can install later)\nChoice",
        default="1", err=True,
    )
    if choice.strip() != "1":
        return None

    install_url = "https://github.com/apps/mallcop-app/installations/new"
    click.echo(f"\nOpening: {install_url}", err=True)
    webbrowser.open(install_url)
    click.echo(
        f"Install the app on the '{org}' org, then come back here.",
        err=True,
    )
    click.prompt("Press Enter when done", default="", err=True, show_default=False)

    # Look up the installation_id using the user's OAuth token
    click.echo("Looking up installation...", err=True)
    try:
        resp = requests.get(
            "https://api.github.com/user/installations",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )
        if resp.status_code != 200:
            click.echo(f"Could not list installations (HTTP {resp.status_code}).", err=True)
            return None

        installations = resp.json().get("installations", [])
        for inst in installations:
            account = inst.get("account", {})
            if account.get("login", "").lower() == org.lower():
                installation_id = inst["id"]
                click.echo(
                    f"Found installation {installation_id} for {org}.",
                    err=True,
                )
                return installation_id

        click.echo(
            f"No installation found for '{org}'. "
            "You can install later and add installation_id to mallcop.yaml.",
            err=True,
        )
        return None
    except Exception as e:
        click.echo(f"Failed to look up installation: {e}", err=True)
        return None


def _setup_github(config_data: dict[str, Any]) -> dict[str, Any] | None:
    """Detect git/GitHub state and walk user through GitHub auth via device flow.

    Mutates config_data (adds 'github' section).
    Returns github result dict for CLI output, or None if skipped.
    """
    import subprocess
    import sys
    from pathlib import Path

    interactive = sys.stdin.isatty()
    cwd = Path.cwd()

    # Step 1: Detect git state
    if not _is_git_repo():
        if not interactive:
            return None
        click.echo("\nNo git repository detected.", err=True)
        choice = click.prompt(
            "  [1] Run git init here\n  [2] Skip GitHub integration\nChoice",
            default="2", err=True,
        )
        if choice.strip() == "1":
            result = subprocess.run(
                ["git", "init"], capture_output=True, text=True, cwd=str(cwd),
            )
            if result.returncode != 0:
                click.echo(f"git init failed: {result.stderr}", err=True)
                return None
            click.echo("Initialized git repository.", err=True)
        else:
            return None

    # Step 2: Detect GitHub remote
    github_repo = _detect_github_remote()
    if github_repo is None:
        if not interactive:
            return None
        click.echo("\nNo GitHub remote found.", err=True)
        click.echo("Add a GitHub remote to enable finding sync and dashboard.", err=True)
        choice = click.prompt(
            "  [1] I'll add a remote later (skip for now)\n  [2] Enter a GitHub repo (owner/repo)\nChoice",
            default="1", err=True,
        )
        if choice.strip() == "2":
            github_repo = click.prompt("GitHub repo (owner/repo)", err=True).strip()
            if "/" not in github_repo:
                click.echo("Invalid format. Expected owner/repo.", err=True)
                return None
            # Add the remote
            remote_url = f"https://github.com/{github_repo}.git"
            subprocess.run(
                ["git", "remote", "add", "origin", remote_url],
                capture_output=True, text=True, cwd=str(cwd),
            )
            click.echo(f"Added remote: {remote_url}", err=True)
        else:
            return None

    # Step 3: GitHub OAuth device flow
    click.echo(f"\nGitHub repo: {github_repo}", err=True)
    click.echo("Authorizing mallcop to push findings to your repo...", err=True)

    from mallcop.github_auth import start_device_flow, poll_for_token, save_credentials

    # Use the mallcop OAuth App client ID
    client_id = config_data.get("github", {}).get("client_id", "")
    if not client_id:
        # Default client ID for the mallcop GitHub App
        client_id = "Iv23li2NjQafyaxgyTUF"

    try:
        pending = start_device_flow(client_id)
    except Exception as e:
        click.echo(f"Failed to start GitHub auth: {e}", err=True)
        return None

    click.echo(f"\n  Open: {pending.verification_uri}", err=True)
    click.echo(f"  Enter code: {pending.user_code}\n", err=True)
    click.echo("Waiting for authorization...", err=True)

    try:
        tokens = poll_for_token(client_id, pending.device_code, pending.interval, timeout=300)
    except Exception as e:
        click.echo(f"GitHub auth failed: {e}", err=True)
        return None

    # Save credentials
    credentials_path = cwd / ".mallcop" / ".github-credentials"
    save_credentials(credentials_path, tokens)
    click.echo("GitHub authorized.", err=True)

    # Configure git to use the token for push
    subprocess.run(
        ["git", "config", f"credential.https://github.com.helper",
         f"!f() {{ echo username=x-access-token; echo password={tokens.access_token}; }}; f"],
        capture_output=True, text=True, cwd=str(cwd),
    )

    # Step 4: GitHub App installation for org audit log access
    # The device flow token gives push access but not org admin permissions.
    # Installing the GitHub App grants audit log, secret scanning, Dependabot etc.
    installation_id = _setup_github_app_installation(tokens.access_token, github_repo, interactive)

    # Write github section to config
    github_config: dict[str, Any] = {
        "repo": github_repo,
        "credentials_path": str(credentials_path),
        "client_id": client_id,
    }

    # Write connector config with installation_id for the token exchange flow
    org = github_repo.split("/")[0] if "/" in github_repo else ""
    if org:
        connectors = config_data.setdefault("connectors", {})
        gh_connector = connectors.setdefault("github", {})
        gh_connector["org"] = org
        if installation_id:
            gh_connector["installation_id"] = installation_id

    config_data["github"] = github_config

    result: dict[str, Any] = {
        "repo": github_repo,
        "status": "authorized",
    }
    if installation_id:
        result["installation_id"] = installation_id
    return result


_GHA_WORKFLOW_TEMPLATE = """\
name: mallcop
on:
  schedule:
    - cron: '*/15 * * * *'
  workflow_dispatch:
jobs:
  mallcop:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install mallcop
        run: pip install mallcop
      - name: Run mallcop watch
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
          GITHUB_ORG: ${{{{ secrets.GITHUB_ORG }}}}
          GITHUB_INSTALLATION_ID: ${{{{ secrets.GITHUB_INSTALLATION_ID }}}}
          MALLCOP_SERVICE_TOKEN: ${{{{ secrets.MALLCOP_SERVICE_TOKEN }}}}
          MALLCOP_TELEGRAM_BOT_TOKEN: ${{{{ secrets.MALLCOP_TELEGRAM_BOT_TOKEN }}}}
          MALLCOP_TELEGRAM_CHAT_ID: ${{{{ secrets.MALLCOP_TELEGRAM_CHAT_ID }}}}
        run: mallcop watch --dir ${{{{ github.workspace }}}}
"""


def _generate_gha_workflow(config_data: dict[str, Any], cwd: Path) -> dict[str, Any]:
    """Write .github/workflows/mallcop.yml and set GitHub Actions secrets.

    Only runs when config_data["github"]["repo"] is present.
    Returns a dict of delivery keys to merge into the output.
    """
    import subprocess as _subprocess

    github_section = config_data.get("github", {})
    if not isinstance(github_section, dict) or not github_section.get("repo"):
        return {}

    delivery: dict[str, Any] = {}

    # Write workflow file (skip if already exists)
    workflow_path = cwd / ".github" / "workflows" / "mallcop.yml"
    if not workflow_path.exists():
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(_GHA_WORKFLOW_TEMPLATE)
        delivery["workflow_written"] = True

    # Set GitHub Actions secrets via gh CLI
    delivery_section = config_data.get("delivery", {})
    campfire_id = delivery_section.get("campfire_id", "")
    telegram_bot_token = delivery_section.get("telegram_bot_token", "")
    telegram_chat_id = delivery_section.get("telegram_chat_id", "")

    secrets_to_set: list[tuple[str, str]] = []
    if campfire_id:
        secrets_to_set.append(("CAMPFIRE_ID", campfire_id))
    if telegram_bot_token:
        secrets_to_set.append(("MALLCOP_TELEGRAM_BOT_TOKEN", telegram_bot_token))
    if telegram_chat_id:
        secrets_to_set.append(("MALLCOP_TELEGRAM_CHAT_ID", telegram_chat_id))

    # GitHub connector secrets for installation token flow
    gh_connector = config_data.get("connectors", {}).get("github", {})
    if gh_connector.get("org"):
        secrets_to_set.append(("GITHUB_ORG", gh_connector["org"]))
    if gh_connector.get("installation_id"):
        secrets_to_set.append(("GITHUB_INSTALLATION_ID", str(gh_connector["installation_id"])))
    # Service token for mallcop-pro API calls (token exchange)
    pro_section = config_data.get("pro", {})
    service_token = pro_section.get("service_token", "")
    if service_token:
        secrets_to_set.append(("MALLCOP_SERVICE_TOKEN", service_token))

    gh_missing = False
    for secret_name, secret_value in secrets_to_set:
        try:
            _subprocess.run(
                ["gh", "secret", "set", secret_name, "--body", secret_value],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            gh_missing = True
            break  # gh not on PATH — skip remaining secrets
        except Exception:
            pass  # other errors are best-effort; don't fail init

    if gh_missing:
        delivery["secrets_skipped"] = "gh not found"

    return delivery


def _setup_pro(config_data: dict[str, Any]) -> dict[str, Any] | None:
    """Set up Pro managed inference after connector discovery.

    Mutates config_data in place (adds 'pro' section, removes 'llm').
    Returns a dict with pro account info for CLI output, or None on failure.
    """
    import os
    import subprocess

    from mallcop.pro import ProClient

    # Get email from git config
    email = ""
    try:
        result = subprocess.run(
            ["git", "config", "user.email"], capture_output=True, text=True
        )
        if result.returncode == 0:
            email = result.stdout.strip()
    except Exception:
        pass

    if not email:
        click.echo(
            json.dumps({"status": "error", "error": "No email found. Set git config user.email first."}),
            err=True,
        )
        return None

    # Validate email format before sending to external API (mallcop-ak1n.1.18).
    _EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    if not _EMAIL_RE.match(email):
        click.echo(
            json.dumps({"status": "error", "error": f"Invalid email address: {email!r}. Fix git config user.email first."}),
            err=True,
        )
        return None

    # Disclosure prompt: inform user their email is being sent to api.mallcop.dev (mallcop-ak1n.1.18).
    # Only prompt in interactive terminals — skip in CI/automated pipelines.
    import sys
    if sys.stdin.isatty():
        click.echo(f"Creating Pro account with email: {email}", err=True)
        confirm = click.prompt("Continue? [Y/n]", default="Y", err=True)
        if confirm.strip().lower() not in ("y", "yes", ""):
            click.echo(json.dumps({"status": "error", "error": "Cancelled by user."}), err=True)
            return None

    account_url = DEFAULT_API_URL
    client = ProClient(account_url)

    # Invite code from env or interactive prompt
    invite_code = os.environ.get("MALLCOP_INVITE_CODE", "")
    if not invite_code and sys.stdin.isatty():
        invite_code = click.prompt("Invite code (leave blank to skip)", default="", err=True).strip()

    # Create account (server uses anti-enumeration: duplicate emails return 200 silently)
    try:
        account_id, service_token = client.create_account(email, invite_code=invite_code or None)
    except (RuntimeError, OSError) as e:
        click.echo(
            json.dumps({"status": "error", "error": "Account creation failed"}),
            err=True,
        )
        return None

    # Get plan recommendation from service API (no local pricing data needed)
    connector_names = list(config_data.get("connectors", {}).keys())
    try:
        recommendation = client.recommend_plan(connector_names)
    except RuntimeError as e:
        click.echo(
            json.dumps({"status": "error", "error": str(e)}),
            err=True,
        )
        return None

    appetite_donuts = recommendation.get("estimated_donuts", 0)
    recommended_plan = recommendation.get("recommended_tier", "starter")
    headroom_pct = recommendation.get("headroom_pct", 0.0)
    # Format price from tiers list
    plan_price = next(
        (t["price"] for t in recommendation.get("tiers", []) if t["name"] == recommended_plan),
        "",
    )

    # Get checkout URL
    checkout_url = None
    try:
        checkout_url = client.subscribe(account_id, recommended_plan, service_token)
    except Exception:
        pass

    # Mutate config_data: add pro section, remove BYOK llm
    config_data["pro"] = {
        "account_id": account_id,
        "service_token": service_token,
        "account_url": account_url,
        "inference_url": "https://api.mallcop.app",
    }
    if "llm" in config_data:
        del config_data["llm"]

    # Build result for CLI output
    pro_result: dict[str, Any] = {
        "account_id": account_id,
        "email": email,
        "estimated_appetite_donuts": appetite_donuts,
        "recommended_plan": recommended_plan,
        "plan_price": plan_price,
        "plan_headroom_pct": headroom_pct,
    }
    if checkout_url:
        pro_result["checkout_url"] = checkout_url
        pro_result["next_step"] = (
            "Open the checkout URL to activate your subscription, then run: mallcop watch"
        )
    else:
        pro_result["next_step"] = "Run: mallcop watch"

    return pro_result


def _setup_pro_online(config_data: dict[str, Any]) -> dict[str, Any] | None:
    """Register for Pro Online hosted daemon tier.

    Validates prerequisites (pro service_token + Telegram + campfire),
    sets the Telegram webhook to mallcop.app, and registers with the
    mallcop-pro pro-online endpoint.

    Mutates config_data["delivery"] in place on success.
    Returns a result dict for CLI output, or None if prerequisites are missing.
    """
    import requests as _requests

    # --- prerequisite checks ---
    pro_section = config_data.get("pro", {})
    delivery_section = config_data.get("delivery", {})

    service_token = pro_section.get("service_token", "")
    telegram_bot_token = delivery_section.get("telegram_bot_token", "")
    telegram_chat_id = delivery_section.get("telegram_chat_id", "")
    campfire_id = delivery_section.get("campfire_id", "")

    missing: list[str] = []
    if not service_token:
        missing.append("pro.service_token")
    if not telegram_bot_token:
        missing.append("delivery.telegram_bot_token")
    if not telegram_chat_id:
        missing.append("delivery.telegram_chat_id")
    if not campfire_id:
        missing.append("delivery.campfire_id")

    if missing:
        click.echo(
            f"ERROR: --pro-online requires: {', '.join(missing)}",
            err=True,
        )
        return None

    # --- register Telegram webhook ---
    webhook_url = f"https://mallcop.app/webhooks/telegram/{service_token}"
    try:
        resp = _requests.post(
            f"https://api.telegram.org/bot{telegram_bot_token}/setWebhook",
            json={"url": webhook_url},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as exc:
        click.echo(f"ERROR: Telegram setWebhook failed: {exc}", err=True)
        return None

    # --- register with mallcop-pro ---
    account_url = pro_section.get("account_url", "https://mallcop.app")
    base_url = account_url.rsplit("/api/", 1)[0] if "/api/" in account_url else account_url
    try:
        resp = _requests.post(
            f"{base_url}/api/pro-online/register",
            json={
                "service_token": service_token,
                "telegram_bot_token": telegram_bot_token,
                "telegram_chat_id": telegram_chat_id,
                "campfire_id": campfire_id,
            },
            headers={"Authorization": f"Bearer {service_token}"},
            timeout=10,
        )
        if resp.status_code == 404:
            click.echo(
                "  pro-online registration endpoint not yet deployed — skipping server registration",
                err=True,
            )
        else:
            resp.raise_for_status()
    except _requests.HTTPError as exc:
        click.echo(f"ERROR: pro-online registration failed: {exc}", err=True)
        return None
    except _requests.RequestException as exc:
        click.echo(f"WARNING: pro-online registration request failed: {exc}", err=True)
        # Non-fatal for connection errors — webhook was already set

    # --- update config ---
    delivery_section["pro_online"] = True
    delivery_section["telegram_webhook_url"] = webhook_url

    return {
        "pro_online": True,
        "webhook_url": webhook_url,
    }


def _setup_telegram_interactive() -> tuple[str, str] | None:
    """Walk the user through Telegram bot setup interactively.

    Returns (bot_token, chat_id) on success, None if the user skips.
    """
    import sys
    import requests as _req

    click.echo("", err=True)
    click.echo("── Telegram notifications ─────────────────────────────", err=True)
    if not click.confirm("  Set up Telegram alerts?", default=False, err=True):
        return None

    click.echo("", err=True)
    click.echo("  1. Open Telegram and search for @BotFather", err=True)
    click.echo("  2. Send /newbot and follow the prompts", err=True)
    click.echo("  3. Copy the token BotFather gives you", err=True)
    click.echo("", err=True)

    while True:
        token = click.prompt("  Bot token", err=True).strip()
        try:
            resp = _req.get(
                f"https://api.telegram.org/bot{token}/getMe",
                timeout=10,
            )
            resp.raise_for_status()
            bot_name = resp.json()["result"]["username"]
            click.echo(f"  ✓ Connected: @{bot_name}", err=True)
            break
        except Exception:
            click.echo("  ✗ Could not reach Telegram — check the token and try again.", err=True)

    click.echo("", err=True)
    click.echo(f"  Now send any message to @{bot_name} in Telegram.", err=True)

    while True:
        click.prompt("  Press Enter when done", default="", show_default=False, err=True)
        try:
            resp = _req.get(
                f"https://api.telegram.org/bot{token}/getUpdates?limit=20",
                timeout=10,
            )
            resp.raise_for_status()
            results = resp.json().get("result", [])
            if results:
                last = results[-1]
                msg = last.get("message") or last.get("channel_post") or {}
                chat_id = str(msg.get("chat", {}).get("id", ""))
                if chat_id:
                    click.echo(f"  ✓ Chat ID: {chat_id}", err=True)
                    return token, chat_id
            click.echo("  No messages found yet — send a message to the bot and try again.", err=True)
        except Exception as exc:
            click.echo(f"  Could not read updates: {exc}", err=True)


@cli.command()
@click.option("--pro", is_flag=True, help="Set up Pro managed inference")
@click.option("--api-key", "api_key", default=None, help="mallcop Pro API key (mallcop-sk-* format); stored in mallcop.yaml")
@click.option("--pro-online", "pro_online", is_flag=True, default=False,
              help="Set up Pro Online hosted daemon (requires --pro + Telegram)")
@click.option("--telegram-bot-token", "telegram_bot_token", default=None, envvar="MALLCOP_TELEGRAM_BOT_TOKEN", hidden=True)
@click.option("--telegram-chat-id", "telegram_chat_id", default=None, envvar="MALLCOP_TELEGRAM_CHAT_ID", hidden=True)
def init(pro: bool, api_key: str | None, pro_online: bool, telegram_bot_token: str | None, telegram_chat_id: str | None) -> None:
    """Discover environment, write config, estimate costs."""
    cwd = Path.cwd()
    search_paths = get_search_paths(cwd)
    plugins = discover_plugins(search_paths)

    connector_results: list[dict[str, Any]] = []
    available_connectors: dict[str, dict[str, Any]] = {}
    total_sample_events = 0
    required_secrets: list[str] = []

    secrets = EnvSecretProvider()

    for name, plugin_info in plugins["connectors"].items():
        connector = instantiate_connector(name)
        if connector is None:
            continue

        # Authenticate before discovery so connectors can make API calls
        try:
            connector.authenticate(secrets)
        except Exception:
            pass  # discover() will report missing credentials

        result = connector.discover()

        connector_entry: dict[str, Any] = {
            "name": name,
            "available": result.available,
            "resources": result.resources,
            "missing_credentials": result.missing_credentials,
            "notes": result.notes,
        }
        connector_results.append(connector_entry)

        # Read manifest once per connector for auth config and required secrets
        manifest_path = plugin_info.path / "manifest.yaml"
        auth_required: list[str] = []
        if manifest_path.exists():
            with open(manifest_path) as f:
                manifest_data = yaml.safe_load(f)
            auth_required = manifest_data.get("auth", {}).get("required", [])

        # Collect required secrets for all connectors
        for key in auth_required:
            env_var = f"{name.upper()}_{key.upper()}"
            if env_var not in required_secrets:
                required_secrets.append(env_var)

        if result.available:
            connector_config: dict[str, Any] = {}
            for key in auth_required:
                env_var = f"{name.upper()}_{key.upper()}"
                connector_config[key] = f"${{{env_var}}}"

            for k, v in result.suggested_config.items():
                connector_config[k] = v

            available_connectors[name] = connector_config

            try:
                # Apply connector-specific config from discovery
                connector.configure(result.suggested_config)
                sample_result = connector.poll(checkpoint=None)
                total_sample_events += len(sample_result.events)
                connector_entry["sample_events"] = len(sample_result.events)
            except Exception:
                connector_entry["sample_events"] = 0

    budget = BudgetConfig()
    config_data: dict[str, Any] = {
        "secrets": {"backend": "env"},
        "connectors": available_connectors,
        "routing": {},
        "actor_chain": {},
        "budget": {
            "max_findings_for_actors": budget.max_findings_for_actors,
            "max_tokens_per_run": budget.max_tokens_per_run,
            "max_tokens_per_finding": budget.max_tokens_per_finding,
        },
    }

    # GitHub setup: detect repo, auth via device flow
    github_result: dict[str, Any] | None = None
    if pro or api_key:
        github_result = _setup_github(config_data)

    # --api-key: direct key-injection path — store the key in config without
    # going through the full account-creation flow.
    api_key_result: dict[str, Any] | None = None
    if api_key:
        import os as _os
        _base = _os.environ.get("MALLCOP_API_URL", "https://api.mallcop.app").rstrip("/")
        config_data["pro"] = {
            "service_token": api_key,
            "account_url": f"{_base}/api/account",
            "inference_url": _base,
        }
        if "llm" in config_data:
            del config_data["llm"]
        api_key_result = {"api_key": api_key, "inference_url": config_data["pro"]["inference_url"]}

    # Pro setup modifies config_data before writing.
    # Deep-copy so we can restore on failure (setup mutates in place).
    pro_result: dict[str, Any] | None = None
    if pro and not api_key:
        config_backup = copy.deepcopy(config_data)
        pro_result = _setup_pro(config_data)
        if pro_result is None:
            # Restore config_data from backup — _setup_pro may have
            # partially mutated it before failing.
            config_data.clear()
            config_data.update(config_backup)

    # Campfire and Telegram delivery setup
    import subprocess as _subprocess
    import os as _os
    import sys as _sys

    delivery_result: dict[str, Any] = {}
    delivery_config_data: dict[str, Any] = {}
    init_warnings: list[str] = []

    # Always create a campfire for this deployment.
    try:
        cf_cmd = ["cf", "create", "--description", f"mallcop-{cwd.name}"]
        github_section = config_data.get("github", {})
        github_repo = github_section.get("repo", "") if isinstance(github_section, dict) else ""
        if github_repo:
            cf_cmd += ["--transport", "github", "--github-repo", github_repo, "--github-token-env", "GITHUB_TOKEN"]
        cf_proc = _subprocess.run(
            cf_cmd,
            capture_output=True,
            text=True,
        )
        # cf create prints config path on the first line and the campfire
        # hex ID on the last line.  Only keep the ID.
        campfire_id = cf_proc.stdout.strip().splitlines()[-1].strip()
        if campfire_id:
            delivery_config_data["campfire_id"] = campfire_id
            delivery_result["campfire_id"] = campfire_id
        else:
            init_warnings.append("cf create returned no campfire ID")
    except Exception as exc:
        init_warnings.append(f"campfire setup failed: {exc}")

    # Telegram: use env vars if provided (CI/scripted), else interactive dialog on TTY.
    if not telegram_bot_token and _sys.stdin.isatty():
        tg = _setup_telegram_interactive()
        if tg:
            telegram_bot_token, telegram_chat_id = tg

    if telegram_bot_token:
        delivery_config_data["telegram_bot_token"] = telegram_bot_token
        delivery_result["telegram_configured"] = True
        if telegram_chat_id:
            delivery_config_data["telegram_chat_id"] = telegram_chat_id

    if delivery_config_data:
        config_data["delivery"] = delivery_config_data

    # Pro Online hosted daemon setup (after delivery config is populated)
    pro_online_result: dict[str, Any] | None = None
    if pro_online:
        if not pro and not api_key:
            click.echo("ERROR: --pro-online requires --pro", err=True)
            raise SystemExit(1)
        pro_online_result = _setup_pro_online(config_data)

    # Generate GitHub Actions workflow and set secrets (only when github config present)
    gha_delivery = _generate_gha_workflow(config_data, cwd)
    if gha_delivery:
        delivery_result.update(gha_delivery)

    config_path = cwd / "mallcop.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

    # Create .mallcop/ data directory so it exists before the first scan.
    # JsonlStore creates it on instantiation, but init runs before any scan.
    mallcop_dir = cwd / ".mallcop"
    mallcop_dir.mkdir(parents=True, exist_ok=True)

    cost_estimate = estimate_costs(
        num_connectors=len(available_connectors),
        sample_event_count=total_sample_events,
        budget=budget,
    )

    # Reference the example workflow template
    workflow_ref = (
        "See github-actions-example.yml in the mallcop package "
        "(mallcop/templates/github-actions-example.yml) for a GitHub Actions workflow template. "
        "Configure the required secrets in your repo settings."
    )

    output: dict[str, Any] = {
        "status": "ok",
        "config_path": str(config_path),
        "connectors": connector_results,
        "cost_estimate": cost_estimate,
        "workflow_example": workflow_ref,
        "required_secrets": required_secrets,
    }

    if github_result:
        output["github"] = github_result
    if pro_result:
        output["pro"] = pro_result
    if api_key_result:
        output["pro"] = api_key_result
    if pro_online_result:
        output["pro_online"] = pro_online_result
    if delivery_result:
        output["delivery"] = delivery_result
    if init_warnings:
        output["warnings"] = init_warnings

    click.echo(json.dumps(output))


@cli.command()
@click.option("--json", "output_json", is_flag=True, help="Output discovery data as JSON instead of human-readable summary.")
@click.option("--dir", "dir_path", default=None, help="Repo directory to inspect (default: cwd).")
def discover(output_json: bool, dir_path: str | None) -> None:
    """Inspect repo for connectors, write .mallcop/discovery.json."""
    from mallcop.discover import DiscoverError, discover as _discover, write_discovery_json

    repo_dir = Path(dir_path) if dir_path else Path.cwd()
    data = _discover(repo_dir)
    try:
        write_discovery_json(repo_dir, data)
    except DiscoverError as exc:
        click.echo(json.dumps({"status": "error", "error": str(exc)}))
        raise SystemExit(1)
    if output_json:
        click.echo(json.dumps(data))
    else:
        cov = data["coverage"]
        active = [c for c in data["connectors"] if c["status"] == "active"]
        detected = [c for c in data["connectors"] if c["status"] == "detected"]
        click.echo(f"Repo: {data['repo']}")
        click.echo(f"Coverage: {cov['percentage']}% ({cov['active_count']} active, {cov['detected_count']} detected, {cov['available_count']} available)")
        if active:
            click.echo("Active: " + ", ".join(c["type"] for c in active))
        if detected:
            click.echo("Detected (needs credentials): " + ", ".join(c["type"] for c in detected))
        click.echo(f"Written: {repo_dir / '.mallcop' / 'discovery.json'}")


@cli.command()
def scan() -> None:
    """Poll all connectors, store events."""
    from mallcop.cli_pipeline import _compute_exit_code
    try:
        result = _run_scan_pipeline(Path.cwd())
    except RuntimeError as e:
        click.echo(json.dumps({"status": "error", "error": str(e)}))
        raise SystemExit(1)
    click.echo(json.dumps(result))
    # Emit stderr JSON diagnostic when any connector failed (exit > 0)
    connector_summaries = result.get("connectors", {})
    exit_code = _compute_exit_code(connector_summaries)
    if exit_code > 0:
        failed_names = [n for n, s in connector_summaries.items() if s.get("status") == "error"]
        first_error = next(
            (connector_summaries[n].get("error", "unknown") for n in failed_names), "unknown"
        )
        stderr_payload = {
            "exit": exit_code,
            "connectors_failed": failed_names,
            "error": first_error,
            "suggestion": f"Check credentials for: {', '.join(failed_names)}" if failed_names else "",
        }
        click.echo(json.dumps(stderr_payload), err=True)


@cli.command()
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
def detect(dir_path: str | None) -> None:
    """Run detectors against new events."""
    root = Path(dir_path) if dir_path else Path.cwd()
    result = _run_detect_pipeline(root)
    result["command"] = "detect"
    click.echo(json.dumps(result))


@cli.command()
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
@click.option("--no-actors", is_flag=True, help="Skip actor invocation (log findings only).")
@click.option("--backend", default="anthropic", type=click.Choice(["anthropic", "claude-code"]),
              help="LLM backend: 'anthropic' (API) or 'claude-code' (CLI, uses subscription).")
def escalate(dir_path: str | None, human: bool, no_actors: bool, backend: str) -> None:
    """Invoke actor chain on open findings."""
    from mallcop.escalate import run_escalate

    root = Path(dir_path) if dir_path else Path.cwd()

    actor_runner = None
    if not no_actors:
        from mallcop.actors.runtime import EscalationPathError
        try:
            actor_runner = _build_actor_runner(root, backend=backend)
        except EscalationPathError as e:
            _emit_error(str(e), human)
            raise SystemExit(1)
        except Exception:
            pass

    result = run_escalate(root, actor_runner=actor_runner)
    if human:
        click.echo(f"Findings processed: {result['findings_processed']}")
        if result.get("circuit_breaker_triggered"):
            click.echo("Circuit breaker triggered -- actors bypassed.")
        if result.get("budget_exhausted"):
            click.echo("Budget exhausted -- some findings skipped.")
        click.echo(f"Donuts used: {result.get('tokens_used', 0)}")
    else:
        click.echo(json.dumps(result))


@cli.command()
@click.option("--dry-run", is_flag=True, help="Run scan and detect without invoking actors.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
@click.option("--backend", default="anthropic", type=click.Choice(["anthropic", "claude-code"]),
              help="LLM backend: 'anthropic' (API) or 'claude-code' (CLI, uses subscription).")
@click.option("--daemon", "daemon", is_flag=True, default=False,
              help="Run persistently: campfire chat dispatch + periodic scans.")
@click.option("--scan-interval", "scan_interval", default=300, type=int,
              help="Seconds between scans in daemon mode (default: 300).")
def watch(dry_run: bool, dir_path: str | None, human: bool, backend: str, daemon: bool, scan_interval: int) -> None:
    """Scan + detect + escalate (cron-friendly)."""
    from mallcop.escalate import run_escalate

    # --daemon mode: run CampfireDispatcher + periodic scan loop persistently.
    if daemon:
        import asyncio as _asyncio
        import logging as _logging
        from mallcop.campfire_dispatch import CampfireDispatcher
        from mallcop.daemon import _daemon_loop
        from mallcop.llm.managed import ManagedClient

        _logging.basicConfig(level=_logging.INFO, format="%(name)s: %(message)s")

        root = Path(dir_path) if dir_path else Path.cwd()

        campfire_id = os.environ.get('MALLCOP_CAMPFIRE_ID')
        service_token = os.environ.get('MALLCOP_PRO_SERVICE_TOKEN')
        inference_url = os.environ.get('MALLCOP_PRO_INFERENCE_URL', 'https://mallcop.app')
        bot_token = os.environ.get('MALLCOP_TELEGRAM_BOT_TOKEN')
        chat_id = os.environ.get('MALLCOP_TELEGRAM_CHAT_ID')
        inbound_mode = os.environ.get('MALLCOP_INBOUND_MODE') == 'campfire'

        if campfire_id and service_token:
            # Container mode — skip load_config entirely
            managed_client = ManagedClient(
                endpoint=inference_url,
                service_token=service_token,
                use_lanes=True,
            )
            cf_home = os.environ.get('CF_HOME')
            bridge = None
            if inbound_mode and bot_token and chat_id:
                from mallcop.telegram_bridge import TelegramCampfireBridge
                bridge = TelegramCampfireBridge(
                    bot_token=bot_token, chat_id=chat_id,
                    campfire_id=campfire_id, inbound_mode=True,
                )
            # Build a minimal config for container mode — no mallcop.yaml on disk.
            from mallcop.config import MallcopConfig, BudgetConfig, DeliveryConfig
            _container_config = MallcopConfig(
                secrets_backend="env",
                connectors={},
                routing={},
                actor_chain={},
                budget=BudgetConfig(),
                delivery=DeliveryConfig(campfire_id=campfire_id or ""),
            )
            try:
                interactive_runner = _build_interactive_runner(
                    root, managed_client, config=_container_config
                )
                click.echo(f"[daemon] InteractiveRuntime built: {type(interactive_runner).__name__}", err=True)
            except Exception as exc:
                click.echo(f"[daemon] InteractiveRuntime build FAILED: {exc}", err=True)
                interactive_runner = None  # non-fatal — chat returns platform error
            dispatcher = CampfireDispatcher(
                campfire_id=campfire_id,
                interactive_runner=interactive_runner,
                root=root,
                cf_home=cf_home,
                bridge=bridge,
            )
            try:
                _asyncio.run(_daemon_loop(dispatcher, root, float(scan_interval), idle_timeout_seconds=300.0, bridge=bridge))
            except KeyboardInterrupt:
                click.echo("daemon stopped")
            return

        try:
            config = load_config(root)
        except Exception as exc:
            click.echo(f"ERROR: could not load config: {exc}", err=True)
            raise SystemExit(1)

        campfire_id = getattr(config.delivery, "campfire_id", "") or ""
        if not campfire_id:
            click.echo(
                "daemon requires campfire_id in config (run: mallcop init)",
                err=True,
            )
            raise SystemExit(1)

        pro = config.pro
        if pro is None or not pro.service_token:
            click.echo(
                "daemon requires Pro config (run: mallcop init --pro)",
                err=True,
            )
            raise SystemExit(1)

        managed_client = ManagedClient(
            endpoint=pro.inference_url or "https://mallcop.app",
            service_token=pro.service_token,
            use_lanes=True,
        )

        try:
            interactive_runner = _build_interactive_runner(root, managed_client)
        except Exception:
            interactive_runner = None
        dispatcher = CampfireDispatcher(
            campfire_id=campfire_id,
            interactive_runner=interactive_runner,
            root=root,
        )

        try:
            _asyncio.run(_daemon_loop(dispatcher, root, float(scan_interval), idle_timeout_seconds=300.0))
        except KeyboardInterrupt:
            click.echo("daemon stopped")
        return

    root = Path(dir_path) if dir_path else Path.cwd()
    result: dict[str, Any] = {"command": "watch", "dry_run": dry_run}

    # Step 0: Build and validate actor runner once (reused in Step 3)
    watch_runner = None
    if not dry_run:
        from mallcop.actors.runtime import EscalationPathError
        try:
            watch_runner = _build_actor_runner(root, backend=backend)
        except EscalationPathError as e:
            result["status"] = "error"
            result["error"] = str(e)
            click.echo(json.dumps(result))
            raise SystemExit(1)
        except Exception:
            pass

    # Step 1: Scan (fail-fast)
    try:
        scan_result = _run_scan_pipeline(root)
        result["scan"] = scan_result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"scan failed: {e}"
        click.echo(json.dumps(result))
        raise SystemExit(1)

    # Step 2: Detect (fail-fast)
    try:
        detect_result = _run_detect_pipeline(root)
        # Extract baseline for top-level output (backward compat)
        if "baseline" in detect_result:
            result["baseline"] = detect_result.pop("baseline")
        result["detect"] = detect_result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"detect failed: {e}"
        click.echo(json.dumps(result))
        raise SystemExit(1)

    # Step 3: Escalate (skip only if dry-run; learning mode is handled per-finding in escalate)
    skip_escalate = dry_run
    escalate_reason = "dry_run" if dry_run else None

    if skip_escalate:
        result["escalate"] = {"skipped": True, "reason": escalate_reason}
    else:
        try:
            escalate_result = run_escalate(root, actor_runner=watch_runner)
            result["escalate"] = escalate_result
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"escalate failed: {e}"
            click.echo(json.dumps(result))
            raise SystemExit(1)

    # Step 4: Campfire bridge + dispatcher pass (one-shot, when campfire configured).
    # Runs bridge.run_once() first (Telegram → campfire), then dispatcher.run_once()
    # (campfire chat → LLM response). Silently skipped when campfire_id absent.
    try:
        _watch_dispatch_pass(root)
    except Exception:
        pass  # non-fatal: dispatch errors never fail a watch run

    result["status"] = "ok"

    if human:
        _watch_human_output(result, root)
    else:
        click.echo(json.dumps(result))


def _watch_dispatch_pass(root: Path) -> None:
    """Run one bridge+dispatcher pass when campfire_id is configured.

    Loads config, checks for campfire_id in delivery section. If absent,
    returns immediately (silent skip). If present, runs:
        1. TelegramCampfireBridge.run_once()  — Telegram → campfire
        2. CampfireDispatcher.run_once()      — campfire chat → LLM response

    Both are run via asyncio.run(). Errors in either call propagate to the
    caller, which wraps this in a try/except and treats failures as non-fatal.
    """
    import asyncio as _asyncio

    try:
        config = load_config(root)
    except Exception:
        return

    campfire_id = getattr(config.delivery, "campfire_id", "") or ""
    if not campfire_id:
        return

    delivery = config.delivery
    bot_token = getattr(delivery, "telegram_bot_token", "") or ""
    chat_id = getattr(delivery, "telegram_chat_id", "") or ""

    bridge = TelegramCampfireBridge(
        bot_token=bot_token,
        chat_id=chat_id,
        campfire_id=campfire_id,
    )

    # Build interactive_runner if pro is configured
    interactive_runner = None
    pro = getattr(config, "pro", None)
    if pro is not None and getattr(pro, "service_token", None):
        from mallcop.llm.managed import ManagedClient
        _mc = ManagedClient(
            endpoint=getattr(pro, "inference_url", None) or "https://mallcop.app",
            service_token=pro.service_token,
            use_lanes=True,
        )
        try:
            interactive_runner = _build_interactive_runner(root, _mc)
        except Exception:
            interactive_runner = None

    dispatcher = CampfireDispatcher(
        campfire_id=campfire_id,
        interactive_runner=interactive_runner,
        root=root,
        bridge=bridge,
    )

    async def _run() -> None:
        await bridge.run_once()
        await dispatcher.run_once()

    _asyncio.run(_run())


def _watch_human_output(result: dict[str, Any], root: Path) -> None:
    """Human-readable watch output including push status."""
    click.echo(f"Watch: {result['status']}")
    if "scan" in result:
        click.echo(f"  Scan: {result['scan'].get('total_events_ingested', 0)} events")
    if "detect" in result:
        click.echo(f"  Detect: {result['detect'].get('findings_count', 0)} findings")
    if "escalate" in result:
        esc = result["escalate"]
        if esc.get("skipped"):
            click.echo(f"  Escalate: skipped ({esc.get('reason', 'unknown')})")
        else:
            click.echo(f"  Escalate: {esc.get('findings_processed', 0)} processed")
    push = result.get("push", {})
    if push.get("status") == "ok":
        click.echo("  Pushed to GitHub.")
    elif push.get("status") == "error":
        click.echo(f"  Push failed: {push.get('error', 'unknown')}")


# Backward-compat aliases for internal callers
_run_scan_pipeline = run_scan_pipeline
_run_detect_pipeline = run_detect_pipeline
_run_retrospective_if_transitioning = run_retrospective_if_transitioning


# --- Investigation (interactive mode) ---


@cli.command()
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def review(dir_path: str | None, human: bool) -> None:
    """Orient: POST.md + all open findings + commands."""
    from mallcop.review import run_review

    root = Path(dir_path) if dir_path else Path.cwd()
    result = run_review(root)

    if human:
        print_review_human(result)
    else:
        click.echo(json.dumps(result))


@cli.command()
@click.argument("finding_id")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def investigate(finding_id: str, dir_path: str | None, human: bool) -> None:
    """Drill down: POST.md + deep context for one finding."""
    from mallcop.investigate import run_investigate

    root = Path(dir_path) if dir_path else Path.cwd()
    result = run_investigate(root, finding_id)

    if result.get("status") == "error":
        click.echo(json.dumps(result))
        raise SystemExit(1)

    if human:
        print_investigate_human(result)
    else:
        click.echo(json.dumps(result))


@cli.command()
@click.option("--status", default=None, help="Filter by status.")
@click.option("--severity", default=None, help="Filter by severity (comma-separated).")
@click.option("--since", default=None, help="Time window (e.g. 24h).")
@click.option("--human", is_flag=True, help="Human-readable output.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
def report(
    status: str | None,
    severity: str | None,
    since: str | None,
    human: bool,
    dir_path: str | None,
) -> None:
    """Show findings report."""
    from mallcop.store import JsonlStore

    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    findings = store.query_findings(status=status)

    # Filter by severity (comma-separated)
    if severity:
        severity_set = {s.strip() for s in severity.split(",")}
        findings = [f for f in findings if f.severity.value in severity_set]

    # Filter by since
    if since:
        cutoff = _parse_since(since)
        findings = [f for f in findings if f.timestamp >= cutoff]

    if human:
        if not findings:
            click.echo("No findings.")
        else:
            for f in findings:
                click.echo(
                    f"[{f.severity.value.upper()}] {f.id}: {f.title} "
                    f"({f.status.value}) @ {f.timestamp.isoformat()}"
                )
    else:
        click.echo(json.dumps({
            "command": "report",
            "status": "ok",
            "findings": [f.to_dict() for f in findings],
        }))


@cli.command()
@click.argument("finding_id")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def finding(finding_id: str, dir_path: str | None, human: bool) -> None:
    """Full finding detail + annotation trail."""
    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    findings = store.query_findings()
    match = [f for f in findings if f.id == finding_id]

    if not match:
        click.echo(json.dumps({
            "command": "finding",
            "status": "error",
            "error": f"Finding not found: {finding_id}",
        }))
        raise SystemExit(1)

    fnd = match[0]
    result = {
        "command": "finding",
        "status": "ok",
        "finding": fnd.to_dict(),
    }

    if human:
        print_finding_human(fnd)
    else:
        click.echo(json.dumps(result))


@cli.command()
@click.option("--finding", "finding_id", default=None, help="Filter by finding ID.")
@click.option("--actor", default=None, help="Filter by actor.")
@click.option("--source", default=None, help="Filter by source connector.")
@click.option("--hours", type=int, default=None, help="Time window in hours (default 24).")
@click.option("--type", "event_type", default=None, help="Filter by event type.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def events(
    finding_id: str | None,
    actor: str | None,
    source: str | None,
    hours: int | None,
    event_type: str | None,
    dir_path: str | None,
    human: bool,
) -> None:
    """Query events."""
    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    # Default to 24 hours
    effective_hours = hours if hours is not None else 24
    since = datetime.now(timezone.utc) - timedelta(hours=effective_hours)

    # If filtering by finding, resolve event_ids first
    event_id_filter: set[str] | None = None
    if finding_id is not None:
        findings = store.query_findings()
        match = [f for f in findings if f.id == finding_id]
        if not match:
            click.echo(json.dumps({
                "command": "events",
                "status": "error",
                "error": f"Finding not found: {finding_id}",
            }))
            raise SystemExit(1)
        event_id_filter = set(match[0].event_ids)
        # When filtering by finding, don't apply time window
        since = None  # type: ignore[assignment]

    # Query from store
    all_events = store.query_events(
        source=source,
        since=since,
        actor=actor,
    )

    # Apply event_type filter
    if event_type is not None:
        all_events = [e for e in all_events if e.event_type == event_type]

    # Apply finding event_ids filter
    if event_id_filter is not None:
        all_events = [e for e in all_events if e.id in event_id_filter]

    # Sort newest first
    all_events.sort(key=lambda e: e.timestamp, reverse=True)

    result = {
        "command": "events",
        "status": "ok",
        "events": [e.to_dict() for e in all_events],
    }

    if human:
        if not all_events:
            click.echo("No events found.")
        else:
            click.echo(f"Events ({len(all_events)}):")
            for e in all_events:
                click.echo(
                    f"  {e.id}: {e.actor} {e.action} {e.target} "
                    f"[{e.source}] @ {e.timestamp.isoformat()}"
                )
    else:
        click.echo(json.dumps(result))


@cli.command()
@click.option("--actor", default=None, help="Show baseline for actor.")
@click.option("--entity", default=None, help="Show baseline for entity.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
def baseline(actor: str | None, entity: str | None, dir_path: str | None) -> None:
    """Query baseline data."""
    from mallcop.store import JsonlStore

    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)
    bl = store.get_baseline()
    all_events = store.query_events(limit=100_000)

    if actor:
        # Show baseline profile for a specific actor
        freq_entries = {
            k: v for k, v in bl.frequency_tables.items() if actor in k
        }
        prefix = f"{actor}:"
        relationships = {
            k[len(prefix):]: v for k, v in bl.relationships.items()
            if k.startswith(prefix)
        }
        click.echo(json.dumps({
            "command": "baseline",
            "status": "ok",
            "actor": actor,
            "known": actor in bl.known_entities.get("actors", []),
            "frequency_entries": freq_entries,
            "relationships": relationships,
        }))
    elif entity:
        # Lookup specific entity across all types
        known = False
        known_actors = bl.known_entities.get("actors", [])
        known_sources = bl.known_entities.get("sources", [])
        if entity in known_actors or entity in known_sources:
            known = True
        click.echo(json.dumps({
            "command": "baseline",
            "status": "ok",
            "entity": entity,
            "known": known,
        }))
    else:
        # General baseline stats
        known_actors = bl.known_entities.get("actors", [])
        click.echo(json.dumps({
            "command": "baseline",
            "status": "ok",
            "event_count": len(all_events),
            "known_actor_count": len(known_actors),
            "frequency_table_entries": len(bl.frequency_tables),
            "known_sources": bl.known_entities.get("sources", []),
        }))


@cli.command()
@click.argument("finding_id")
@click.argument("text")
@click.option("--author", default="interactive", help="Author of the annotation.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def annotate(finding_id: str, text: str, author: str, dir_path: str | None, human: bool) -> None:
    """Add investigation note to a finding."""
    from mallcop.schemas import Annotation

    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    # Check finding exists
    findings = store.query_findings()
    target = None
    for f in findings:
        if f.id == finding_id:
            target = f
            break

    if target is None:
        click.echo(json.dumps({
            "command": "annotate",
            "status": "error",
            "error": f"Finding not found: {finding_id}",
        }))
        raise SystemExit(1)

    now = datetime.now(timezone.utc)
    annotation = Annotation(
        actor=author,
        timestamp=now,
        content=text,
        action="annotate",
        reason=None,
    )

    store.update_finding(finding_id, annotations=[annotation])

    if human:
        click.echo(f"[{annotation.actor}] {annotation.content}")
    else:
        click.echo(json.dumps({
            "command": "annotate",
            "status": "ok",
            "finding_id": finding_id,
            "annotation": annotation.to_dict(),
        }))


@cli.command()
@click.argument("finding_id")
@click.option("--author", default="interactive", help="Author of the ack.")
@click.option("--reason", default=None, help="Reason for acknowledging.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def ack(finding_id: str, author: str, reason: str | None, dir_path: str | None, human: bool) -> None:
    """Resolve finding, update baseline."""
    from mallcop.schemas import Annotation, FindingStatus

    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    # Look up the finding
    findings = store.query_findings()
    target = None
    for f in findings:
        if f.id == finding_id:
            target = f
            break

    if target is None:
        click.echo(json.dumps({
            "command": "ack",
            "status": "error",
            "error": f"Finding not found: {finding_id}",
        }))
        raise SystemExit(1)

    # Reject ack on boundary-violation findings: these are non-ackable.
    # Only fixing the underlying boundary (file ownership, cross-write access, sudo
    # membership) resolves them — human acknowledgement cannot suppress them.
    if target.detector == "boundary-violation":
        click.echo(json.dumps({
            "command": "ack",
            "status": "error",
            "error": (
                f"Finding {finding_id} is a boundary-violation and cannot be acked. "
                "Fix the underlying boundary violation to resolve it."
            ),
        }))
        raise SystemExit(1)

    # Reject double-ack
    if target.status == FindingStatus.ACKED:
        click.echo(json.dumps({
            "command": "ack",
            "status": "error",
            "error": f"Finding already acked: {finding_id}",
        }))
        raise SystemExit(1)

    # Build annotation
    now = datetime.now(timezone.utc)
    annotation = Annotation(
        actor=author,
        timestamp=now,
        content=f"Finding acknowledged by {author}" + (f": {reason}" if reason else ""),
        action="acked",
        reason=reason,
    )

    # Update finding: set status + add annotation
    store.update_finding(finding_id, status=FindingStatus.ACKED, annotations=[annotation])

    # Load triggering events and update baseline
    triggering_events = []
    if target.event_ids:
        triggering_events = store.query_events_by_ids(target.event_ids)

    if triggering_events:
        try:
            config = load_config(root)
            ack_window_days: int | None = config.baseline.window_days
        except ConfigError:
            from mallcop.config import BaselineConfig
            ack_window_days = BaselineConfig().window_days
        # Pass only the triggering events so only the acked actor becomes
        # "known". Passing all events would mark unrelated actors as known,
        # suppressing their findings — acking actor A must not silence actor B.
        store.update_baseline(triggering_events, window_days=ack_window_days)

    # Re-read the updated finding for output
    updated_findings = store.query_findings()
    updated = [f for f in updated_findings if f.id == finding_id][0]

    if human:
        click.echo(f"Acked: {updated.id}")
        click.echo(f"  Status: {updated.status.value}")
        click.echo(f"  Author: {author}")
        if reason:
            click.echo(f"  Reason: {reason}")
        click.echo(f"  Baseline updated with {len(triggering_events)} triggering events")
    else:
        click.echo(json.dumps({
            "command": "ack",
            "status": "ok",
            "finding": updated.to_dict(),
            "baseline_events_applied": len(triggering_events),
        }))


# --- Operational ---


@cli.command()
@click.option("--costs", is_flag=True, help="Show cost trends.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output.")
def status(costs: bool, dir_path: str | None, human: bool) -> None:
    """Event/finding counts and operational status."""
    from mallcop.status import run_status

    root = Path(dir_path) if dir_path else Path.cwd()
    result = run_status(root, costs=costs)

    # Escalation health check — always included in status output
    try:
        from mallcop.actors.runtime import check_escalation_health
        config_path = root / "mallcop.yaml"
        if config_path.exists():
            with open(config_path) as f:
                raw = yaml.safe_load(f) or {}

            # Load .env into os.environ so ${VAR} resolution works
            import os
            env_file = root / ".env"
            if env_file.exists():
                with open(env_file) as ef:
                    for line in ef:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            os.environ.setdefault(k.strip(), v.strip())

            class _HealthConfig:
                routing = raw.get("routing", {})
                actors = raw.get("actors", {})

            esc_errors = check_escalation_health(_HealthConfig())
            if esc_errors:
                result["escalation_health"] = {"status": "broken", "errors": esc_errors}
            else:
                result["escalation_health"] = {"status": "ok"}
        else:
            result["escalation_health"] = {"status": "unknown", "errors": ["No mallcop.yaml found"]}
    except Exception as exc:
        result["escalation_health"] = {"status": "unknown", "errors": [str(exc)]}

    if human:
        click.echo(f"Events: {result['total_events']}")
        click.echo(f"Findings: {result['total_findings']}")
        if result.get("events_by_source"):
            click.echo("Events by source:")
            for src, count in result["events_by_source"].items():
                click.echo(f"  {src}: {count}")
        if result.get("findings_by_status"):
            click.echo("Findings by status:")
            for st, count in result["findings_by_status"].items():
                click.echo(f"  {st}: {count}")
        if costs and "costs" in result:
            c = result["costs"]
            click.echo(f"Cost summary ({c['total_runs']} runs):")
            click.echo(f"  Avg donuts/run: {c['avg_donuts_per_run']}")
            click.echo(f"  Total donuts: {c['total_donuts']}")
            click.echo(f"  Estimated total: ${c['estimated_total_usd']}")
            click.echo(f"  Circuit breaker: triggered {c['circuit_breaker_triggered']} times")
        esc = result.get("escalation_health", {})
        esc_status = esc.get("status", "unknown")
        if esc_status == "broken":
            click.echo("ESCALATION: BROKEN")
            for e in esc.get("errors", []):
                click.echo(f"  {e}")
        elif esc_status == "ok":
            click.echo("Escalation: ok")
        else:
            click.echo(f"Escalation: {esc_status}")
            for e in esc.get("errors", []):
                click.echo(f"  {e}")
    else:
        click.echo(json.dumps(result))


# --- Chat ---


@cli.command()
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
def chat(dir_path: str | None) -> None:
    """Interactive chat REPL — ask questions about your security posture."""
    from mallcop.chat import run_chat_repl
    from mallcop.config import load_config
    from mallcop.llm.managed import ManagedClient

    root = Path(dir_path) if dir_path else Path.cwd()

    try:
        config = load_config(root)
    except Exception as exc:
        click.echo(f"ERROR: could not load config: {exc}", err=True)
        raise SystemExit(1)

    pro = config.pro
    if pro is None or not getattr(pro, "api_key", None):
        click.echo(
            "ERROR: mallcop Pro not configured. Run `mallcop init --pro` first.",
            err=True,
        )
        raise SystemExit(1)

    import uuid
    session_id = str(uuid.uuid4())

    try:
        managed_client = ManagedClient(
            endpoint=getattr(pro, "inference_url", None) or "https://mallcop.app",
            service_token=pro.service_token,
            use_lanes=True,
        )
        interactive_runner = _build_interactive_runner(root, managed_client)
    except Exception:
        interactive_runner = None
    run_chat_repl(interactive_runner=interactive_runner, root=root)


# --- Development ---


@cli.command()
@click.argument("plugin_type", type=click.Choice(["connector", "detector", "actor", "tool"]))
@click.argument("name")
def scaffold(plugin_type: str, name: str) -> None:
    """Generate plugin directory with stubs."""
    from mallcop.scaffold import scaffold_plugin, scaffold_tool

    base_path = Path.cwd()
    try:
        if plugin_type == "tool":
            tool_path = scaffold_tool(name, base_path)
            click.echo(json.dumps({
                "command": "scaffold",
                "status": "ok",
                "plugin_type": "tool",
                "name": name,
                "path": str(tool_path),
            }))
        else:
            plugin_dir = scaffold_plugin(plugin_type, name, base_path)
            click.echo(json.dumps({
                "command": "scaffold",
                "status": "ok",
                "plugin_type": plugin_type,
                "name": name,
                "path": str(plugin_dir),
            }))
    except (ValueError, FileExistsError) as e:
        click.echo(json.dumps({
            "command": "scaffold",
            "status": "error",
            "error": str(e),
        }))
        raise SystemExit(1)


@cli.command()
@click.argument("plugin_path", required=False)
@click.option("--all", "verify_all", is_flag=True, help="Verify all plugins.")
def verify(plugin_path: str | None, verify_all: bool) -> None:
    """Validate plugin against contracts."""
    from mallcop.plugins import discover_plugins
    from mallcop.verify import (
        verify_plugin as _verify,
        verify_tool_file as _verify_tool,
        verify_app_artifacts as _verify_app,
    )

    results = []

    if verify_all:
        base_path = Path.cwd()
        discovered = discover_plugins([base_path])
        type_map = {
            "connectors": "connector",
            "detectors": "detector",
            "actors": "actor",
        }
        for category, plugins in discovered.items():
            ptype = type_map.get(category)
            if ptype is None:
                continue  # e.g. skills — not verified via manifest.yaml contract
            for pinfo in plugins.values():
                results.append(_verify(pinfo.path, ptype))

        # Also scan plugins/tools/*.py for tool files
        for search_dir in [base_path / "plugins" / "tools", base_path]:
            tools_dir = search_dir if search_dir.name == "tools" else search_dir / "plugins" / "tools"
            if not tools_dir.exists():
                continue
            for py_file in sorted(tools_dir.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                results.append(_verify_tool(py_file))
            break  # Only scan once

        # Also scan apps/*/ for parser.yaml and detectors.yaml
        apps_dir = base_path / "apps"
        if apps_dir.exists():
            for app_subdir in sorted(apps_dir.iterdir()):
                if app_subdir.is_dir():
                    results.extend(_verify_app(app_subdir))
    elif plugin_path:
        p = Path(plugin_path)
        if p.suffix == ".py":
            # It's a tool file
            results.append(_verify_tool(p))
        elif _is_app_dir(p):
            # It's an app artifact directory (contains parser.yaml or detectors.yaml)
            results.extend(_verify_app(p))
        else:
            # Infer plugin type from parent directory
            ptype = _infer_plugin_type(p)
            results.append(_verify(p, ptype))
    else:
        click.echo(json.dumps({
            "command": "verify",
            "status": "error",
            "error": "Provide a plugin path or use --all",
        }))
        raise SystemExit(1)

    all_passed = all(r.passed for r in results)
    output = {
        "command": "verify",
        "status": "ok" if all_passed else "fail",
        "results": [
            {
                "plugin": r.plugin_name,
                "type": r.plugin_type,
                "passed": r.passed,
                "errors": r.errors,
                "warnings": r.warnings,
            }
            for r in results
        ],
    }
    click.echo(json.dumps(output))
    if not all_passed:
        raise SystemExit(1)


def _infer_plugin_type(path: Path) -> str:
    """Infer plugin type from parent directory name."""
    parent_name = path.parent.name
    mapping = {
        "connectors": "connector",
        "detectors": "detector",
        "actors": "actor",
    }
    if parent_name in mapping:
        return mapping[parent_name]
    # Fallback: check path components
    for part in path.parts:
        if part in mapping:
            return mapping[part]
    raise ValueError(f"Cannot infer plugin type from path: {path}")


def _is_app_dir(path: Path) -> bool:
    """Check if a path is an app artifact directory."""
    if not path.is_dir():
        return False
    return (path / "parser.yaml").exists() or (path / "detectors.yaml").exists()


@cli.command("discover-app")
@click.argument("app_name")
@click.option("--lines", default=100, help="Number of recent log lines to sample.")
@click.option(
    "--refresh", is_flag=True,
    help="Re-discover (same behavior, signals refresh intent).",
)
@click.option(
    "--dir", "dir_path", default=None,
    help="Deployment repo directory.", hidden=True,
)
def discover_app_cmd(
    app_name: str, lines: int, refresh: bool, dir_path: str | None,
) -> None:
    """Sample container logs for an app, output structured context."""
    from mallcop.discover_app import DiscoverAppError, discover_app_logic

    cwd = Path(dir_path) if dir_path else Path.cwd()

    try:
        result = discover_app_logic(app_name, cwd, lines=lines, refresh=refresh)
        click.echo(json.dumps(result))
    except (DiscoverAppError, ConfigError) as e:
        click.echo(json.dumps({"status": "error", "error": str(e)}))
        raise SystemExit(1)


@cli.command()
@click.argument("finding_id")
@click.argument("action", type=click.Choice(["agree", "override"], case_sensitive=False))
@click.option("--reason", default=None, help="Explanation for this feedback (free text).")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
def feedback(finding_id: str, action: str, reason: str | None, dir_path: str | None) -> None:
    """Record human feedback on an agent finding.

    FINDING_ID is the finding to give feedback on (e.g. fnd_001).
    ACTION is 'agree' (agent was right) or 'override' (agent was wrong).

    Example: mallcop feedback fnd_001 override --reason "Baron is US/Eastern"
    """
    from mallcop.feedback import FeedbackRecord, HumanAction, check_feedback_cadence
    from mallcop.sanitize import sanitize_field

    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    # Resolve the finding
    findings = store.query_findings()
    match = [f for f in findings if f.id == finding_id]
    if not match:
        click.echo(json.dumps({
            "command": "feedback",
            "status": "error",
            "error": f"Finding not found: {finding_id}",
        }))
        raise SystemExit(1)

    fnd = match[0]

    # Sanitize reason — free text is untrusted input
    sanitized_reason = sanitize_field(reason) if reason is not None else None

    # Build snapshot: capture events + baseline + annotations at time of override
    event_ids = fnd.event_ids
    fnd_events = [e.to_dict() for e in store.query_events_by_ids(event_ids)]

    baseline = store.get_baseline()
    # Capture actor-relevant baseline entries
    actor_keys = {k for k in baseline.frequency_tables if fnd.metadata.get("actor", "") in k}
    baseline_snapshot: dict = {
        "actors": baseline.known_entities.get("actors", []),
        "frequency_subset": {k: baseline.frequency_tables[k] for k in actor_keys},
    }

    # Original action: last annotation's action, or status
    annotations = fnd.annotations
    if annotations:
        original_action = annotations[-1].action
        original_reason = annotations[-1].reason
    else:
        original_action = fnd.status.value
        original_reason = None

    # Detector from finding
    detector = fnd.detector

    record = FeedbackRecord(
        finding_id=finding_id,
        human_action=HumanAction(action.lower()),
        reason=sanitized_reason,
        original_action=original_action,
        original_reason=original_reason,
        timestamp=datetime.now(timezone.utc),
        events=fnd_events,
        baseline_snapshot=baseline_snapshot,
        annotations=[a.to_dict() for a in annotations],
        detector=detector,
    )

    store.append_feedback(record)

    # Cadence check: warn if human is rubber-stamping at anomalous speed
    recent_feedback = store.query_feedback()
    cadence_warning = check_feedback_cadence(recent_feedback)
    if cadence_warning:
        click.echo(cadence_warning)

    click.echo(json.dumps({
        "command": "feedback",
        "status": "ok",
        "finding_id": finding_id,
        "human_action": action.lower(),
    }))


@cli.command()
@click.option("--auto", is_flag=True, help="Apply proposed patches automatically.")
@click.option("--dry-run", is_flag=True, help="Show what would change without applying.")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, default=False, help="Human-readable output.")
def heal(auto: bool, dry_run: bool, dir_path: str | None, human: bool) -> None:
    """Review and apply parser patches proposed by the heal actor.

    Without flags: shows all pending patch proposals from heal actor annotations.
    --dry-run: shows what patches would be applied.
    --auto: applies all proposed patches to parser.yaml files automatically.

    Example: mallcop heal --dry-run
    """
    import yaml as _yaml

    from mallcop.actors.heal import ParserPatch, analyze_drift

    root = Path(dir_path) if dir_path else Path.cwd()
    store = JsonlStore(root)

    # Find all log_format_drift findings with heal actor annotations
    findings = store.query_findings()
    drift_findings = [f for f in findings if f.detector == "log-format-drift"]

    patches: list[dict[str, Any]] = []
    for fnd in drift_findings:
        # Check for heal actor annotations with patch proposals
        heal_anns = [a for a in fnd.annotations if a.actor == "heal" and a.action == "proposed_patch"]
        if heal_anns:
            for ann in heal_anns:
                try:
                    patch_dict = json.loads(ann.content)
                    patches.append({
                        "finding_id": fnd.id,
                        "finding_title": fnd.title,
                        "patch": patch_dict,
                        "proposed_at": ann.timestamp.isoformat(),
                    })
                except (json.JSONDecodeError, ValueError):
                    continue
        else:
            # No heal annotation yet — run analyze_drift inline
            patch = analyze_drift(fnd)
            if patch is not None:
                patches.append({
                    "finding_id": fnd.id,
                    "finding_title": fnd.title,
                    "patch": patch.to_dict(),
                    "proposed_at": None,
                })

    if not patches:
        if human:
            click.echo("No parser patch proposals found.")
        else:
            click.echo(json.dumps({"command": "heal", "status": "ok", "patches": []}))
        return

    if dry_run or (not auto):
        # Show proposals without applying
        if human:
            click.echo(f"Found {len(patches)} patch proposal(s):\n")
            for entry in patches:
                patch = entry["patch"]
                click.echo(f"  Finding: {entry['finding_id']} — {entry['finding_title']}")
                click.echo(f"  Scenario: {patch.get('scenario', 'unknown')}")
                click.echo(f"  App: {patch.get('app_name', 'unknown')}")
                click.echo(f"  Confidence: {patch.get('confidence', 0.0):.0%}")
                click.echo(f"  Reason: {patch.get('reason', '')}")
                if patch.get("before"):
                    click.echo(f"  Before: {json.dumps(patch['before'], indent=4)}")
                click.echo(f"  After: {json.dumps(patch['after'], indent=4)}")
                click.echo("")
            if dry_run:
                click.echo("(Dry run — no changes applied. Use --auto to apply.)")
        else:
            click.echo(json.dumps({
                "command": "heal",
                "status": "ok",
                "dry_run": dry_run,
                "patches": patches,
            }))
        return

    # --auto: apply patches to parser.yaml files
    applied: list[dict[str, Any]] = []
    errors: list[str] = []

    for entry in patches:
        patch = entry["patch"]
        app_name = patch.get("app_name", "")
        after = patch.get("after", {})
        if not app_name or not after:
            continue

        # Look for parser.yaml in common locations
        parser_candidates = [
            root / "plugins" / app_name / "parser.yaml",
            root / app_name / "parser.yaml",
            root / "parsers" / f"{app_name}.yaml",
        ]

        parser_path: Path | None = None
        for candidate in parser_candidates:
            if candidate.exists():
                parser_path = candidate
                break

        if parser_path is None:
            errors.append(
                f"parser.yaml not found for app '{app_name}' "
                f"(searched {[str(c) for c in parser_candidates]})"
            )
            continue

        try:
            with open(parser_path) as f:
                parser_data = _yaml.safe_load(f) or {}

            templates: list[dict[str, Any]] = parser_data.get("templates", [])
            scenario = patch.get("scenario", "new_field")
            before = patch.get("before")

            if scenario == "new_field" or before is None:
                # Append new template
                templates.append(after)
            else:
                # Find matching template by pattern and replace
                old_pattern = (before or {}).get("pattern")
                replaced = False
                for i, t in enumerate(templates):
                    if old_pattern and t.get("pattern") == old_pattern:
                        templates[i] = after
                        replaced = True
                        break
                if not replaced:
                    templates.append(after)

            parser_data["templates"] = templates
            with open(parser_path, "w") as f:
                _yaml.dump(parser_data, f, default_flow_style=False)

            applied.append({
                "finding_id": entry["finding_id"],
                "app_name": app_name,
                "scenario": scenario,
                "parser_path": str(parser_path),
            })
        except Exception as e:
            errors.append(f"Failed to apply patch for '{app_name}': {e}")

    if human:
        if applied:
            click.echo(f"Applied {len(applied)} patch(es):")
            for a in applied:
                click.echo(f"  {a['app_name']} ({a['scenario']}) → {a['parser_path']}")
        if errors:
            click.echo(f"\n{len(errors)} error(s):")
            for e in errors:
                click.echo(f"  ERROR: {e}", err=True)
    else:
        click.echo(json.dumps({
            "command": "heal",
            "status": "ok" if not errors else "partial",
            "applied": applied,
            "errors": errors,
        }))


# --- Academy Exam ---


@cli.group()
def exam() -> None:
    """Academy Exam: validate mallcop's AI reasoning with canned scenarios."""


@exam.command("run")
@click.option("--tag", default=None, help="Filter scenarios by failure_mode tag (e.g. KA, AE, CS).")
@click.option("--scenario", "scenario_id", default=None, help="Run a single scenario by ID.")
@click.option("--model", default=None, help="LLM model to use (e.g. haiku, sonnet).")
@click.option("--human", is_flag=True, help="Human-readable output (default is JSON).")
@click.option("--backend", default=None,
              help="LLM backend: anthropic, claude-code, bedrock, openai-compat, managed.")
def exam_run(tag: str | None, scenario_id: str | None, model: str | None, human: bool, backend: str | None) -> None:
    """Run Academy Exam scenarios and output grades."""
    import os
    from pathlib import Path as _Path

    # Locate scenario directory — relative to this package
    scenarios_dir = _Path(__file__).resolve().parents[2] / "tests" / "shakedown" / "scenarios"
    if not scenarios_dir.exists():
        # Fallback for installed packages (no tests/ directory)
        _emit_error("Scenario directory not found. Run from mallcop source checkout.", human)
        raise SystemExit(1)

    # Set env vars so _build_llm_client picks them up
    if backend:
        os.environ["SHAKEDOWN_BACKEND"] = backend
    if model:
        os.environ["SHAKEDOWN_MODEL"] = model

    # Import after env setup
    try:
        from tests.shakedown.harness import ShakedownHarness
        from tests.shakedown.scenario import load_all_scenarios, load_scenarios_tagged
        from tests.shakedown.conftest import _build_llm_client
    except ImportError as e:
        _emit_error(f"Shakedown module not available: {e}. Run from mallcop source checkout.", human)
        raise SystemExit(1)

    try:
        llm = _build_llm_client(backend=backend, model=model)
    except SystemExit:
        _emit_error(
            "No LLM credentials found. Set ANTHROPIC_API_KEY, or use --backend claude-code.",
            human,
        )
        raise SystemExit(1)
    except Exception as e:
        _emit_error(f"Failed to build LLM client: {e}", human)
        raise SystemExit(1)

    harness = ShakedownHarness(llm=llm, scenario_dir=scenarios_dir)

    # Load scenarios
    if scenario_id:
        all_s = load_all_scenarios(scenarios_dir)
        scenarios = [s for s in all_s if s.id == scenario_id]
        if not scenarios:
            _emit_error(f"Scenario '{scenario_id}' not found.", human)
            raise SystemExit(1)
    elif tag:
        scenarios = load_scenarios_tagged(scenarios_dir, failure_mode=tag)
    else:
        scenarios = load_all_scenarios(scenarios_dir)

    if not scenarios:
        _emit_error("No scenarios matched the filter.", human)
        raise SystemExit(1)

    results = harness.run_scenarios(scenarios)

    grades_out: list[dict[str, Any]] = []
    for r in results:
        grades_out.append({
            "scenario_id": r.scenario_id,
            "chain_action": r.chain_action,
            "triage_action": r.triage_action,
            "total_tokens": r.total_tokens,
            "llm_calls": len(r.llm_calls),
        })

    if human:
        click.echo(f"Academy Exam — {len(results)} scenario(s) run\n")
        for g in grades_out:
            click.echo(
                f"  {g['scenario_id']:20s}  action={g['chain_action']:10s}"
                f"  triage={g['triage_action']:10s}  tokens={g['total_tokens']}"
            )
    else:
        click.echo(json.dumps({
            "command": "exam",
            "scenarios_run": len(results),
            "results": grades_out,
        }))


@exam.command("bakeoff")
@click.option("--pricing", "pricing_path", required=True, type=click.Path(exists=True),
              help="Path to pricing.yaml (model catalog).")
@click.option("--models", "model_filter", default=None,
              help="Comma-separated model aliases to test (default: all auto-routable).")
@click.option("--profile", default=None, help="AWS SSO profile name (e.g. 3dl).")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock.")
@click.option("--judge-backend", default=None,
              help="Backend for the judge LLM (default: same as SHAKEDOWN_BACKEND).")
@click.option("--output", "output_path", default=None, type=click.Path(),
              help="Write summary JSON to this path (default: stdout).")
@click.option("--human", is_flag=True, help="Human-readable progress output.")
def exam_bakeoff(
    pricing_path: str,
    model_filter: str | None,
    profile: str | None,
    region: str,
    judge_backend: str | None,
    output_path: str | None,
    human: bool,
) -> None:
    """Run Academy Exam against all Bedrock commodity models.

    Reads models from pricing.yaml, runs scenarios against each via Bedrock,
    grades with LLM-as-judge, and produces a diffable summary JSON with
    routing recommendations.

    Requires AWS SSO credentials: run 'aws sso login --profile <name>' first.
    Requires boto3: pip install mallcop[aws]
    """
    import os
    from pathlib import Path as _Path

    scenarios_dir = _Path(__file__).resolve().parents[2] / "tests" / "shakedown" / "scenarios"
    if not scenarios_dir.exists():
        _emit_error("Scenario directory not found. Run from mallcop source checkout.", human)
        raise SystemExit(1)

    try:
        from tests.shakedown.bakeoff import (
            build_summary,
            load_models_from_pricing,
            run_bakeoff,
        )
        from tests.shakedown.evaluator import JudgeEvaluator
        from tests.shakedown.runs import RunRecorder
        from tests.shakedown.scenario import load_all_scenarios
        from tests.shakedown.conftest import _build_llm_client
    except ImportError as e:
        _emit_error(f"Shakedown module not available: {e}. Run from mallcop source checkout.", human)
        raise SystemExit(1)

    # Load models from pricing.yaml
    models = load_models_from_pricing(_Path(pricing_path))
    if model_filter:
        keep = {m.strip() for m in model_filter.split(",")}
        models = [m for m in models if m.alias in keep]
        missing = keep - {m.alias for m in models}
        if missing:
            _emit_error(f"Models not found in pricing.yaml: {', '.join(sorted(missing))}", human)
            raise SystemExit(1)

    if not models:
        _emit_error("No models to test.", human)
        raise SystemExit(1)

    # Load scenarios
    scenarios = load_all_scenarios(scenarios_dir)
    if not scenarios:
        _emit_error("No scenarios found.", human)
        raise SystemExit(1)

    # Build judge LLM (always sonnet, separate from the model under test)
    backend = judge_backend or os.environ.get("SHAKEDOWN_BACKEND", "api")
    try:
        judge_llm = _build_llm_client(backend=backend, model="sonnet")
    except Exception as e:
        _emit_error(f"Failed to build judge LLM: {e}", human)
        raise SystemExit(1)

    judge = JudgeEvaluator(judge_llm=judge_llm, judge_model="sonnet")
    recorder = RunRecorder()

    if human:
        click.echo(f"Bakeoff: {len(models)} models x {len(scenarios)} scenarios")
        click.echo(f"Models: {', '.join(m.alias for m in models)}")
        click.echo(f"Judge: sonnet via {backend}")
        click.echo(f"Run ID: {recorder.run_id}")
        click.echo()

    def _progress(model_alias: str, scenario_id: str, grade: Any) -> None:
        if human:
            v = grade.verdict.value.upper()
            click.echo(f"  {model_alias:20s} {scenario_id:40s} {v}")

    # Run bakeoff
    model_results = run_bakeoff(
        models=models,
        scenarios=scenarios,
        judge=judge,
        region=region,
        profile=profile,
        recorder=recorder,
        on_scenario_done=_progress if human else None,
    )

    # Build summary
    summary = build_summary(model_results, scenarios_total=len(scenarios))
    summary_json = json.dumps(summary, indent=2, sort_keys=False)

    if output_path:
        _Path(output_path).write_text(summary_json + "\n")
        if human:
            click.echo(f"\nSummary written to {output_path}")
    else:
        click.echo(summary_json)

    # Print routing recommendation in human mode
    if human and "routing_recommendation" in summary:
        click.echo("\nRouting Recommendation:")
        for lane, sovs in summary["routing_recommendation"].items():
            for sov, model_alias in sovs.items():
                click.echo(f"  {lane:12s} {sov:10s} → {model_alias or 'NONE (no model meets threshold)'}")

        click.echo(f"\nPer-model JSONL: runs/{recorder.run_id}.jsonl")


@cli.command()
@click.option("--from-exam", "exam_file", default=None,
              help="Path to exam results JSON file (from mallcop exam run).")
@click.option("--refresh-patterns", is_flag=True,
              help="Refresh antipatterns from web (not yet implemented).")
@click.option("--human", is_flag=True, help="Human-readable output (default is JSON).")
def improve(exam_file: str | None, refresh_patterns: bool, human: bool) -> None:
    """Analyze exam results and propose detector/prompt improvements."""
    if refresh_patterns:
        msg = "refresh-patterns not yet implemented"
        if human:
            click.echo(msg)
        else:
            click.echo(json.dumps({"command": "improve", "status": "not_implemented", "message": msg}))
        return

    # Load grades
    if exam_file:
        import pathlib
        p = pathlib.Path(exam_file)
        if not p.exists():
            _emit_error(f"Exam file not found: {exam_file}", human)
            raise SystemExit(1)
        try:
            raw = json.loads(p.read_text())
            results_data = raw.get("results", [])
        except Exception as e:
            _emit_error(f"Failed to parse exam file: {e}", human)
            raise SystemExit(1)

        # Re-import Grade/FixTarget to reconstruct graded results
        try:
            from tests.shakedown.evaluator import FixTarget
        except ImportError:
            _emit_error("Shakedown evaluator not available. Run from mallcop source checkout.", human)
            raise SystemExit(1)

        # exam run output doesn't include Grade objects (no judge step) —
        # group by chain_action as a proxy for failures
        failures = [r for r in results_data if r.get("chain_action") == "unknown"]
        suggestions = _build_improve_suggestions(results_data, failures)
    else:
        suggestions = [
            {
                "message": "No exam results provided. Run 'mallcop exam run' first, "
                           "then pass the output file with --from-exam results.json",
            }
        ]

    if human:
        click.echo("Mallcop Improvement Suggestions\n")
        for s in suggestions:
            if "message" in s:
                click.echo(s["message"])
            else:
                click.echo(f"Fix target : {s.get('fix_target', 'unknown')}")
                click.echo(f"Scenario(s): {', '.join(s.get('scenario_ids', []))}")
                click.echo(f"Pattern    : {s.get('failure_pattern', '')}")
                click.echo(f"Direction  : {s.get('fix_direction', '')}")
                click.echo("")
    else:
        click.echo(json.dumps({
            "command": "improve",
            "status": "ok",
            "suggestions": suggestions,
        }))


def _build_improve_suggestions(
    results_data: list[dict[str, Any]],
    failures: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build improvement suggestions from exam result dicts."""
    if not results_data:
        return [{"message": "No results to analyze."}]

    # Group by failure pattern — chain_action == "unknown" means actor chain failed
    unknown_ids = [r["scenario_id"] for r in failures]

    suggestions: list[dict[str, Any]] = []

    if unknown_ids:
        suggestions.append({
            "fix_target": "actor_chain",
            "scenario_ids": unknown_ids,
            "failure_pattern": "Actor chain returned unknown action — likely no resolution produced",
            "fix_direction": (
                "Check triage/POST.md and investigate/POST.md for resolution instructions. "
                "Ensure the actor chain is configured correctly in mallcop.yaml."
            ),
        })

    # Summarise non-failures
    ok_count = len(results_data) - len(failures)
    if ok_count > 0 and not failures:
        suggestions.append({
            "message": f"All {ok_count} scenario(s) produced a chain action. "
                       "Re-run with a judge evaluator for quality grades: "
                       "set ANTHROPIC_API_KEY and run 'pytest -m shakedown'."
        })

    return suggestions if suggestions else [{"message": "No actionable suggestions found."}]


# --- OSINT Research ---


@cli.command()
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
@click.option("--human", is_flag=True, help="Human-readable output (default is JSON).")
def research(dir_path: str | None, human: bool) -> None:
    """Research OSINT advisories and generate detector rules (Pro only)."""
    from mallcop.research import Advisory, run_research

    root = Path(dir_path) if dir_path else Path.cwd()

    # Load config
    try:
        config = load_config(root)
    except Exception as e:
        _emit_error(str(e), human)
        raise SystemExit(1)

    # Pro-only gate: requires service_token
    if config.pro is None or not config.pro.service_token:
        _emit_error(
            "mallcop research requires a Pro subscription. "
            "Run 'mallcop init --pro' to set up your account. "
            "Requires pro.service_token in mallcop.yaml.",
            human,
        )
        raise SystemExit(1)

    # Manifest path and detectors dir (co-located with the deployment repo)
    manifest_path = root / ".mallcop" / "intel-manifest.jsonl"
    detectors_dir = root / "plugins" / "detectors"

    # Build LLM client (use pro managed inference if configured)
    from mallcop.llm import build_llm_client
    llm_client = build_llm_client(config.llm, backend="anthropic", pro_config=config.pro)
    if llm_client is None:
        _emit_error(
            "No LLM client available. Check your pro.service_token or llm.api_key config.",
            human,
        )
        raise SystemExit(1)

    # For now, advisories list is empty — the LLM agent feeds this in production.
    # Callers (patrol agents, cron jobs) populate this list by querying OSINT sources.
    # The CLI stub runs with an empty list, demonstrating the pipeline is wired up.
    advisories: list[Advisory] = []

    result = run_research(
        advisories=advisories,
        manifest_path=manifest_path,
        detectors_dir=detectors_dir,
        llm_client=llm_client,
        config=config.research,
        connector_names=list(config.connectors.keys()),
    )

    if human:
        click.echo(f"Research complete:")
        click.echo(f"  Advisories checked  : {result.advisories_checked}")
        click.echo(f"  New advisories      : {result.advisories_new}")
        click.echo(f"  Detectors generated : {result.detectors_generated}")
        click.echo(f"  Advisories skipped  : {result.detectors_skipped}")
    else:
        click.echo(json.dumps({
            "command": "research",
            "status": "ok",
            "advisories_checked": result.advisories_checked,
            "advisories_new": result.advisories_new,
            "detectors_generated": result.detectors_generated,
            "detectors_skipped": result.detectors_skipped,
        }))


# --- Email verification ---


@cli.command("verify-email")
@click.option("--dir", "dir_path", default=None, help="Deployment repo directory.", hidden=True)
def verify_email(dir_path: str | None) -> None:
    """Verify your account email for escalation alerts."""
    from mallcop.pro import ProClient

    root = Path(dir_path) if dir_path else Path.cwd()

    # Load config
    try:
        config = load_config(root)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        raise SystemExit(1)

    # Pro-only gate
    if config.pro is None or not config.pro.account_id or not config.pro.service_token:
        click.echo(
            "Email verification requires a Pro account. Run mallcop init --pro first.",
            err=True,
        )
        raise SystemExit(1)

    client = ProClient(config.pro.account_url)

    # Step 1: Request OTP
    try:
        client.verify_email_request(config.pro.account_id, config.pro.service_token)
    except (RuntimeError, OSError) as e:
        click.echo(f"Failed to request verification: {e}", err=True)
        raise SystemExit(1)

    click.echo("Check your inbox — enter the 6-digit code:")
    otp = click.prompt("Code", hide_input=False)

    # Step 2: Confirm OTP
    try:
        client.verify_email_confirm(config.pro.account_id, otp.strip(), config.pro.service_token)
    except (RuntimeError, OSError):
        click.echo(
            "Invalid or expired code. Run mallcop verify-email again.",
            err=True,
        )
        raise SystemExit(1)

    click.echo("Email verified. Escalation alerts are now active.")


# --- Skill signing ---


@cli.group()
def skill() -> None:
    """Skill signing and verification commands."""


@skill.command("sign")
@click.argument("skill_dir", metavar="DIR", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--key", "key_path", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to SSH private key for signing.")
def skill_sign(skill_dir: Path, key_path: Path) -> None:
    """Sign a skill directory.

    Produces SKILL.md.sig in the skill directory. Any subsequent change
    to any file in the directory will invalidate the signature.
    """
    from mallcop.trust import sign_skill

    try:
        sig_path = sign_skill(skill_dir, key_path)
        click.echo(json.dumps({"status": "ok", "sig": str(sig_path)}))
    except RuntimeError as e:
        click.echo(json.dumps({"status": "error", "error": str(e)}))
        raise SystemExit(1)
    except Exception as e:
        click.echo(json.dumps({"status": "error", "error": f"Signing failed: {e}"}))
        raise SystemExit(1)


@skill.command("verify")
@click.argument("skill_dir", metavar="DIR", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--pubkey", "pubkey_path", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to SSH public key file for verification.")
@click.option("--identity", default=None,
              help="Identity (email) to verify against. Defaults to the comment field in the pubkey.")
def skill_verify(skill_dir: Path, pubkey_path: Path, identity: str | None) -> None:
    """Verify a skill directory's signature.

    Exits 0 if the signature is valid, non-zero otherwise.
    """
    from mallcop.trust import verify_skill_signature

    pubkey_str = pubkey_path.read_text().strip()

    # Default identity: last field of pubkey (comment)
    if identity is None:
        parts = pubkey_str.split()
        if len(parts) >= 3:
            identity = parts[2]
        elif len(parts) == 2:
            identity = parts[1]
        else:
            click.echo(json.dumps({"status": "error", "error": "Cannot determine identity from pubkey. Use --identity."}))
            raise SystemExit(1)

    try:
        valid = verify_skill_signature(skill_dir, pubkey_str, identity)
    except RuntimeError as e:
        click.echo(json.dumps({"status": "error", "error": str(e)}))
        raise SystemExit(1)

    if valid:
        click.echo(json.dumps({"status": "ok", "verified": True}))
    else:
        click.echo(json.dumps({"status": "error", "verified": False, "error": "Signature verification failed"}))
        raise SystemExit(1)


@skill.command("lock")
@click.option(
    "--skills-dir",
    "skills_dir",
    default=None,
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory containing skill subdirectories. Defaults to ~/.mallcop/skills.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(path_type=Path),
    help="Output path for skills.lock. Defaults to skills-dir/skills.lock.",
)
def skill_lock(skills_dir: Path | None, output_path: Path | None) -> None:
    """(Re)generate skills.lock from installed skills.

    Scans the skills directory for all skill subdirectories, computes
    SHA-256 hashes of each skill's content, and writes skills.lock.
    """
    from mallcop.skills._schema import SkillManifest
    from mallcop.trust import generate_lockfile, write_lockfile

    if skills_dir is None:
        skills_dir = Path.home() / ".mallcop" / "skills"

    if not skills_dir.exists():
        click.echo(json.dumps({"status": "error", "error": f"Skills directory not found: {skills_dir}"}))
        raise SystemExit(1)

    if output_path is None:
        output_path = skills_dir / "skills.lock"

    skills: dict[str, SkillManifest] = {}
    for entry in sorted(skills_dir.iterdir()):
        if not entry.is_dir():
            continue
        manifest = SkillManifest.from_skill_dir(entry)
        if manifest is not None:
            skills[manifest.name] = manifest

    lockfile = generate_lockfile(skills)
    write_lockfile(lockfile, output_path)

    click.echo(json.dumps({
        "status": "ok",
        "lock_file": str(output_path),
        "skills_locked": list(skills.keys()),
    }))


# --- Trust web ---


@cli.group()
@click.option(
    "--trust-dir",
    "trust_dir",
    default=None,
    type=click.Path(path_type=Path),
    help="Path to trust directory (default: .mallcop/trust in cwd).",
)
@click.pass_context
def trust(ctx: click.Context, trust_dir: Path | None) -> None:
    """Manage the trust web: anchors, keyring, and endorsements."""
    if trust_dir is None:
        trust_dir = Path.cwd() / ".mallcop" / "trust"
    ctx.ensure_object(dict)
    ctx.obj["trust_dir"] = trust_dir


def _trust_append_key_line(path: Path, identity: str, pubkey_str: str) -> None:
    """Append 'identity keytype base64' to path, creating parent dirs if needed.

    No-ops if the identity is already present.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    parts = pubkey_str.split()
    keytype, b64 = parts[0], parts[1]
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip().startswith(identity + " "):
                return  # already present
    with path.open("a") as f:
        f.write(f"{identity} {keytype} {b64}\n")


@trust.command("add-anchor")
@click.argument("identity")
@click.argument("pubkey_file", metavar="PUBKEY_FILE", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def trust_add_anchor(ctx: click.Context, identity: str, pubkey_file: Path) -> None:
    """Add IDENTITY as a trust anchor.

    PUBKEY_FILE is the path to an SSH public key file.
    """
    trust_dir: Path = ctx.obj["trust_dir"]
    pubkey_str = pubkey_file.read_text().strip()
    _trust_append_key_line(trust_dir / "anchors", identity, pubkey_str)
    click.echo(json.dumps({"status": "ok", "identity": identity,
                           "file": str(trust_dir / "anchors")}))


@trust.command("add-key")
@click.argument("identity")
@click.argument("pubkey_file", metavar="PUBKEY_FILE", type=click.Path(exists=True, path_type=Path))
@click.pass_context
def trust_add_key(ctx: click.Context, identity: str, pubkey_file: Path) -> None:
    """Add IDENTITY's public key to the keyring.

    PUBKEY_FILE is the path to an SSH public key file.
    """
    trust_dir: Path = ctx.obj["trust_dir"]
    pubkey_str = pubkey_file.read_text().strip()
    _trust_append_key_line(trust_dir / "keyring", identity, pubkey_str)
    click.echo(json.dumps({"status": "ok", "identity": identity,
                           "file": str(trust_dir / "keyring")}))


@trust.command("endorse")
@click.argument("identity")
@click.option("--scope", required=True,
              help="Glob pattern for skill names (e.g. '*', 'aws-*').")
@click.option("--level", required=True, type=click.Choice(["full", "author"]),
              help="'full' can re-delegate; 'author' can only sign skills.")
@click.option("--expires", required=True, help="Expiry date YYYY-MM-DD.")
@click.option("--reason", default="", help="Reason for this endorsement.")
@click.option("--key", "key_path", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="SSH private key used to sign the endorsement.")
@click.option("--identity", "endorser_identity", default=None,
              help="Endorser identity (defaults to key comment in .pub file).")
@click.pass_context
def trust_endorse(
    ctx: click.Context,
    identity: str,
    scope: str,
    level: str,
    expires: str,
    reason: str,
    key_path: Path,
    endorser_identity: str | None,
) -> None:
    """Endorse IDENTITY for SCOPE at trust LEVEL, signed with KEY.

    Produces a signed .endorse + .endorse.sig pair in the endorsements dir.
    """
    import shutil as _shutil
    import subprocess as _sp
    import tempfile as _tmp
    from datetime import date as _date, datetime as _dt, timezone as _tz

    import yaml as _yaml

    trust_dir: Path = ctx.obj["trust_dir"]

    # Resolve endorser identity from public key comment if not supplied
    if endorser_identity is None:
        for candidate in [key_path.with_suffix(".pub"), Path(str(key_path) + ".pub")]:
            if candidate.exists():
                parts = candidate.read_text().strip().split()
                endorser_identity = parts[2] if len(parts) >= 3 else parts[-1]
                break
        if endorser_identity is None:
            click.echo(json.dumps({"status": "error", "error":
                "Cannot determine endorser identity. Supply --identity."}))
            raise SystemExit(1)

    # Parse expiry date
    try:
        d = _date.fromisoformat(expires)
        expires_aware = _dt(d.year, d.month, d.day, tzinfo=_tz.utc)
    except ValueError as e:
        click.echo(json.dumps({"status": "error", "error": f"Invalid date: {e}"}))
        raise SystemExit(1)

    now_iso = _dt.now(_tz.utc).isoformat()
    data = {
        "endorser": endorser_identity,
        "signed_at": now_iso,
        "endorsements": [
            {
                "expires": expires_aware.isoformat(),
                "identity": identity,
                "reason": reason,
                "scope": scope,
                "trust_level": level,
            }
        ],
    }
    content = _yaml.dump(data, sort_keys=True, default_flow_style=False)

    endorse_dir = trust_dir / "endorsements"
    endorse_dir.mkdir(parents=True, exist_ok=True)
    safe = endorser_identity.replace("@", "_").replace(".", "_")
    endorse_path = endorse_dir / f"{safe}.endorse"
    endorse_path.write_text(content)

    ssh_keygen = _shutil.which("ssh-keygen")
    if ssh_keygen is None:
        click.echo(json.dumps({"status": "error", "error": "ssh-keygen not found."}))
        raise SystemExit(1)

    with _tmp.NamedTemporaryFile(delete=False, suffix=".content") as tf:
        content_file = Path(tf.name)
        tf.write(content.encode())

    try:
        _sp.run(
            [ssh_keygen, "-Y", "sign", "-f", str(key_path),
             "-n", "mallcop-endorsement", str(content_file)],
            check=True, capture_output=True,
        )
        content_file.with_suffix(".content.sig").rename(
            endorse_path.with_suffix(".endorse.sig")
        )
    except _sp.CalledProcessError as e:
        click.echo(json.dumps({"status": "error",
                               "error": f"Signing failed: {e.stderr.decode()}"}))
        raise SystemExit(1)
    finally:
        content_file.unlink(missing_ok=True)

    click.echo(json.dumps({
        "status": "ok",
        "endorser": endorser_identity,
        "identity": identity,
        "scope": scope,
        "level": level,
        "file": str(endorse_path),
    }))


@trust.command("chain")
@click.argument("identity")
@click.option("--skill", "skill_name", default="*", show_default=True,
              help="Skill name to check the trust chain for.")
@click.pass_context
def trust_chain(ctx: click.Context, identity: str, skill_name: str) -> None:
    """Show the trust path from an anchor to IDENTITY for a given skill.

    Exits non-zero if no trust path exists.
    """
    from mallcop.trust import find_trust_path, load_trust_store

    trust_dir: Path = ctx.obj["trust_dir"]
    ts = load_trust_store(trust_dir)
    path = find_trust_path(ts, identity, skill_name)

    if path is None:
        click.echo(json.dumps({
            "status": "error",
            "error": f"No trust path to {identity!r} for skill {skill_name!r}",
        }))
        raise SystemExit(1)

    click.echo(json.dumps({"status": "ok", "path": path, "skill": skill_name}))


@trust.command("list")
@click.pass_context
def trust_list(ctx: click.Context) -> None:
    """Show the full trust web: anchors, keyring, and endorsements."""
    from mallcop.trust import load_trust_store

    trust_dir: Path = ctx.obj["trust_dir"]
    ts = load_trust_store(trust_dir)

    endorsement_data: dict[str, list[dict]] = {}
    for endorser, enlist in ts.endorsements.items():
        endorsement_data[endorser] = [
            {
                "identity": e.identity,
                "trust_level": e.trust_level,
                "scope": e.scope,
                "reason": e.reason,
                "expires": e.expires.isoformat(),
            }
            for e in enlist
        ]

    click.echo(json.dumps({
        "status": "ok",
        "anchors": list(ts.anchors.keys()),
        "keyring": list(ts.keyring.keys()),
        "endorsements": endorsement_data,
    }, indent=2))


# --- Academy Flywheel: contribute ---

_DEFAULT_CAPTURES_DIR = Path.home() / ".mallcop" / "captures"
_DEFAULT_SYNTHETIC_DIR = (
    Path(__file__).resolve().parents[2] / "tests" / "shakedown" / "scenarios" / "synthetic"
)


def _scan_captures(captures_dir: Path) -> list[Path]:
    """Return all cap-*.jsonl files that have no .evaluated marker."""
    if not captures_dir.exists():
        return []
    results = []
    for cap_file in sorted(captures_dir.rglob("cap-*.jsonl")):
        marker = cap_file.with_suffix(".evaluated")
        if not marker.exists():
            results.append(cap_file)
    return results


def _load_capture(cap_file: Path) -> dict | None:
    """Load the first JSON object from a capture JSONL file. Returns None on error."""
    try:
        for line in cap_file.read_text().splitlines():
            line = line.strip()
            if line:
                return json.loads(line)
    except Exception:
        pass
    return None


@cli.command()
@click.option("--dry-run", "mode", flag_value="dry-run", default=True,
              help="Print what would be contributed without writing files (default).")
@click.option("--local", "mode", flag_value="local",
              help="Write synthesized scenarios to the synthetic/ directory.")
@click.option("--submit", "mode", flag_value="submit",
              help="Create a PR to the OSS repo via gh CLI.")
@click.option("--captures-dir", default=None,
              help="Override captures directory (default: ~/.mallcop/captures).")
@click.option("--synthetic-dir", default=None,
              help="Override synthetic scenarios output directory.")
def contribute(
    mode: str,
    captures_dir: str | None,
    synthetic_dir: str | None,
) -> None:
    """Contribute anonymized production captures to the OSS scenario corpus.

    Scans ~/.mallcop/captures/ for unevaluated captures, runs the anonymizer
    and quality gate on each, then synthesizes passing captures into shakedown
    scenario YAML files.

    Modes:
      --dry-run (default)  Print a summary of what would be contributed.
      --local              Write YAML files to tests/shakedown/scenarios/synthetic/.
      --submit             Create a PR to the OSS repo via gh CLI.
    """
    import subprocess

    from mallcop.flywheel.anonymizer import anonymize_capture
    from mallcop.flywheel.quality_gate import QualityGate
    from mallcop.flywheel.synthesizer import Synthesizer

    cap_dir = Path(captures_dir) if captures_dir else _DEFAULT_CAPTURES_DIR
    syn_dir = Path(synthetic_dir) if synthetic_dir else _DEFAULT_SYNTHETIC_DIR

    cap_files = _scan_captures(cap_dir)

    if not cap_files:
        click.echo(json.dumps({
            "command": "contribute",
            "status": "ok",
            "captures_found": 0,
            "synthesized": 0,
            "rejected": 0,
            "message": "No unevaluated captures found.",
        }, indent=2))
        return

    gate = QualityGate()
    synthesizer = Synthesizer()

    results = []
    synthesized = []
    rejected = []

    for cap_file in cap_files:
        raw = _load_capture(cap_file)
        if raw is None:
            rejected.append({"file": str(cap_file), "reason": "parse error"})
            if mode != "dry-run":
                cap_file.with_suffix(".evaluated").touch()
            continue

        # Anonymize first, then evaluate
        anon = anonymize_capture(raw)

        gate_result = gate.evaluate(anon)
        if not gate_result.passed:
            rejected.append({
                "file": str(cap_file),
                "reason": gate_result.rejection_reason,
            })
            if mode != "dry-run":
                cap_file.with_suffix(".evaluated").touch()
            continue

        # Quality gate passed: synthesize
        scenario = synthesizer.synthesize(anon)
        synthesized.append({
            "file": str(cap_file),
            "scenario_id": scenario["id"],
            "scenario": scenario,
        })

        if mode == "local":
            syn_dir.mkdir(parents=True, exist_ok=True)
            out_file = syn_dir / f"{scenario['id']}.yaml"
            out_file.write_text(
                yaml.dump(scenario, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            cap_file.with_suffix(".evaluated").touch()
        elif mode == "submit":
            syn_dir.mkdir(parents=True, exist_ok=True)
            out_file = syn_dir / f"{scenario['id']}.yaml"
            out_file.write_text(
                yaml.dump(scenario, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            cap_file.with_suffix(".evaluated").touch()

    summary: dict[str, Any] = {
        "command": "contribute",
        "status": "ok",
        "mode": mode,
        "captures_found": len(cap_files),
        "synthesized": len(synthesized),
        "rejected": len(rejected),
    }

    if mode == "dry-run":
        summary["would_contribute"] = [s["scenario_id"] for s in synthesized]
        summary["rejected_captures"] = rejected
    else:
        summary["contributed"] = [s["scenario_id"] for s in synthesized]
        summary["rejected_captures"] = rejected

    if mode == "submit" and synthesized:
        # Create a PR via gh CLI
        branch = f"synthetic-scenarios-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        try:
            subprocess.run(
                ["gh", "pr", "create",
                 "--title", f"Add {len(synthesized)} synthetic scenario(s) from flywheel",
                 "--body", "Synthesized from anonymized production captures via `mallcop contribute --submit`.",
                 "--base", "main",
                 "--head", branch],
                check=True,
                capture_output=True,
            )
            summary["pr_created"] = True
        except Exception as exc:
            summary["pr_error"] = str(exc)

    click.echo(json.dumps(summary, indent=2))
