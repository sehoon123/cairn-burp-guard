#!/usr/bin/env python3
"""Offline validation of ACTIVE authorized-web templates AND the separate offline profile.

The verifier itself sends NO traffic: no network, worker, Burp, installs or upstream writes.
Python 3.12+. --cairn-root imports trusted source's actual prompting/contracts modules.
Fixture/AST checks are NOT full config/startup, model behavior or active web E2E tests.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib
from importlib import resources
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from urllib.parse import urlsplit

# Set before importing any CAIRN module: readonly checkouts must not gain .pyc files.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "bootstrap.md": ("origin", "goal", "hints"),
    "bootstrap_conclude.md": ("origin", "goal", "hints"),
    "reason.md": ("graph_yaml", "fact_ids", "open_intents", "max_intents"),
    "explore.md": ("graph_yaml", "intent_id", "intent_description"),
    "explore_conclude.md": ("graph_yaml", "intent_id", "intent_description"),
}
FENCES = re.compile(r"^```json\s*\n(.*?)\n```", re.MULTILINE | re.DOTALL)
TOKENS = re.compile(r"\{([a-z][a-z0-9_]*)\}")
STATUSES = ("observed", "not_observed", "blocked", "untested", "inconclusive")
PROFILES = {
    "native-pi-ko": "dispatch.native-pi.example.json",
    "native-pi-ko-offline": "dispatch.native-pi-offline.example.json",
}
BENIGN_CHECKS = {
    "bounded_public_link_discovery", "status_header_content_type_metadata",
    "benign_non_executing_text_marker_comparison",
}


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_nonfinite(_: str) -> None:
    raise VerificationError("nonfinite JSON number")


def parse_json(text: str) -> dict:
    value = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_nonfinite)
    require(isinstance(value, dict), "JSON root must be an object")
    return value


def nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def description(value: object, keys: set[str]) -> None:
    require(isinstance(value, dict) and set(value) == keys, "wrong description object keys")
    require(nonempty(value.get("description")), "description must be a nonempty string")
    if "from" in keys:
        ids = value["from"]
        require(isinstance(ids, list) and bool(ids), "from must be a nonempty fact-ID array")
        require(all(item in {"origin", "f001", "f002", "f003"} for item in ids),
                "sample from must use fixture fact IDs, never goal/evidence/path IDs")


def check_contract(name: str, payload: dict, *, open_intents: bool = False, max_intents: int = 5) -> str:
    """Strict documented wrapped subset, intentionally stricter than permissive upstream parsing."""
    require(type(payload.get("accepted")) is bool, "accepted must be boolean")
    if not payload["accepted"]:
        require(set(payload) == {"accepted", "reason"} and nonempty(payload["reason"]),
                "rejection requires only accepted:false and a nonempty reason")
        return "rejected"
    require(set(payload) == {"accepted", "data"} and isinstance(payload["data"], dict),
            "success requires only accepted:true and data object")
    data = payload["data"]
    if name == "bootstrap.md":
        require(set(data) == {"fact", "complete"}, "bootstrap execute requires fact AND complete")
        description(data["fact"], {"description"})
        description(data["complete"], {"description"})
        return "complete"
    if name == "bootstrap_conclude.md":
        require(set(data) == {"fact"}, "bootstrap conclude must have fact only, never complete")
        description(data["fact"], {"description"})
        return "fact"
    if name in ("explore.md", "explore_conclude.md"):
        require(set(data) == {"description"} and nonempty(data["description"]),
                "explore phases require data.description only")
        return "fact"
    require(name == "reason.md", "unknown phase")
    if set(data) == {"complete"}:
        description(data["complete"], {"from", "description"})
        return "complete"
    if set(data) == {"intents"}:
        intents = data["intents"]
        require(isinstance(intents, list) and 1 <= len(intents) <= max_intents,
                "intents must be nonempty and within the configured finite maximum")
        for intent in intents:
            description(intent, {"from", "description"})
        return "intents"
    require(not data and open_intents, "reason noop requires nonempty Open Intents")
    return "noop"


def check_prompt(name: str, text: str, profile: str = "native-pi-ko") -> list[dict]:
    require(profile in PROFILES, "unknown profile")
    require(0 < len(text.encode("utf-8")) <= 65536, f"{name}: prompt exceeds 64 KiB")
    require(set(TOKENS.findall(text)) == set(REQUIRED[name]), f"{name}: missing/unknown runtime tokens")
    markers = ["## Safety boundary", "## Availability budget", "## Report artifacts",
               "## Exact CAIRN output contract", "NO MCP", "Pi extension",
               "NO authentication automation/session recovery", "artifact_write_failed",
               "blocked", "untested", "KISA", "reports/"]
    if profile == "native-pi-ko-offline":
        markers += ["NO target traffic", "requests 0"]
    else:
        markers += ["active-web", "20 requests", "120 seconds", "per-worker concurrency 1",
                    "<=100", "auth_unavailable", "source attribution", "inherited", "TLS", "direct fallback"]
        require(re.search(r"(?:<=5|at most 5)", text) is not None, f"{name}: missing finite slot ceiling")
        require("This profile generates NO target traffic" not in text,
                f"{name}: active profile silently became offline-only")
        if name in ("bootstrap.md", "reason.md", "explore.md"):
            markers += ["## Proxy-bound request procedure", "--proxy", "--noproxy ''", "NO_PROXY",
                        "proxy_unavailable", "--insecure", "ledger"]
        if name in ("bootstrap.md", "explore.md"):
            require(not re.search(r"(?:Default hard budget: target|Target) requests 0", text),
                    f"{name}: active execution cannot default to zero requests")
    for marker in markers:
        require(marker in text, f"{profile}/{name}: missing safety/report marker {marker!r}")
    blocks = FENCES.findall(text)
    require(len(blocks) >= 2, f"{name}: expected success and rejection JSON examples")
    samples = [parse_json(block) for block in blocks]
    kinds = [check_contract(name, sample, open_intents=sample.get("data") == {},
                            max_intents=5 if profile == "native-pi-ko" else 1) for sample in samples]
    require("rejected" in kinds and any(kind != "rejected" for kind in kinds),
            f"{name}: examples must cover accepted and rejected paths")
    return samples


def bounded_int(value: object, low: int, high: int, label: str) -> None:
    require(type(value) is int and low <= value <= high, f"{label}: integer outside [{low}, {high}]")


def check_plan(plan: dict) -> None:
    """Validate the example's local plan shape/ceilings, NOT runtime authority or egress."""
    require(plan["example_only"] is True and plan["not_a_server_api_payload"] is True,
            "plan example must not impersonate API schema or actual permission")
    require(plan["profile"] == "active-web", "main plan must support active web checks")
    require(plan["operator_authorized"] is False and plan["read_only_routes_confirmed"] is False,
            "synthetic example must NOT authorize traffic")
    require(plan["authorization_window"] == {"starts_at": None, "ends_at": None},
            "synthetic example must not supply an executable authorization window")
    require(plan["authorization_reference"] == "EXAMPLE-NOT-AUTHORIZATION", "unsafe example authorization")
    require(re.fullmatch(r"[A-Za-z0-9_-]+", plan["run_id"]) is not None, "unsafe example run ID")
    limits = plan["limits"]
    for key, low, high in (("engagement_requests", 1, 100), ("max_intents", 1, 5),
                           ("per_intent_requests", 1, 20), ("per_intent_seconds", 21, 120),
                           ("per_worker_concurrency", 1, 1), ("workers", 1, 1),
                           ("min_interval_millis", 1000, 120000), ("connect_timeout_seconds", 1, 5),
                           ("request_timeout_seconds", 1, 10), ("report_reserve_seconds", 20, 20),
                           ("response_body_bytes", 1, 262144), ("input_entries", 1, 100),
                           ("input_bytes", 1, 8388608), ("retries", 0, 0), ("automatic_redirects", 0, 0)):
        bounded_int(limits[key], low, high, key)
    require(plan["proxy"] == {"source": "inherited_scheme_proxy_environment_only",
                              "missing_or_unreachable": "stop", "direct_fallback": False,
                              "tls_verification": True, "credentials": False},
            "plan must stop without existing proxy and require verified TLS, no credentials/fallback")
    scope = plan["scope"]
    require(isinstance(scope, list) and bool(scope), "empty scope")
    for origin in scope:
        require(origin["scheme"] in ("http", "https"), "unsupported scheme")
        host = origin["host"]
        require(isinstance(host, str) and re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.example\.test", host)
                is not None, "example scope must be exact synthetic host, never wildcard/real host")
        bounded_int(origin["port"], 1, 65535, "scope port")
        paths = origin["paths"]
        require(isinstance(paths, list) and bool(paths) and len(paths) == len(set(paths)), "invalid scope paths")
        require(all(isinstance(path, str) and path.startswith("/") and not path.startswith("//")
                    and not any(part in path for part in ("..", "?", "#", "%", "\\")) for path in paths),
                "example paths must be exact normalized paths, not query/traversal/glob")
    intents = plan["intents"]
    require(isinstance(intents, list) and 1 <= len(intents) <= limits["max_intents"], "too many/empty intents")
    slots, allocations, total = set(), set(), 0
    for intent in intents:
        slot = intent["slot"]
        require(isinstance(slot, str) and re.fullmatch(r"[A-Za-z0-9_-]+", slot) is not None
                and slot not in slots, "duplicate/unsafe slot")
        slots.add(slot)
        bounded_int(intent["origin_index"], 0, len(scope) - 1, "origin index")
        paths, methods, keys = intent["paths"], intent["methods"], intent["query_keys"]
        require(isinstance(paths, list) and bool(paths) and len(paths) == len(set(paths))
                and set(paths) <= set(scope[intent["origin_index"]]["paths"]), "intent outside approved scope")
        require(isinstance(methods, list) and bool(methods) and len(methods) == len(set(methods))
                and set(methods) <= {"GET", "HEAD"}, "only explicit read-only GET/HEAD methods")
        require(isinstance(keys, list) and len(keys) == len(set(keys))
                and all(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_]+", key) is not None for key in keys),
                "invalid query key list")
        require(isinstance(intent["checks"], list) and bool(intent["checks"])
                and set(intent["checks"]) <= BENIGN_CHECKS, "unsupported/destructive check")
        bounded_int(intent["max_requests"], 1, limits["per_intent_requests"], "slot requests")
        bounded_int(intent["wall_seconds"], 21, limits["per_intent_seconds"], "slot wall time")
        bounded_int(intent["concurrency"], 1, 1, "slot concurrency")
        total += intent["max_requests"]
        for path in paths:
            allocation = (intent["origin_index"], path)
            require(allocation not in allocations, "overlapping slot path allocations")
            allocations.add(allocation)
    require(total <= limits["engagement_requests"], "sum of slot allocations exceeds engagement cap")


def check_config(config: dict, profile: str) -> None:
    runtime, tasks = config["runtime"], config["tasks"]
    require(runtime["execution"] == "local" and runtime["worker_healthcheck"] == "disabled",
            "example must select Native local mode without a health probe")
    require(Path(runtime["prompt_group"]).is_absolute() and Path(runtime["prompt_group"]).name == profile,
            "example prompt_group must be absolute and select the matching profile")
    require(all(runtime[key] == 1 for key in ("max_workers", "max_project_workers", "max_running_projects")),
            "example must keep one worker/project for bounded accounting")
    require(config["local"]["completed_action"] == "keep", "reports must survive completion cleanup")
    require(len(config["workers"]) == 1 and config["workers"][0]["type"] == "pi"
            and config["workers"][0]["max_running"] == 1 and config["workers"][0]["env"] == {}
            and config["common_env"] == {}, "do not configure integration/proxy/credential injection")
    require(tasks["reason"]["max_intents"] == (5 if profile == "native-pi-ko" else 1), "wrong intent maximum")
    require(tasks["bootstrap"] == {"timeout": 120, "conclude_timeout": 30}
            and tasks["explore"] == {"timeout": 120, "conclude_timeout": 30}
            and tasks["reason"]["timeout"] == 60, "example task deadlines changed")


def verify_local(templates: Path) -> dict[str, dict[str, list[dict]]]:
    samples = {}
    for profile, filename in PROFILES.items():
        group = templates / profile
        require(group.is_absolute() and group.is_dir(), "external prompt directory must exist and be absolute")
        require({p.name for p in group.glob("*.md")} == set(REQUIRED), "expected exactly five prompt Markdown files per group")
        samples[profile] = {name: check_prompt(name, (group / name).read_text(encoding="utf-8"), profile)
                            for name in REQUIRED}
        check_config(parse_json((templates / "examples" / filename).read_text(encoding="utf-8")), profile)
    for filename in ("REPORT.ko.md", "CHECKLIST.ko.md"):
        text = (templates / "reports" / filename).read_text(encoding="utf-8")
        require(all(status in text for status in STATUSES), f"{filename}: incomplete status definitions")
        require(sum("가" <= ch <= "힣" for ch in text) > 100, f"{filename}: expected Korean report content")
        require(all(marker in text for marker in ("KISA", "미수행", "complete", "active-web", "offline-fixture",
                                                  "auth_unavailable", "ledger", "출처", "불확실")),
                f"{filename}: missing modes/coverage/source/uncertainty/completion requirements")
    example = templates / "examples"
    for filename in ("web-context.example.json", "review-context.example.json"):
        context = parse_json((example / filename).read_text(encoding="utf-8"))
        require(context["not_a_server_api_payload"] is True and context["example_only"] is True
                and all(context[k] for k in ("origin", "goal", "hints")), "expected labelled Origin/Goal/Hints")
    web = parse_json((example / "web-context.example.json").read_text(encoding="utf-8"))
    require("bootstrap_enabled=false" in web["human_project_setup"], "multi-intent setup must not misuse bootstrap complete")
    require("허가" in web["origin"] and "20요청" in json.dumps(web, ensure_ascii=False), "missing active authorization/budget hints")
    check_plan(parse_json((example / "engagement-plan.example.json").read_text(encoding="utf-8")))
    fixture = parse_json((example / "demo-evidence.json").read_text(encoding="utf-8"))
    require(fixture["fixtureOnly"] is True and fixture["notAnExportSchema"] is True,
            "fixture must not impersonate a real evidence export")
    require(all((urlsplit(entry["url"]).hostname or "").endswith(".example.test")
                for entry in fixture["entries"]), "fixtures must use synthetic .example.test hosts")
    print("PASS local: active authorized-web + SEPARATE offline profile, ten prompts, exact JSON, finite nonzero plan, Korean reports")
    return samples


def verify_fixture(group: Path) -> None:
    """Artificial resources package, not a stub masquerading as installed CAIRN."""
    package = "guard_prompt_fixture_only"
    with tempfile.TemporaryDirectory(prefix="guard-resource-fixture-") as temp:
        base = Path(temp)
        prompts = base / package / "prompts"
        prompts.mkdir(parents=True)
        (prompts.parent / "__init__.py").write_text("", encoding="utf-8")
        sys.path.insert(0, temp)
        try:
            importlib.invalidate_caches()
            loader = resources.files(package + ".prompts")
            external = loader.joinpath(str(group))
            require(Path(str(external)).resolve() == group, "fixture: absolute joinpath did not select external directory")
            for name in REQUIRED:
                require(external.joinpath(name).read_text(encoding="utf-8") == (group / name).read_text(encoding="utf-8"),
                        "fixture: external read mismatch")
            require(not loader.joinpath(group.name).is_dir(), "fixture: relative group unexpectedly exists")
            try:
                external.joinpath("missing-prompt.md").read_text(encoding="utf-8")
            except FileNotFoundError:
                pass
            else:
                raise VerificationError("fixture: missing resource was not rejected")
            print(f"PASS fixture-only [{group.name}]: {type(loader).__name__}.joinpath(absolute) reads external files; NOT upstream validation")
        finally:
            sys.path.remove(temp)
            for key in list(sys.modules):
                if key == package or key.startswith(package + "."):
                    del sys.modules[key]
            importlib.invalidate_caches()


def fingerprint(directory: Path) -> dict[str, str]:
    return {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob("*")) if path.is_file()}


def source_validator(path: Path):
    """Compile unchanged selected AST nodes. Real resources object; no module/dependency stubs."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    selected = {"DEFAULT_PROMPT_REQUIRED_TOKENS", "PROMPT_REQUIRED_TOKENS_BY_GROUP", "validate_prompt_resources"}
    nodes = [node for node in tree.body
             if (isinstance(node, ast.ImportFrom) and node.module == "__future__")
             or (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in selected)
             or (isinstance(node, ast.FunctionDef) and node.name in selected)]
    require(len(nodes) == 4, "upstream config source structure changed; review loader rather than substituting a fake")
    namespace = {"resources": resources}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    expected = {name: tuple("{" + token + "}" for token in tokens) for name, tokens in REQUIRED.items()}
    require(namespace["DEFAULT_PROMPT_REQUIRED_TOKENS"] == expected, "upstream token contract changed")
    return namespace["validate_prompt_resources"]


def verify_upstream(root: Path, templates: Path, samples: dict, require_full: bool, profile: str) -> None:
    src = root / "cairn" / "src"
    require((src / "cairn" / "dispatcher" / "config.py").is_file(), "--cairn-root must be CAIRN checkout root")
    group = (templates / profile).resolve()
    require(not group.is_relative_to(root), "prompt_group must be external to the CAIRN checkout")
    before = fingerprint(src)
    sys.path.insert(0, str(src))
    try:
        importlib.invalidate_caches()
        prompting = importlib.import_module("cairn.dispatcher.prompting")
        contracts = importlib.import_module("cairn.dispatcher.contracts")
        require(Path(prompting.__file__).resolve() == src / "cairn" / "dispatcher" / "prompting.py",
                "another installed CAIRN shadowed the requested checkout")
        require(Path(contracts.__file__).resolve() == src / "cairn" / "dispatcher" / "contracts.py",
                "contract module is not from the requested checkout")
        real_resources = resources.files("cairn.dispatcher.prompts")
        selected = real_resources.joinpath(str(group))
        require(Path(str(selected)).resolve() == group, "actual upstream resources cannot load absolute external groups")
        validate_resources = source_validator(src / "cairn" / "dispatcher" / "config.py")
        validate_resources(str(group))
        # Negative checks use external scratch copies, never edit the actual templates/upstream.
        with tempfile.TemporaryDirectory(prefix="guard-upstream-negative-") as temp:
            negative = Path(temp)
            for name in REQUIRED:
                (negative / name).write_text((group / name).read_text(encoding="utf-8"), encoding="utf-8")
            for name, tokens in REQUIRED.items():
                saved = (negative / name).read_text(encoding="utf-8")
                (negative / name).unlink()
                try:
                    validate_resources(str(negative))
                except ValueError:
                    pass
                else:
                    raise VerificationError(f"actual source validator accepted missing {name}")
                (negative / name).write_text(saved.replace("{" + tokens[0] + "}", "missing"), encoding="utf-8")
                try:
                    validate_resources(str(negative))
                except ValueError:
                    pass
                else:
                    raise VerificationError(f"actual source validator accepted missing token in {name}")
                (negative / name).write_text(saved, encoding="utf-8")
        for name, tokens in REQUIRED.items():
            text = prompting.load_prompt(str(group), name)
            require(text == (group / name).read_text(encoding="utf-8"), "actual upstream load_prompt text mismatch")
            rendered = prompting.render_prompt(text, {token: "synthetic-" + token for token in tokens})
            require(not TOKENS.search(rendered), f"{name}: upstream renderer left a runtime token")
            for sample in samples[name]:
                # Round trip through the real upstream output parser as well as its contracts.
                payload = contracts.parse_json_output(json.dumps(sample, ensure_ascii=False))
                maximum = 5 if profile == "native-pi-ko" else 1
                expected = check_contract(name, payload, open_intents=payload.get("data") == {}, max_intents=maximum)
                if name == "bootstrap.md":
                    kind, _ = contracts.validate_bootstrap_execute_payload(payload)
                elif name == "bootstrap_conclude.md":
                    kind, _ = contracts.validate_bootstrap_conclude_payload(payload)
                elif name == "reason.md":
                    kind, _ = contracts.validate_reason_payload(payload, open_intents_empty=payload.get("data") != {}, max_intents=maximum)
                else:
                    kind, _ = contracts.validate_explore_payload(payload)
                require(kind == expected, f"{name}: real upstream contract differs from the documented example")
        print(f"PASS actual-upstream [{profile}]: real {type(real_resources).__name__} resource loader, renderer, output parser and contracts")
        print("PASS actual-source-slice: unchanged config.validate_prompt_resources AST + real resources; missing-file/token negatives (NOT full config import)")
        try:
            config_module = importlib.import_module("cairn.dispatcher.config")
        except ModuleNotFoundError as exc:
            if require_full:
                raise VerificationError(f"full upstream config import unavailable: missing {exc.name}") from exc
            print(f"SKIP full-upstream-config: missing dependency {exc.name}; use --require-full-config in a prepared environment")
        else:
            require(Path(config_module.__file__).resolve() == src / "cairn" / "dispatcher" / "config.py",
                    "config module is not from the requested checkout")
            config_module.validate_prompt_resources(str(group))
            data = parse_json((templates / "examples" / PROFILES[profile]).read_text(encoding="utf-8"))
            with tempfile.TemporaryDirectory(prefix="guard-config-check-") as temp:
                data["runtime"]["prompt_group"] = str(group)
                data["local"]["workspace_root"] = str(Path(temp) / "runs")
                config_path = Path(temp) / "dispatch.json"
                config_path.write_text(json.dumps(data), encoding="utf-8")
                loaded = config_module.DispatchConfig.load(config_path)
                require(loaded.runtime.prompt_group == str(group), "full config lost external prompt_group")
            print("PASS full-upstream-config: actual DispatchConfig.load and validate_prompt_resources; no dispatcher/worker launched")
    finally:
        sys.path.remove(str(src))
        require(fingerprint(src) == before, "CAIRN source/resource tree changed during validation")
        print("PASS readonly: CAIRN source/resource fingerprints unchanged; bytecode writes disabled")
    print("NOT RUN: active HTTP checks, live Pi/model/dispatcher/Burp, report-file E2E, egress enforcement, or official KISA full verification")


class RegressionTests(unittest.TestCase):
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(VerificationError):
            parse_json('{"accepted":true,"accepted":false}')

    def test_trailing_json_and_nonfinite_rejected(self):
        for value in ('{"accepted":false} trailing', '{"x":NaN}', '[]'):
            with self.assertRaises((ValueError, VerificationError)):
                parse_json(value)

    def test_bootstrap_fact_only_rejected(self):
        with self.assertRaises(VerificationError):
            check_contract("bootstrap.md", {"accepted": True, "data": {"fact": {"description": "partial"}}})

    def test_conclude_completion_rejected(self):
        for name in ("bootstrap_conclude.md", "explore_conclude.md"):
            with self.assertRaises(VerificationError):
                check_contract(name, {"accepted": True, "data": {"complete": {"description": "not allowed"}}})

    def test_explore_wrong_nesting_and_custom_status_rejected(self):
        for data in ({"fact": {"description": "wrong"}}, {"description": "ok", "status": "vulnerable"}):
            with self.assertRaises(VerificationError):
                check_contract("explore.md", {"accepted": True, "data": data})

    def test_reason_noop_only_with_open_intents(self):
        payload = {"accepted": True, "data": {}}
        self.assertEqual(check_contract("reason.md", payload, open_intents=True), "noop")
        with self.assertRaises(VerificationError):
            check_contract("reason.md", payload, open_intents=False)

    def test_reason_mutual_exclusion_and_goal_reference(self):
        for data in ({"intents": [], "complete": {"from": ["f001"], "description": "wrong"}},
                     {"complete": {"from": ["goal"], "description": "wrong"}}):
            with self.assertRaises(VerificationError):
                check_contract("reason.md", {"accepted": True, "data": data})

    def test_missing_and_unknown_runtime_tokens_rejected(self):
        template = (self.templates / "native-pi-ko" / "bootstrap.md").read_text(encoding="utf-8")
        for changed in (template.replace("{origin}", "missing"), template + "\n{invented_token}\n"):
            with self.assertRaises(VerificationError):
                check_prompt("bootstrap.md", changed)

    def test_accepted_must_be_boolean(self):
        with self.assertRaises(VerificationError):
            check_contract("explore.md", {"accepted": "true", "data": {"description": "wrong"}})

    def plan(self):
        return parse_json((self.templates / "examples" / "engagement-plan.example.json").read_text(encoding="utf-8"))

    def test_active_profile_cannot_regress_to_offline(self):
        for name in REQUIRED:
            offline = (self.templates / "native-pi-ko-offline" / name).read_text(encoding="utf-8")
            check_prompt(name, offline, "native-pi-ko-offline")
            with self.subTest(name=name), self.assertRaises(VerificationError):
                check_prompt(name, offline, "native-pi-ko")

    def test_active_proxy_and_report_gates_required(self):
        for name in ("bootstrap.md", "reason.md", "explore.md"):
            text = (self.templates / "native-pi-ko" / name).read_text(encoding="utf-8")
            for marker in ("--noproxy ''", "proxy_unavailable", "auth_unavailable", "source attribution",
                           "artifact_write_failed", "20 requests", "120 seconds"):
                with self.subTest(name=name, marker=marker), self.assertRaises(VerificationError):
                    check_prompt(name, text.replace(marker, "removed"))

    def test_nonzero_and_hard_budget_bounds(self):
        for key, invalid in (("per_intent_requests", 0), ("per_intent_requests", 21),
                             ("per_intent_seconds", 121), ("max_intents", 6), ("engagement_requests", 101),
                             ("per_worker_concurrency", 2), ("workers", 2), ("retries", 1),
                             ("automatic_redirects", 1), ("min_interval_millis", 999),
                             ("request_timeout_seconds", 11), ("response_body_bytes", 262145),
                             ("per_intent_requests", True)):
            plan = self.plan()
            plan["limits"][key] = invalid
            with self.subTest(key=key, invalid=invalid), self.assertRaises(VerificationError):
                check_plan(plan)

    def test_slot_allocations_cannot_exceed_engagement_or_repeat(self):
        baseline = self.plan()
        changed = copy.deepcopy(baseline)
        changed["limits"]["engagement_requests"] = 59  # Three 20-request slots exceed this.
        duplicate = copy.deepcopy(baseline)
        duplicate["intents"][1]["slot"] = duplicate["intents"][0]["slot"]
        overlap = copy.deepcopy(baseline)
        overlap["intents"][1]["paths"] = overlap["intents"][0]["paths"]
        too_many = copy.deepcopy(baseline)
        too_many["intents"] *= 2
        for plan in (changed, duplicate, overlap, too_many):
            with self.assertRaises(VerificationError):
                check_plan(plan)

    def test_scope_methods_and_benign_check_boundary(self):
        for key, invalid in (("paths", ["/outside"]), ("methods", ["DELETE"]),
                             ("methods", ["POST"]), ("checks", ["credential_attack"]),
                             ("max_requests", 21), ("concurrency", 2), ("wall_seconds", 121)):
            plan = self.plan()
            plan["intents"][0][key] = invalid
            with self.subTest(key=key), self.assertRaises(VerificationError):
                check_plan(plan)

    def test_examples_cannot_authorize_or_add_real_or_wildcard_targets(self):
        for key in ("operator_authorized", "read_only_routes_confirmed"):
            plan = self.plan()
            plan[key] = True
            with self.subTest(key=key), self.assertRaises(VerificationError):
                check_plan(plan)
        for host in ("*.example.test", "unrelated.invalid", "app.example.test@unrelated.invalid"):
            plan = self.plan()
            plan["scope"][0]["host"] = host
            with self.subTest(host=host), self.assertRaises(VerificationError):
                check_plan(plan)

    def test_no_direct_or_insecure_proxy_fallback(self):
        for key, invalid in (("source", "new_endpoint"), ("direct_fallback", True),
                             ("tls_verification", False), ("missing_or_unreachable", "retry_direct"),
                             ("credentials", True)):
            plan = self.plan()
            plan["proxy"][key] = invalid
            with self.subTest(key=key), self.assertRaises(VerificationError):
                check_plan(plan)

    def test_config_cannot_inject_proxy_or_drop_reports(self):
        original = parse_json((self.templates / "examples" / PROFILES["native-pi-ko"]).read_text(encoding="utf-8"))
        for section in ("common_env", "worker_env", "completed_action", "max_workers"):
            config = copy.deepcopy(original)
            if section == "common_env":
                config[section] = {"HTTP_PROXY": "EXAMPLE-NOT-A-PROXY"}
            elif section == "worker_env":
                config["workers"][0]["env"] = {"HTTP_PROXY": "EXAMPLE-NOT-A-PROXY"}
            elif section == "completed_action":
                config["local"][section] = "remove"
            else:
                config["runtime"][section] = 2
            with self.subTest(section=section), self.assertRaises(VerificationError):
                check_config(config, "native-pi-ko")

    def test_reason_up_to_five_intents_exact_contract(self):
        intent = {"from": ["f001"], "description": "승인된 고정 슬롯의 한정 확인"}
        payload = {"accepted": True, "data": {"intents": [copy.deepcopy(intent) for _ in range(5)]}}
        self.assertEqual(check_contract("reason.md", payload), "intents")
        payload["data"]["intents"].append(copy.deepcopy(intent))
        with self.assertRaises(VerificationError):
            check_contract("reason.md", payload)
        with self.assertRaises(VerificationError):
            check_contract("reason.md", {"accepted": True, "data": {"intents": []}})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--templates-root", type=Path, default=ROOT / "templates")
    parser.add_argument("--cairn-root", type=Path, help="trusted, readonly upstream checkout (optional)")
    parser.add_argument("--require-full-config", action="store_true", help="fail if full upstream config cannot import/load")
    args = parser.parse_args()
    if args.require_full_config and not args.cairn_root:
        parser.error("--require-full-config requires --cairn-root")
    templates = args.templates_root.resolve()
    try:
        samples = verify_local(templates)
        RegressionTests.templates = templates
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=1).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(RegressionTests))
        require(result.wasSuccessful(), "negative regression checks failed")
        for profile in PROFILES:
            verify_fixture(templates / profile)
        if args.cairn_root:
            for profile in PROFILES:
                verify_upstream(args.cairn_root.resolve(), templates, samples[profile], args.require_full_config, profile)
        else:
            print("SKIP actual-upstream: not requested; fixture-only success is NOT upstream validation")
            print("NOT RUN: active HTTP checks, live Pi/model/dispatcher/Burp, report-file E2E, egress enforcement or official KISA full verification")
    except (OSError, ValueError, ImportError, SyntaxError, KeyError, TypeError) as exc:
        print(f"FAIL {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
