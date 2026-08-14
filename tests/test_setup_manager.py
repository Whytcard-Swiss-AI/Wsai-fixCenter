from pathlib import Path

import pytest

import wsai_fckdot.setup_manager as module
from wsai_fckdot.setup_manager import MANAGED_MARKER, SetupManager


def manifest(*, instruction="Write tests.", tools=None, variables=None):
    return {
        "version": 1,
        "active_profile": "personal",
        "profiles": {
            "personal": {
                "account_label": "personal",
                "variables": (
                    {"OPENAI_API_KEY": "env:OPENAI_PERSONAL_KEY"}
                    if variables is None
                    else variables
                ),
            },
            "work": {"account_label": "work", "variables": {}},
        },
        "instructions": [instruction],
        "tools": tools or ["agents", "cursor", "claude", "gemini", "copilot"],
    }


def test_catalog_inventory_and_privacy(tmp_path):
    workspace, home = tmp_path / "workspace", tmp_path / "home"
    workspace.mkdir()
    home.mkdir()
    (workspace / ".cursor").mkdir()
    (workspace / ".cursor/mcp.json").write_text("{}", encoding="utf-8")
    (workspace / ".mcp.json").write_text("{}", encoding="utf-8")
    (workspace / ".mystery").mkdir()
    (home / ".codex").mkdir()
    (workspace / "AGENTS.md").write_text("user-owned", encoding="utf-8")
    (workspace / "CLAUDE.md").write_text(f"{MANAGED_MARKER}\n", encoding="utf-8")
    manager = SetupManager(home=home, environ={"OPENAI_API_KEY": "never-read"})

    catalog = manager.catalog()
    assert catalog["manifest_version"] == 1 and len(catalog["adapters"]) == 5
    with pytest.raises(ValueError, match="consent"):
        manager.inventory(str(workspace), consent=False)
    result = manager.inventory(
        str(workspace),
        consent=True,
        include_home=True,
        include_unknown_names=True,
    )
    assert result["workspace"]["known_tool_directories"] == {".cursor": "cursor"}
    assert result["workspace"]["unknown_dot_directories"] == [".mystery"]
    assert result["home"]["known_tool_directories"] == {".codex": "codex"}
    assert result["environment_variable_names"] == ["OPENAI_API_KEY"]
    assert len(result["findings"]) == 5
    assert [item["owner"] for item in result["configuration_files"]] == [
        "cursor-mcp",
        "mcp",
    ]
    assert [item["managed"] for item in result["instruction_files"]] == [False, True]
    hidden = manager.inventory(str(workspace), consent=True)
    assert hidden["workspace"]["unknown_dot_directories"] == []
    assert hidden["home"] is None
    assert "never-read" not in str(result)


def test_inventory_reports_symlinks_without_following_them(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ={})
    original = manager._has_symlink_component
    monkeypatch.setattr(
        manager,
        "_has_symlink_component",
        lambda root, target: (
            target.as_posix().endswith("AGENTS.md")
            or target.as_posix().endswith(".mcp.json")
            or original(root, target)
        ),
    )

    result = manager.inventory(str(workspace), consent=True)
    instruction = next(
        item for item in result["instruction_files"] if item["path"] == "AGENTS.md"
    )
    configuration = next(
        item for item in result["configuration_files"] if item["path"] == ".mcp.json"
    )
    assert instruction["status"] == "blocked-symlink"
    assert configuration["status"] == "blocked-symlink"
    assert instruction["size_bytes"] is None and configuration["size_bytes"] is None


def test_inventory_reports_real_file_symlink_without_following_it(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("outside private content", encoding="utf-8")
    try:
        (workspace / "AGENTS.md").symlink_to(outside)
    except OSError:
        pytest.skip("symbolic links are not available on this host")
    manager = SetupManager(home=tmp_path / "home", environ={})

    result = manager.inventory(str(workspace), consent=True)
    instruction = next(
        item for item in result["instruction_files"] if item["path"] == "AGENTS.md"
    )
    assert instruction == {
        "path": "AGENTS.md",
        "managed": False,
        "size_bytes": None,
        "status": "blocked-symlink",
    }


def test_plan_apply_update_and_stale_guard(tmp_path):
    workspace, home = tmp_path / "workspace", tmp_path / "home"
    workspace.mkdir()
    home.mkdir()
    manager = SetupManager(home=home, environ={})
    data = manifest()

    with pytest.raises(ValueError, match="consent"):
        manager.plan(str(workspace), data, consent=False)
    plan = manager.plan(str(workspace), data, consent=True)
    assert plan.can_apply and {item["action"] for item in plan.actions} == {"create"}
    public_plan = plan.to_dict()
    assert "instruction contents" in public_plan["privacy"]
    assert all("_expected_digest" not in item for item in public_plan["actions"])
    with pytest.raises(ValueError, match="consent"):
        manager.apply(str(workspace), data, plan.plan_id, consent=False)
    with pytest.raises(ValueError, match="stale"):
        manager.apply(str(workspace), data, "0" * 24, consent=True)

    applied = manager.apply(str(workspace), data, plan.plan_id, consent=True)
    assert applied["created"] == 11 and applied["updated"] == 0
    assert (workspace / ".wsai_fckdot/setup.json").is_file()
    assert (
        (workspace / ".cursor/rules/wsai_fckdot.mdc")
        .read_text(encoding="utf-8")
        .startswith("---")
    )
    assert "OPENAI_PERSONAL_KEY" in (workspace / "AGENTS.md").read_text(
        encoding="utf-8"
    )
    powershell = (workspace / ".wsai_fckdot/profiles/personal.ps1").read_text(
        encoding="utf-8"
    )
    shell = (workspace / ".wsai_fckdot/profiles/personal.sh").read_text(
        encoding="utf-8"
    )
    assert "OPENAI_PERSONAL_KEY" in powershell and "never-read" not in powershell
    assert 'export OPENAI_API_KEY="${OPENAI_PERSONAL_KEY}"' in shell

    unchanged = manager.plan(str(workspace), data, consent=True)
    assert {item["action"] for item in unchanged.actions} == {"unchanged"}
    no_change = manager.apply(str(workspace), data, unchanged.plan_id, consent=True)
    assert no_change["unchanged"] == 11 and no_change["backup_directory"] is None

    changed = manifest(instruction="Run the smallest relevant test.")
    update = manager.plan(str(workspace), changed, consent=True)
    assert {item["action"] for item in update.actions} == {"update", "unchanged"}
    updated = manager.apply(str(workspace), changed, update.plan_id, consent=True)
    assert updated["updated"] == 7 and updated["created"] == 0
    backup = workspace / ".wsai_fckdot/backups" / update.plan_id
    assert backup.is_dir() and (backup / "AGENTS.md").is_file()


def test_plan_is_workspace_bound_and_retires_removed_surfaces(tmp_path):
    first_root, second_root, home = (
        tmp_path / "first",
        tmp_path / "second",
        tmp_path / "home",
    )
    first_root.mkdir()
    second_root.mkdir()
    home.mkdir()
    manager = SetupManager(home=home, environ={})
    complete = manifest()
    first_plan = manager.plan(str(first_root), complete, consent=True)
    second_plan = manager.plan(str(second_root), complete, consent=True)
    assert first_plan.plan_id != second_plan.plan_id
    manager.apply(str(first_root), complete, first_plan.plan_id, consent=True)

    reduced = manifest(tools=["agents"])
    reduced["profiles"].pop("work")
    retire_plan = manager.plan(str(first_root), reduced, consent=True)
    retired_paths = {
        item["path"] for item in retire_plan.actions if item["action"] == "retire"
    }
    assert "CLAUDE.md" in retired_paths
    assert ".wsai_fckdot/profiles/work.ps1" in retired_paths
    result = manager.apply(str(first_root), reduced, retire_plan.plan_id, consent=True)
    assert result["retired"] == 6
    assert not (first_root / "CLAUDE.md").exists()
    retired = first_root / ".wsai_fckdot/retired" / retire_plan.plan_id
    assert (retired / "CLAUDE.md").is_file()
    assert (retired / ".wsai_fckdot/profiles/work.sh").is_file()


def test_preserves_user_files_and_blocks_unsafe_targets(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ={})
    data = manifest(tools=["agents"])
    (workspace / "AGENTS.md").write_text("mine", encoding="utf-8")
    blocked = manager.plan(str(workspace), data, consent=True)
    assert not blocked.can_apply and blocked.warnings
    with pytest.raises(ValueError, match="blocked"):
        manager.apply(str(workspace), data, blocked.plan_id, consent=True)
    assert (workspace / "AGENTS.md").read_text(encoding="utf-8") == "mine"

    (workspace / "AGENTS.md").unlink()
    (workspace / "AGENTS.md").mkdir()
    assert not manager.plan(str(workspace), data, consent=True).can_apply
    (workspace / "AGENTS.md").rmdir()
    (workspace / "AGENTS.md").write_bytes(b"x" * (module.MAX_FILE_BYTES + 1))
    assert manager._managed_file(workspace / "AGENTS.md") is False
    assert not manager.plan(str(workspace), data, consent=True).can_apply
    (workspace / "AGENTS.md").unlink()
    monkeypatch.setattr(manager, "_has_symlink_component", lambda *_: True)
    assert not manager.plan(str(workspace), data, consent=True).can_apply


def test_transaction_restores_created_and_updated_files(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ={})
    data = manifest(tools=["agents"])
    plan = manager.plan(str(workspace), data, consent=True)

    monkeypatch.setattr(
        manager,
        "_atomic_create",
        lambda *_: (_ for _ in ()).throw(OSError("synthetic")),
    )
    with pytest.raises(OSError, match="synthetic"):
        manager.apply(str(workspace), data, plan.plan_id, consent=True)
    assert not (workspace / ".wsai_fckdot/instructions.md").exists()

    monkeypatch.undo()
    plan = manager.plan(str(workspace), data, consent=True)
    manager.apply(str(workspace), data, plan.plan_id, consent=True)
    original = (workspace / ".wsai_fckdot/instructions.md").read_bytes()
    changed = manifest(instruction="Different safe rule.", tools=["agents"])
    update = manager.plan(str(workspace), changed, consent=True)
    monkeypatch.setattr(
        manager,
        "_atomic_create",
        lambda *_: (_ for _ in ()).throw(OSError("synthetic")),
    )
    with pytest.raises(OSError):
        manager.apply(str(workspace), changed, update.plan_id, consent=True)
    assert (workspace / ".wsai_fckdot/instructions.md").read_bytes() == original


def test_apply_rechecks_state_and_preserves_concurrent_file(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ={})
    data = manifest(tools=["agents"])
    plan = manager.plan(str(workspace), data, consent=True)
    original_check = manager._assert_create_state
    changed = False

    def race(root, target):
        nonlocal changed
        if not changed:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("concurrent user file", encoding="utf-8")
            changed = True
        original_check(root, target)

    monkeypatch.setattr(manager, "_assert_create_state", race)
    with pytest.raises(ValueError, match="changed after planning"):
        manager.apply(str(workspace), data, plan.plan_id, consent=True)
    concurrent = workspace / ".wsai_fckdot/instructions.md"
    assert concurrent.read_text(encoding="utf-8") == "concurrent user file"


def test_update_identity_race_preserves_concurrent_content(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ={})
    initial = manifest(tools=["agents"])
    first = manager.plan(str(workspace), initial, consent=True)
    manager.apply(str(workspace), initial, first.plan_id, consent=True)
    changed = manifest(instruction="Changed instruction.", tools=["agents"])
    plan = manager.plan(str(workspace), changed, consent=True)
    target = workspace / ".wsai_fckdot/instructions.md"
    original_create = manager._atomic_create
    raced = False

    def race(candidate, content):
        nonlocal raced
        if candidate == target and not raced:
            candidate.write_text("concurrent user content", encoding="utf-8")
            raced = True
        original_create(candidate, content)

    monkeypatch.setattr(manager, "_atomic_create", race)
    with pytest.raises(FileExistsError):
        manager.apply(str(workspace), changed, plan.plan_id, consent=True)
    assert target.read_text(encoding="utf-8") == "concurrent user content"
    backup = workspace / ".wsai_fckdot/backups" / plan.plan_id
    assert (backup / ".wsai_fckdot/instructions.md").is_file()


def test_update_move_never_replaces_concurrent_backup(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ={})
    initial = manifest(tools=["agents"])
    first = manager.plan(str(workspace), initial, consent=True)
    manager.apply(str(workspace), initial, first.plan_id, consent=True)
    changed = manifest(instruction="Changed instruction.", tools=["agents"])
    plan = manager.plan(str(workspace), changed, consent=True)
    target = workspace / ".wsai_fckdot/instructions.md"
    original = target.read_text(encoding="utf-8")
    original_move = manager._move_no_replace
    raced = False

    def race(source, destination):
        nonlocal raced
        if source == target and not raced:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text("concurrent backup", encoding="utf-8")
            raced = True
        original_move(source, destination)

    monkeypatch.setattr(manager, "_move_no_replace", race)
    with pytest.raises(FileExistsError):
        manager.apply(str(workspace), changed, plan.plan_id, consent=True)
    assert target.read_text(encoding="utf-8") == original
    backup = workspace / ".wsai_fckdot/backups" / plan.plan_id
    assert (backup / ".wsai_fckdot/instructions.md").read_text(
        encoding="utf-8"
    ) == "concurrent backup"


def test_apply_lock_prevents_overlapping_application(tmp_path):
    workspace = tmp_path / "workspace"
    lock = workspace / ".wsai_fckdot/apply.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text("stale-but-unlocked", encoding="utf-8")
    manager = SetupManager(home=tmp_path / "home", environ={})
    data = manifest(tools=["agents"])
    plan = manager.plan(str(workspace), data, consent=True)
    with (
        manager._workspace_lock(workspace),
        pytest.raises(ValueError, match="in progress"),
    ):
        manager.apply(str(workspace), data, plan.plan_id, consent=True)
    assert lock.exists()
    assert manager.apply(str(workspace), data, plan.plan_id, consent=True)["applied"]


def test_expected_state_and_lock_defensive_branches(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "AGENTS.md"
    target.write_text("current", encoding="utf-8")
    with pytest.raises(ValueError, match="no longer matches"):
        SetupManager._read_expected_file(workspace, target, "wrong")
    metadata = target.lstat()
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )
    SetupManager._assert_file_identity(target, identity)
    with pytest.raises(ValueError, match="identity no longer matches"):
        SetupManager._assert_file_identity(target, (0, 0, 0, 0))
    target.unlink()
    with pytest.raises(ValueError, match="identity no longer matches"):
        SetupManager._assert_file_identity(target, identity)
    target.write_text("current", encoding="utf-8")
    monkeypatch.setattr(
        SetupManager,
        "_has_symlink_component",
        staticmethod(lambda *_: True),
    )
    with pytest.raises(ValueError, match="symbolic link detected"):
        SetupManager._assert_create_state(workspace, target)
    with pytest.raises(ValueError, match="symbolic link detected"):
        SetupManager._read_expected_file(workspace, target, "wrong")
    with (
        pytest.raises(ValueError, match="directory contains a symbolic link"),
        SetupManager._workspace_lock(workspace),
    ):
        pass
    monkeypatch.undo()

    with SetupManager._workspace_lock(workspace):
        assert (workspace / ".wsai_fckdot/apply.lock").is_file()

    monkeypatch.setattr(
        module.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("open")),
    )
    with (
        pytest.raises(ValueError, match="in progress"),
        SetupManager._workspace_lock(workspace),
    ):
        pass

    monkeypatch.undo()
    original_symlink_check = SetupManager._has_symlink_component
    monkeypatch.setattr(
        SetupManager,
        "_has_symlink_component",
        staticmethod(
            lambda root, candidate: (
                candidate.name == "apply.lock"
                or original_symlink_check(root, candidate)
            )
        ),
    )
    with (
        pytest.raises(ValueError, match="lock path contains a symbolic link"),
        SetupManager._workspace_lock(workspace),
    ):
        pass


def test_read_expected_file_rejects_unsafe_targets(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "AGENTS.md"
    with pytest.raises(ValueError, match="opened safely"):
        SetupManager._read_expected_file(workspace, target, "missing")
    target.mkdir()
    with pytest.raises(ValueError, match="opened safely|safe regular file"):
        SetupManager._read_expected_file(workspace, target, "directory")
    target.rmdir()
    target.write_text("content", encoding="utf-8")
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 1)
    with pytest.raises(ValueError, match="safe regular file"):
        SetupManager._read_expected_file(workspace, target, "oversize")


def test_atomic_create_cleans_partial_file(tmp_path, monkeypatch):
    target = tmp_path / "new.txt"

    class BrokenStream:
        def __init__(self, descriptor):
            self.descriptor = descriptor

        def __enter__(self):
            return self

        def __exit__(self, *_):
            module.os.close(self.descriptor)
            return False

        def write(self, _content):
            raise OSError("synthetic write")

    monkeypatch.setattr(
        module.os,
        "fdopen",
        lambda descriptor, *_args, **_kwargs: BrokenStream(descriptor),
    )
    with pytest.raises(OSError, match="synthetic write"):
        SetupManager._atomic_create(target, "content")
    assert not target.exists()

    monkeypatch.setattr(
        module.os, "unlink", lambda *_: (_ for _ in ()).throw(FileNotFoundError())
    )
    with pytest.raises(OSError, match="synthetic write"):
        SetupManager._atomic_create(target, "content")


@pytest.mark.parametrize(
    "change,error,message",
    [
        (lambda _: [], TypeError, "object"),
        (lambda d: {**d, "extra": True}, ValueError, "unknown fields"),
        (lambda d: {**d, "version": 2}, ValueError, "version"),
        (lambda d: {**d, "active_profile": "bad space"}, ValueError, "safe"),
        (lambda d: {**d, "profiles": {}}, ValueError, "between"),
        (lambda d: {**d, "profiles": {"bad space": {}}}, ValueError, "names"),
        (lambda d: {**d, "profiles": {"CON": {}}}, ValueError, "portable"),
        (lambda d: {**d, "profiles": {"personal.": {}}}, ValueError, "portable"),
        (
            lambda d: {**d, "profiles": {"personal": {}, "PERSONAL": {}}},
            ValueError,
            "ignoring case",
        ),
        (lambda d: {**d, "profiles": {"personal": []}}, TypeError, "object"),
        (
            lambda d: {**d, "profiles": {"personal": {"extra": True}}},
            ValueError,
            "unknown fields",
        ),
        (
            lambda d: {**d, "profiles": {"personal": {"account_label": "bad x"}}},
            ValueError,
            "account_label",
        ),
        (
            lambda d: {
                **d,
                "profiles": {
                    "personal": {"account_label": "sk-123456789012345678901234"}
                },
            },
            ValueError,
            "account_label",
        ),
        (
            lambda d: {**d, "profiles": {"personal": {"variables": []}}},
            ValueError,
            "variables",
        ),
        (
            lambda d: {
                **d,
                "profiles": {"personal": {"variables": {"BAD NAME": "env:X"}}},
            },
            ValueError,
            "variable names",
        ),
        (
            lambda d: {
                **d,
                "profiles": {"personal": {"variables": {"TOKEN": "actual-value"}}},
            },
            ValueError,
            "env:VARIABLE",
        ),
        (
            lambda d: {
                **d,
                "profiles": {
                    "personal": {"variables": {"OPENAI_API_KEY": "env:openai_api_key"}}
                },
            },
            ValueError,
            "must not also be managed target",
        ),
        (
            lambda d: {
                **d,
                "profiles": {
                    "personal": {"variables": {"OPENAI_API_KEY": "env:SOURCE_A"}},
                    "work": {"variables": {"openai_api_key": "env:SOURCE_B"}},
                },
            },
            ValueError,
            "consistent casing",
        ),
        (lambda d: {**d, "active_profile": "missing"}, ValueError, "declared"),
        (lambda d: {**d, "instructions": []}, ValueError, "between"),
        (lambda d: {**d, "instructions": [3]}, TypeError, "string"),
        (lambda d: {**d, "instructions": [" "]}, ValueError, "non-empty"),
        (
            lambda d: {**d, "instructions": ["token=actual-secret"]},
            ValueError,
            "credentials",
        ),
        (lambda d: {**d, "instructions": [MANAGED_MARKER]}, ValueError, "markers"),
        (lambda d: {**d, "tools": []}, ValueError, "adapter"),
        (lambda d: {**d, "tools": [3]}, ValueError, "adapter"),
        (lambda d: {**d, "tools": ["unknown"]}, ValueError, "unknown setup"),
    ],
)
def test_manifest_validation(change, error, message):
    with pytest.raises(error, match=message):
        SetupManager._validate_manifest(change(manifest()))


def test_path_scan_and_atomic_helpers(tmp_path, monkeypatch):
    manager = SetupManager(home=tmp_path, environ={})
    with pytest.raises(ValueError, match="non-empty"):
        manager._resolve_root("")
    with pytest.raises(ValueError, match="absolute"):
        manager._resolve_root("relative")
    with pytest.raises(ValueError, match="accessible"):
        manager._resolve_root(str(tmp_path / "missing"))
    regular_file = tmp_path / "file"
    regular_file.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="directory"):
        manager._resolve_root(str(regular_file))
    with pytest.raises(ValueError, match="filesystem root"):
        manager._resolve_root(str(Path(tmp_path.anchor)), writable=True)
    with pytest.raises(ValueError, match="user home"):
        manager.apply(str(tmp_path), manifest(), "0" * 24, consent=True)
    with pytest.raises(ValueError, match="escapes"):
        manager._safe_target(tmp_path, "../outside")

    class BrokenDirectory:
        def iterdir(self):
            raise PermissionError("synthetic")

    scan = manager._scan_directory(BrokenDirectory(), False)
    assert scan["scan_error"] == "PermissionError"
    (tmp_path / ".one").mkdir()
    (tmp_path / ".two").mkdir()
    monkeypatch.setattr(module, "MAX_DIRECTORY_ENTRIES", 1)
    assert manager._scan_directory(tmp_path, True)["truncated"] is True

    target = tmp_path / "atomic.txt"
    manager._atomic_create(target, "ok")
    assert target.read_text(encoding="utf-8") == "ok"
    with pytest.raises(FileExistsError):
        manager._atomic_create(target, "fail")


def test_optional_defaults_and_empty_bindings(tmp_path):
    manager = SetupManager(environ={})
    data = manifest(tools=["agents"], variables={})
    normalized = manager._validate_manifest(data)
    body = manager._instruction_body(normalized)
    assert "No environment bindings" in body
    assert manager._is_managed(
        '{"managed_by": "wsai_fckdot"}', ".wsai_fckdot/setup.json"
    )
    assert not manager._is_managed('{"managed_by": "wsai_fckdot"}')
    assert manager._is_managed(manager._cursor_body(f"{MANAGED_MARKER}\nbody"))
    assert not manager._is_managed(f"Quoted later: {MANAGED_MARKER}")
    assert not manager._is_managed("not json")
    assert not manager._is_managed("not json", ".wsai_fckdot/setup.json")
    assert not manager._is_managed('["managed_by", "wsai_fckdot"]')
    assert manager._digest(b"x")
    target = manager._safe_target(tmp_path, "AGENTS.md")
    assert manager._has_symlink_component(tmp_path, target) is False


def test_profile_scripts_validate_sources_before_changing_targets():
    bindings = {
        "OPENAI_API_KEY": "env:OPENAI_PERSONAL_KEY",
        "GITHUB_TOKEN": "env:GITHUB_PERSONAL_TOKEN",
    }
    targets = ["GITHUB_TOKEN", "OPENAI_API_KEY"]
    powershell = SetupManager._powershell_profile("personal", bindings, targets)
    shell = SetupManager._shell_profile("personal", bindings, targets)
    assert powershell.rfind("Test-Path Env:") < powershell.find("Remove-Item Env:")
    assert shell.rfind('if [ "${') < shell.find("unset ")


def test_backup_preflight_guards(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manager = SetupManager(home=tmp_path / "home", environ=set())
    data = manifest(tools=["agents"])
    first = manager.plan(str(workspace), data, consent=True)
    manager.apply(str(workspace), data, first.plan_id, consent=True)
    changed = manifest(instruction="Changed rule.", tools=["agents"])
    update = manager.plan(str(workspace), changed, consent=True)

    original_check = manager._has_symlink_component
    monkeypatch.setattr(
        manager,
        "_has_symlink_component",
        lambda root, target: "backups" in target.parts or original_check(root, target),
    )
    with pytest.raises(ValueError, match="symbolic"):
        manager.apply(str(workspace), changed, update.plan_id, consent=True)
    monkeypatch.undo()

    backup = workspace / ".wsai_fckdot/backups" / update.plan_id / "AGENTS.md"
    backup.parent.mkdir(parents=True)
    backup.write_text("collision", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        manager.apply(str(workspace), changed, update.plan_id, consent=True)


def test_retirement_candidate_and_restore_edge_cases(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    profiles = workspace / ".wsai_fckdot/profiles"
    profiles.mkdir(parents=True)
    (workspace / "CLAUDE.md").mkdir()

    original_iterdir = Path.iterdir

    def fail_profiles(path):
        if path == profiles:
            raise PermissionError("synthetic")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", fail_profiles)
    assert SetupManager._retirement_candidates(workspace, set()) == (
        [],
        "Profile activators could not be inventoried safely.",
    )
    monkeypatch.undo()
    (profiles / "notes.txt").write_text("ignore", encoding="utf-8")
    assert SetupManager._retirement_candidates(workspace, set()) == ([], None)

    target = workspace / "GEMINI.md"
    retired = workspace / ".wsai_fckdot/retired/plan/GEMINI.md"
    retired.parent.mkdir(parents=True)
    retired.write_text("old", encoding="utf-8")
    SetupManager._restore_transaction(workspace, {}, {target: retired})
    assert target.read_bytes() == b"old" and not retired.exists()
    missing_target = workspace / "missing"
    missing_retired = workspace / ".wsai_fckdot/retired/plan/missing"
    SetupManager._restore_transaction(workspace, {}, {missing_target: missing_retired})
    SetupManager._restore_transaction(workspace, {})
    created = workspace / "created"
    created.write_text("created", encoding="utf-8")
    digest = SetupManager._digest(b"created")
    SetupManager._restore_transaction(workspace, {created: digest})
    assert not created.exists()
    changed = workspace / "changed"
    changed.write_text("external", encoding="utf-8")
    SetupManager._restore_transaction(
        workspace, {changed: SetupManager._digest(b"generated")}
    )
    assert changed.read_text(encoding="utf-8") == "external"
    occupied = workspace / "occupied"
    occupied.write_text("external", encoding="utf-8")
    occupied_backup = workspace / ".wsai_fckdot/backups/occupied"
    occupied_backup.parent.mkdir(parents=True, exist_ok=True)
    occupied_backup.write_text("old", encoding="utf-8")
    SetupManager._restore_transaction(workspace, {}, {occupied: occupied_backup})
    assert occupied.exists() and occupied_backup.exists()
    link_target = workspace / "link-target"
    link_backup = workspace / ".wsai_fckdot/backups/link-target"
    link_backup.write_text("old", encoding="utf-8")
    monkeypatch.setattr(
        module.os, "link", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    SetupManager._restore_transaction(workspace, {}, {link_target: link_backup})
    assert not link_target.exists() and link_backup.exists()


@pytest.mark.parametrize("state", ["symlink", "oversize", "unmanaged"])
def test_retirement_rechecks_candidate_state(tmp_path, monkeypatch, state):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "CLAUDE.md"
    target.write_text(f"{MANAGED_MARKER}\n", encoding="utf-8")
    manager = SetupManager(home=tmp_path / "home", environ=set())
    monkeypatch.setattr(
        manager,
        "_retirement_candidates",
        lambda *_: (["CLAUDE.md"], None),
    )
    if state == "symlink":
        monkeypatch.setattr(
            manager,
            "_has_symlink_component",
            lambda _root, candidate: candidate == target,
        )
    elif state == "oversize":
        monkeypatch.setattr(module, "MAX_FILE_BYTES", 1)
    else:
        target.write_text("user-owned", encoding="utf-8")
    plan = manager.plan(str(workspace), manifest(tools=["agents"]), consent=True)
    action = next(item for item in plan.actions if item["path"] == "CLAUDE.md")
    assert action["action"] == "blocked"


def test_retirement_ignores_unprovable_adapter_ownership(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "CLAUDE.md").write_text("user owned", encoding="utf-8")
    manager = SetupManager(home=tmp_path / "home", environ=set())
    plan = manager.plan(str(workspace), manifest(tools=["agents"]), consent=True)
    assert plan.can_apply
    assert all(item["path"] != "CLAUDE.md" for item in plan.actions)

    (workspace / "CLAUDE.md").write_bytes(b"x" * 2)
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 1)
    plan = manager.plan(str(workspace), manifest(tools=["agents"]), consent=True)
    assert plan.can_apply
    assert all(item["path"] != "CLAUDE.md" for item in plan.actions)


def test_retirement_scan_limit_blocks_plan(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    profiles = workspace / ".wsai_fckdot/profiles"
    profiles.mkdir(parents=True)
    (profiles / "a.ps1").write_text(
        f"{module.MANAGED_SCRIPT_MARKER}\n", encoding="utf-8"
    )
    (profiles / "b.ps1").write_text(
        f"{module.MANAGED_SCRIPT_MARKER}\n", encoding="utf-8"
    )
    monkeypatch.setattr(module, "MAX_DIRECTORY_ENTRIES", 1)
    manager = SetupManager(home=tmp_path / "home", environ=set())
    plan = manager.plan(str(workspace), manifest(tools=["agents"]), consent=True)
    assert not plan.can_apply
    assert any("entry limit" in item["reason"] for item in plan.actions)


def test_symlink_component_short_circuits(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "AGENTS.md"
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "nested")
    assert SetupManager._has_symlink_component(tmp_path, target) is True
