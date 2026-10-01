import builtins

from guard import cli


def test_gui_cli_overrides_config():
    args = cli.build_parser().parse_args(
        ["gui", "--db-path", "chosen.db", "--limit", "12"]
    )
    args = cli.resolve_args(
        args,
        {
            "paths": {"db_path": "config.db", "model_path": "config.bundle"},
            "gui": {"limit": 40},
        },
    )
    assert (
        args.db_path == "chosen.db"
        and args.model_path == "config.bundle"
        and args.limit == 12
    )


def test_gui_cli_uses_config():
    args = cli.resolve_args(
        cli.build_parser().parse_args(["gui"]),
        {"paths": {"db_path": "config.db"}, "gui": {"limit": 40}},
    )
    assert (
        args.db_path == "config.db"
        and args.model_path == "data/model.bundle"
        and args.limit == 40
    )


def test_gui_missing_dependency_has_actionable_error(monkeypatch, capsys):
    original = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "guard.gui.app":
            raise ModuleNotFoundError("No module named PySide6", name="PySide6")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    args = cli.resolve_args(cli.build_parser().parse_args(["gui"]), {})
    assert cli.cmd_gui(args) == 1
    assert ".[gui]" in capsys.readouterr().out


def test_gui_rejects_nonpositive_limit(capsys):
    args = cli.resolve_args(cli.build_parser().parse_args(["gui", "--limit", "0"]), {})
    assert cli.cmd_gui(args) == 2
    assert "positive" in capsys.readouterr().out
