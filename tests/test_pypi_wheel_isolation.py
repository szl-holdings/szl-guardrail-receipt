"""Installed-wheel checks must not import a healthy source checkout instead."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import TestCase, main, mock, SkipTest
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / ".github/scripts/szl_pypi_release_gate.py"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if sys.version_info < (3, 11):
    raise SkipTest(
        "Release-gate regression requires Python 3.11+ stdlib tomllib; "
        "the canonical release workflow runs Python 3.12. "
        "Package compatibility tests are unchanged."
    )

gate = load("pypi_wheel_isolation_gate", GATE)


class InstalledWheelIsolationTests(TestCase):
    def run_gate(self, root, *, wheel_broken, checkout_broken):
        """Stub build/network steps; execute the actual venv metadata/import probes."""
        checkout = root / "checkout"
        checkout.mkdir()
        source = checkout / "shadow_probe"
        source.mkdir()
        failure = 'raise RuntimeError("SYNTHETIC_BROKEN_MODULE")\n'
        healthy = 'origin = "synthetic healthy module"\n'
        (source / "__init__.py").write_text(failure if checkout_broken else healthy, encoding="utf-8")
        (checkout / "README.md").write_text("Synthetic package fixture.\n", encoding="utf-8")
        (checkout / "pyproject.toml").write_text(
            '[build-system]\nbuild-backend = "setuptools.build_meta"\n'
            '[project]\nname = "shadow-probe"\nversion = "1.2.3"\n'
            'description = "synthetic wheel isolation fixture"\nreadme = "README.md"\n'
            'requires-python = ">=3.11"\nlicense = "MIT"\n'
            '[project.urls]\nSource = "https://github.com/szl-holdings/shadow-repo"\n'
            '[tool.szl.release]\nimport_names = ["shadow_probe"]\n',
            encoding="utf-8",
        )
        commands = []

        def sh(command, **kwargs):
            commands.append(command)
            if command[1:3] == ["-m", "build"]:
                stage = Path(command[command.index("--outdir") + 1])
                wheel = stage / "shadow_probe-1.2.3-py3-none-any.whl"
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr("shadow_probe/__init__.py", failure if wheel_broken else healthy)
                    archive.writestr(
                        "shadow_probe-1.2.3.dist-info/METADATA",
                        "Metadata-Version: 2.1\nName: shadow-probe\nVersion: 1.2.3\n"
                        "Project-URL: Source, https://github.com/szl-holdings/shadow-repo\n\n",
                    )
                (stage / "shadow_probe-1.2.3.tar.gz").write_bytes(b"synthetic sdist; not built or published")
                return
            if command[1:3] == ["-m", "twine"]:
                return
            if command[1:3] == ["-m", "venv"]:
                venv.EnvBuilder(with_pip=False).create(command[-1])
                return
            if "pip" in command and "check" in command:
                # Synthetic fixture dependencies are empty; no real pip is installed.
                return
            if "pip" in command and "install" in command:
                # No installer or network: lay out only our own two fixture files.
                env = Path(command[0]).parents[1]
                site = env / ("Lib/site-packages" if os.name == "nt" else
                              f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
                with zipfile.ZipFile(command[-1]) as archive:
                    archive.extractall(site)
                return
            subprocess.run(command, check=True, text=True, capture_output=True,
                           cwd=checkout, timeout=20, **kwargs)
            return None

        package = {"name": "shadow-probe", "dir": str(checkout), "environment": "pypi"}
        with mock.patch.object(gate, "sh", side_effect=sh), \
                mock.patch.object(gate, "pypi_versions", return_value=set()), \
                contextlib.redirect_stdout(io.StringIO()):
            receipt = gate.gate_package(package, "szl-holdings/shadow-repo", "pull_request",
                                        "branch", "synthetic-test", root / "dist")
        return receipt, commands

    def test_broken_installed_wheel_cannot_pass_using_healthy_checkout(self):
        with tempfile.TemporaryDirectory(prefix="szl-pypi-isolation-") as directory:
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                self.run_gate(Path(directory), wheel_broken=True, checkout_broken=False)
            self.assertIn("SYNTHETIC_BROKEN_MODULE", failure.exception.stderr)
            self.assertIn("site-packages", failure.exception.stderr)

    def test_healthy_installed_wheel_is_not_shadowed_by_broken_checkout(self):
        with tempfile.TemporaryDirectory(prefix="szl-pypi-isolation-") as directory:
            receipt, commands = self.run_gate(Path(directory), wheel_broken=False, checkout_broken=True)
            self.assertEqual(receipt["package"], "shadow-probe")
            self.assertEqual(receipt["version"], "1.2.3")
            venv_commands = [command for command in commands if "venv-shadow-probe" in command[0]]
            self.assertEqual(len(venv_commands), 4)
            self.assertTrue(all(command[1] == "-I" for command in venv_commands))



if __name__ == "__main__":
    main()
