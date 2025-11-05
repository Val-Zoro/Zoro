from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_OWNER = "Val-Zoro"
DEFAULT_REPO = "Zoro"
DEFAULT_CHANNEL = "prerelease"
INSTALL_DIR_NAME = "ZoroApp"
VERSION_FILE_NAME = ".zoro-version"
PRESERVE_WHEN_PRESENT: frozenset[str] = frozenset(
	{
		"config.ini",
		"data",
		"logs",
		"output",
	}
)
USER_AGENT = "Valorant-Zoro-Launcher"
EXE_PATTERN = re.compile(r"^Zoro.*\.exe$", re.IGNORECASE)


class LauncherError(Exception):
	"""Raised when the launcher cannot complete a required action."""


def parse_args() -> tuple[argparse.Namespace, list[str]]:
	parser = argparse.ArgumentParser(
		description=(
			"Valorant Zoro bootstrap launcher. Downloads or updates the full client before launching it."
		),
		add_help=True,
	)
	parser.add_argument(
		"--channel",
		choices=("stable", "prerelease"),
		default=DEFAULT_CHANNEL,
		help="Choose which GitHub release channel to track.",
	)
	parser.add_argument(
		"--owner",
		default=DEFAULT_OWNER,
		help="GitHub account hosting Valorant Zoro releases.",
	)
	parser.add_argument(
		"--repo",
		default=DEFAULT_REPO,
		help="GitHub repository providing release archives.",
	)
	parser.add_argument(
		"--install-dir",
		default=INSTALL_DIR_NAME,
		help="Target folder (relative) where Valorant Zoro should be installed.",
	)
	parser.add_argument(
		"--force-install",
		action="store_true",
		help="Always download and reinstall the latest release before launching.",
	)
	parser.add_argument(
		"--yes",
		action="store_true",
		help="Answer yes to update prompts (useful for scripted deployments).",
	)
	return parser.parse_known_args()


def resolve_base_dir() -> Path:
	if getattr(sys, "frozen", False):
		return Path(sys.executable).resolve().parent
	return Path(__file__).resolve().parent


def read_local_version(install_dir: Path) -> Optional[str]:
	version_file = install_dir / VERSION_FILE_NAME
	if not version_file.exists():
		return None
	try:
		return version_file.read_text(encoding="utf-8").strip() or None
	except OSError:
		return None


def write_local_version(install_dir: Path, version: str) -> None:
	version_file = install_dir / VERSION_FILE_NAME
	version_file.write_text(version.strip(), encoding="utf-8")


def fetch_latest_release(owner: str, repo: str, *, include_prerelease: bool) -> Optional[dict]:
	url = f"https://api.github.com/repos/{owner}/{repo}/releases"
	request = Request(
		url,
		headers={
			"Accept": "application/vnd.github+json",
			"User-Agent": USER_AGENT,
		},
	)
	try:
		with urlopen(request, timeout=20) as response:
			payload = response.read()
	except HTTPError as exc:
		raise LauncherError(f"GitHub API returned HTTP {exc.code}") from exc
	except URLError as exc:
		raise LauncherError(f"Unable to reach GitHub: {exc.reason}") from exc

	try:
		releases = json.loads(payload)
	except json.JSONDecodeError as exc:
		raise LauncherError("Failed to parse GitHub release metadata") from exc

	if not isinstance(releases, list):
		raise LauncherError("Unexpected response shape from GitHub API")

	for release in releases:
		if release.get("draft"):
			continue
		if not include_prerelease and release.get("prerelease"):
			continue
		return release
	return None


def version_key(version: str) -> tuple[int, ...]:
	if not version:
		return (0,)
	cleaned = version.strip()
	if cleaned.lower().startswith("v"):
		cleaned = cleaned[1:]
	base = cleaned.split("-", 1)[0].split("+", 1)[0]
	parts: list[int] = []
	for segment in base.split("."):
		digits = "".join(ch for ch in segment if ch.isdigit())
		if digits:
			parts.append(int(digits))
	return tuple(parts) if parts else (0,)


def download_release_asset(release: dict, destination_dir: Path) -> Path:
	url, filename = select_executable_asset(release)
	if not url:
		raise LauncherError(
			"Release does not expose a downloadable executable named Zoro*.exe.",
		)

	destination_dir.mkdir(parents=True, exist_ok=True)
	asset_path = destination_dir / filename

	request = Request(
		url,
		headers={"User-Agent": USER_AGENT},
	)
	try:
		with urlopen(request, timeout=60) as response, asset_path.open("wb") as fh:
			chunk = response.read(1024 * 128)
			while chunk:
				fh.write(chunk)
				chunk = response.read(1024 * 128)
	except HTTPError as exc:
		raise LauncherError(f"Failed to download executable (HTTP {exc.code})") from exc
	except URLError as exc:
		raise LauncherError(f"Network error while downloading executable: {exc.reason}") from exc
	except OSError as exc:
		raise LauncherError(f"Could not persist downloaded executable: {exc}") from exc

	return asset_path


def select_executable_asset(release: dict) -> tuple[str, str]:
	assets = release.get("assets") or []
	for asset in assets:
		url = asset.get("browser_download_url")
		name = asset.get("name")
		if not url or not name:
			continue
		if EXE_PATTERN.match(name):
			return url, name
	return "", ""


def install_executable(executable_path: Path, install_dir: Path) -> Path:
	install_dir.mkdir(parents=True, exist_ok=True)

	for existing in list(install_dir.iterdir()):
		if existing.name in PRESERVE_WHEN_PRESENT:
			continue
		if existing.is_dir():
			shutil.rmtree(existing, ignore_errors=True)
			continue
		if existing.is_file():
			if EXE_PATTERN.match(existing.name):
				existing.unlink(missing_ok=True)
			else:
				existing.unlink(missing_ok=True)

	target_path = install_dir / executable_path.name
	shutil.copy2(executable_path, target_path)

	canonical_path = install_dir / "Zoro.exe"
	if target_path.name.lower() != "zoro.exe":
		canonical_path.unlink(missing_ok=True)
		shutil.copy2(target_path, canonical_path)
		return canonical_path
	return target_path


def ensure_installation(
		*,
		owner: str,
		repo: str,
		channel: str,
		install_dir: Path,
		force_install: bool,
		assume_yes: bool,
) -> tuple[Optional[str], Optional[str]]:
	include_prerelease = channel == "prerelease"
	release = fetch_latest_release(owner, repo, include_prerelease=include_prerelease)
	if release is None:
		raise LauncherError("No suitable release was found on GitHub")

	remote_version = release.get("tag_name") or release.get("name") or "latest"
	local_version = read_local_version(install_dir)

	needs_install = force_install or local_version is None or not has_existing_payload(install_dir)
	if not needs_install and version_key(remote_version) <= version_key(local_version):
		print(f"[launcher] Local version {local_version} is up to date.")
		return local_version, remote_version

	if not needs_install:
		if assume_yes:
			install_update = True
		else:
			prompt = f"Update available ({local_version or 'unknown'} -> {remote_version}). Download now? [Y/n]: "
			install_update = input(prompt).strip().lower() in {"", "y", "yes"}

		if not install_update:
			print("[launcher] Skipping update at user request.")
			return local_version, remote_version

	print(f"[launcher] Downloading Valorant Zoro {remote_version}...")
	with tempfile.TemporaryDirectory(prefix="zoro-launcher-download-") as temp_dir_str:
		temp_dir = Path(temp_dir_str)
		asset_path = download_release_asset(release, temp_dir)
		try:
			install_executable(asset_path, install_dir)
		except OSError as exc:
			raise LauncherError(f"Failed to copy release files: {exc}") from exc

	write_local_version(install_dir, remote_version)
	print(f"[launcher] Installed Valorant Zoro {remote_version} at {install_dir}")
	return local_version, remote_version


def has_existing_payload(install_dir: Path) -> bool:
	if not install_dir.exists():
		return False
	return any(EXE_PATTERN.match(path.name) for path in install_dir.glob("*.exe"))


def launch_application(install_dir: Path, forward_args: Iterable[str]) -> int:
	exe_candidates = sorted(
		[path for path in install_dir.glob("*.exe") if EXE_PATTERN.match(path.name)],
		key=lambda p: (0 if p.name.lower() == "zoro.exe" else 1, p.name.lower()),
	)

	for candidate in exe_candidates:
		if candidate.exists():
			print(f"[launcher] Starting {candidate}")
			process = subprocess.Popen([str(candidate), *forward_args], cwd=install_dir)
			try:
				return process.wait()
			except KeyboardInterrupt:
				process.terminate()
				return process.wait()

	script_candidate = install_dir / "main.py"
	if script_candidate.exists():
		python_cmd = select_python_interpreter()
		if python_cmd is None:
			raise LauncherError(
				"Unable to locate a Python interpreter to run main.py. "
				"Ensure Python 3.12+ is installed or ship a compiled executable."
			)
		print(f"[launcher] Starting Python entrypoint {script_candidate}")
		process = subprocess.Popen([python_cmd, str(script_candidate), *forward_args], cwd=install_dir)
		try:
			return process.wait()
		except KeyboardInterrupt:
			process.terminate()
			return process.wait()

	raise LauncherError(
		"Could not find an executable entrypoint in the installation directory. "
		"Expected Zoro.exe or main.py to exist."
	)


def select_python_interpreter() -> Optional[str]:
	if not getattr(sys, "frozen", False):
		return sys.executable
	for candidate in ("python.exe", "python3.exe", "python", "python3"):
		python_path = shutil.which(candidate)
		if python_path:
			return python_path
	return None


def main() -> int:
	args, forward_args = parse_args()
	base_dir = resolve_base_dir()
	install_dir = (base_dir / args.install_dir).resolve()

	print(f"[launcher] Using install directory: {install_dir}")
	try:
		ensure_installation(
			owner=args.owner.strip() or DEFAULT_OWNER,
			repo=args.repo.strip() or DEFAULT_REPO,
			channel=args.channel,
			install_dir=install_dir,
			force_install=args.force_install,
			assume_yes=args.yes,
		)
		return launch_application(install_dir, forward_args)
	except LauncherError as exc:
		print(f"[launcher] Error: {exc}")
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
