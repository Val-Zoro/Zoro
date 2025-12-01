from __future__ import annotations

import argparse
import hashlib
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
CHANNEL_CHOICES = ("stable", "prerelease")
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
LAUNCHER_FILENAME = "Launcher.exe"
LAUNCHER_PATTERN = re.compile(r"^Launcher.*\.exe$", re.IGNORECASE)
INSTALL_METADATA_FILE = ".zoro-install.json"
CHECKSUM_BUFFER_SIZE = 1024 * 1024


class LauncherError(Exception):
	"""Raised when the launcher cannot complete a required action."""


def parse_digest_parts(digest: str) -> tuple[str, str]:
	if ":" in digest:
		algorithm, value = digest.split(":", 1)
	else:
		algorithm, value = "sha256", digest
	return algorithm.strip().lower(), value.strip().lower()


def format_digest(algorithm: str, value: str) -> str:
	return f"{algorithm.lower()}:{value.lower()}"


def digests_equal(first: Optional[str], second: Optional[str]) -> bool:
	if not first or not second:
		return False
	algo_a, value_a = parse_digest_parts(first)
	algo_b, value_b = parse_digest_parts(second)
	return algo_a == algo_b and value_a == value_b


def compute_file_digest(file_path: Path, algorithm: str = "sha256") -> str:
	try:
		hasher = hashlib.new(algorithm)
	except ValueError as exc:
		raise LauncherError(f"Unsupported digest algorithm requested: {algorithm}") from exc
	with file_path.open("rb") as source:
		for chunk in iter(lambda: source.read(CHECKSUM_BUFFER_SIZE), b""):
			if not chunk:
				break
			hasher.update(chunk)
	return hasher.hexdigest()


def ensure_checksum(file_path: Path, expected_digest: Optional[str]) -> str:
	if expected_digest:
		algorithm, expected_value = parse_digest_parts(expected_digest)
	else:
		algorithm, expected_value = "sha256", ""

	actual_value = compute_file_digest(file_path, algorithm)
	if expected_digest and actual_value.lower() != expected_value:
		raise LauncherError(
			f"Checksum mismatch for {file_path.name} "
			f"(expected {expected_value}, got {actual_value})"
		)
	return format_digest(algorithm, actual_value)


def read_install_metadata(install_dir: Path) -> Optional[dict]:
	metadata_path = install_dir / INSTALL_METADATA_FILE
	if not metadata_path.exists():
		return None
	try:
		data = json.loads(metadata_path.read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError):
		return None
	if not isinstance(data, dict):
		return None
	return data


def write_install_metadata(
		install_dir: Path,
		*,
		version: str,
		exe_name: str,
		digest: str,
) -> None:
	metadata_path = install_dir / INSTALL_METADATA_FILE
	payload = {
		"version": version,
		"exe_name": exe_name,
		"digest": digest,
	}
	metadata_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def determine_primary_executable(install_dir: Path) -> Optional[Path]:
	canonical = install_dir / "Zoro.exe"
	if canonical.exists():
		return canonical
	exe_candidates = sorted(
		[path for path in install_dir.glob("*.exe") if EXE_PATTERN.match(path.name)],
		key=lambda p: (0 if p.name.lower() == "zoro.exe" else 1, p.name.lower()),
	)
	if exe_candidates:
		return exe_candidates[0]
	return None


def ensure_install_metadata_exists(
		install_dir: Path,
		version_hint: Optional[str],
) -> Optional[dict]:
	metadata = read_install_metadata(install_dir)
	if metadata and metadata.get("exe_name") and metadata.get("digest"):
		return metadata
	target = determine_primary_executable(install_dir)
	if target is None or not target.exists():
		return metadata
	digest = format_digest("sha256", compute_file_digest(target))
	version_value = version_hint or read_local_version(install_dir) or ""
	try:
		write_install_metadata(
			install_dir,
			version=version_value,
			exe_name=target.name,
			digest=digest,
		)
	except OSError:
		return metadata
	return read_install_metadata(install_dir)


def verify_installed_payload(
		install_dir: Path,
		metadata: Optional[dict] = None,
) -> Path:
	metadata = metadata or read_install_metadata(install_dir)
	if not metadata:
		raise LauncherError(
			"Installation metadata is missing. Run the launcher without --launch-only to repair the installation."
		)
	exe_name = metadata.get("exe_name")
	digest = metadata.get("digest")
	if not exe_name or not digest:
		raise LauncherError(
			"Installation metadata is incomplete; reinstall or update the client to refresh it."
		)
	target = install_dir / exe_name
	if not target.exists():
		raise LauncherError(f"Metadata references missing executable: {exe_name}")
	ensure_checksum(target, digest)
	return target


def checksum_matches(file_path: Path, digest: str) -> bool:
	try:
		ensure_checksum(file_path, digest)
	except LauncherError:
		return False
	return True


def parse_args(argv: Optional[Iterable[str]] = None) -> tuple[argparse.Namespace, list[str]]:
	parser = argparse.ArgumentParser(
		description=(
			"Zoro bootstrap launcher. Downloads or updates the full client before launching it."
		),
		formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	)
	parser.add_argument("--owner", default=DEFAULT_OWNER, help="GitHub account containing the releases.")
	parser.add_argument("--repo", default=DEFAULT_REPO, help="Repository name containing the release artifacts.")
	parser.add_argument(
		"--channel",
		default=DEFAULT_CHANNEL,
		choices=CHANNEL_CHOICES,
		help="Release channel to track. 'stable' ignores prereleases.",
	)
	parser.add_argument(
		"--install-dir",
		metavar="PATH",
		help=(
			"Directory where Zoro should be installed. "
			"Relative paths are resolved against the launcher binary."
		),
	)
	parser.add_argument("--force-install", action="store_true", help="Always reinstall the latest release.")
	parser.add_argument("-y", "--assume-yes", action="store_true", help="Automatically accept update prompts.")
	parser.add_argument(
		"--install-only",
		action="store_true",
		help="Download/update the client and exit without launching it.",
	)
	parser.add_argument(
		"--launch-only",
		action="store_true",
		help="Skip update checks and immediately launch the existing installation.",
	)
	parser.add_argument(
		"--update-launcher",
		action="store_true",
		help=f"Update the bundled {LAUNCHER_FILENAME} asset alongside the client installation.",
	)
	args, forward_args = parser.parse_known_args(argv)
	if args.install_only and args.launch_only:
		parser.error("--install-only and --launch-only cannot be used together.")
	return args, forward_args


def resolve_base_dir() -> Path:
	if getattr(sys, "frozen", False):
		return Path(sys.executable).resolve().parent
	return Path(__file__).resolve().parent


def resolve_install_path(base_dir: Path, override: Optional[str]) -> Path:
	if override is None:
		return (base_dir / INSTALL_DIR_NAME).resolve()
	override_str = str(override).strip()
	if not override_str:
		return (base_dir / INSTALL_DIR_NAME).resolve()
	requested_path = Path(override_str).expanduser()
	if requested_path.is_absolute():
		return requested_path.resolve()
	return (base_dir / requested_path).resolve()


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


def download_release_asset(asset: dict, destination_dir: Path) -> Path:
	url = asset.get("browser_download_url")
	filename = asset.get("name")
	if not url or not filename:
		raise LauncherError("Release asset is missing download metadata.")

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
		raise LauncherError(f"Failed to download asset (HTTP {exc.code})") from exc
	except URLError as exc:
		raise LauncherError(f"Network error while downloading asset: {exc.reason}") from exc
	except OSError as exc:
		raise LauncherError(f"Could not persist downloaded asset: {exc}") from exc

	return asset_path


def select_release_asset(release: dict, pattern: re.Pattern[str]) -> Optional[dict]:
	assets = release.get("assets") or []
	for asset in assets:
		name = asset.get("name")
		if not name:
			continue
		if pattern.match(name):
			url = asset.get("browser_download_url")
			if not url:
				continue
			return asset
	return None


def update_launcher_executable(base_dir: Path, release: dict, assume_yes: bool) -> None:
	asset = select_release_asset(release, LAUNCHER_PATTERN)
	if asset is None:
		print("[launcher] No Launcher.exe asset found; skipping self-update.")
		return

	target_path = (base_dir / LAUNCHER_FILENAME).resolve()
	expected_digest = asset.get("digest")
	needs_update = not target_path.exists()
	if expected_digest and target_path.exists():
		needs_update = not checksum_matches(target_path, expected_digest)
	elif not expected_digest:
		needs_update = True

	if not needs_update:
		print("[launcher] Launcher.exe is already up to date.")
		return

	if not assume_yes:
		prompt = f"Update launcher binary at {target_path}? [Y/n]: "
		if input(prompt).strip().lower() not in {"", "y", "yes"}:
			print("[launcher] Skipping launcher self-update at user request.")
			return

	print("[launcher] Downloading updated launcher binary...")
	with tempfile.TemporaryDirectory(prefix="zoro-launcher-selfupdate-") as temp_dir_str:
		temp_dir = Path(temp_dir_str)
		asset_path = download_release_asset(asset, temp_dir)
		ensure_checksum(asset_path, asset.get("digest"))

		target_path.parent.mkdir(parents=True, exist_ok=True)
		replacement_path = target_path.with_name(f"{target_path.name}.new")
		shutil.copy2(asset_path, replacement_path)

		try:
			replacement_path.replace(target_path)
		except OSError as exc:
			fallback_path = target_path.with_name(f"{target_path.stem}.updated{target_path.suffix}")
			try:
				fallback_path.unlink(missing_ok=True)
			except OSError:
				pass
			replacement_path.replace(fallback_path)
			raise LauncherError(
				f"Unable to replace {target_path}. "
				f"A new copy was saved to {fallback_path}. Close the running launcher and rename it manually."
			) from exc

	print(f"[launcher] Updated launcher binary at {target_path}")


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
		release: Optional[dict] = None,
) -> tuple[Optional[str], Optional[str]]:
	include_prerelease = channel == "prerelease"
	release_data = release
	if release_data is None:
		release_data = fetch_latest_release(owner, repo, include_prerelease=include_prerelease)
	if release_data is None:
		raise LauncherError("No suitable release was found on GitHub")

	asset = select_release_asset(release_data, EXE_PATTERN)
	if asset is None:
		raise LauncherError("Release does not expose a downloadable executable named Zoro*.exe.")

	remote_version = release_data.get("tag_name") or release_data.get("name") or "latest"
	local_version = read_local_version(install_dir)
	metadata = ensure_install_metadata_exists(install_dir, local_version)
	installed_digest = metadata.get("digest") if metadata else None
	payload_exists = has_existing_payload(install_dir)

	needs_install = force_install or local_version is None or not payload_exists

	if not needs_install and version_key(remote_version) <= version_key(local_version):
		print(f"[launcher] Local version {local_version} is up to date.")

		remote_digest = asset.get("digest")
		if (
				not needs_install
				and remote_digest
				and installed_digest
				and not digests_equal(remote_digest, installed_digest)
		):
			print(
				"[launcher] Remote release hash differs from installed build; reinstalling to ensure integrity."
			)
			needs_install = True
		elif not needs_install and remote_digest and not installed_digest:
			print(
				"[launcher] Installed build lacks checksum metadata; reinstalling to capture official digest."
			)
			needs_install = True
		else:
			return local_version, remote_version

	if not needs_install:
		if assume_yes:
			install_update = True
		else:
			prompt = f"Update available ({local_version or 'unknown'} -> {remote_version}). Download now? [Y/n]: "
			install_update = input(prompt).strip().lower() in {"", "y", "yes"}

		if not install_update:
			print("[launcher] Skipping update at user request.")
			ensure_install_metadata_exists(install_dir, local_version)
			return local_version, remote_version

	print(f"[launcher] Downloading Valorant Zoro {remote_version}...")
	installed_path: Optional[Path] = None
	asset_digest: Optional[str] = None
	with tempfile.TemporaryDirectory(prefix="zoro-launcher-download-") as temp_dir_str:
		temp_dir = Path(temp_dir_str)
		asset_path = download_release_asset(asset, temp_dir)
		asset_digest = ensure_checksum(asset_path, asset.get("digest"))
		try:
			installed_path = install_executable(asset_path, install_dir)
		except OSError as exc:
			raise LauncherError(f"Failed to copy release files: {exc}") from exc

	if installed_path is None:
		installed_path = determine_primary_executable(install_dir)
	if installed_path is None or not installed_path.exists():
		raise LauncherError("Installation succeeded but no executable was found afterward.")

	write_local_version(install_dir, remote_version)
	write_install_metadata(
		install_dir,
		version=remote_version,
		exe_name=installed_path.name,
		digest=asset_digest or format_digest("sha256", compute_file_digest(installed_path)),
	)
	print(f"[launcher] Installed Valorant Zoro {remote_version} at {install_dir}")
	return local_version, remote_version


def has_existing_payload(install_dir: Path) -> bool:
	if not install_dir.exists():
		return False
	return any(EXE_PATTERN.match(path.name) for path in install_dir.glob("*.exe"))


def launch_application(
		install_dir: Path,
		forward_args: Iterable[str],
		preferred_executable: Optional[Path] = None,
) -> int:
	exe_candidates = sorted(
		[path for path in install_dir.glob("*.exe") if EXE_PATTERN.match(path.name)],
		key=lambda p: (0 if p.name.lower() == "zoro.exe" else 1, p.name.lower()),
	)

	if preferred_executable and preferred_executable.exists():
		exe_candidates = [preferred_executable, *[p for p in exe_candidates if p != preferred_executable]]

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
	try:
		install_dir = resolve_install_path(base_dir, args.install_dir)
	except OSError as exc:
		print(f"[launcher] Error while resolving install directory: {exc}")
		return 1

	print(f"[launcher] Using install directory: {install_dir}")
	release: Optional[dict] = None
	try:
		if not args.launch_only or args.update_launcher:
			include_prerelease = args.channel == "prerelease"
			release = fetch_latest_release(
				args.owner,
				args.repo,
				include_prerelease=include_prerelease,
			)
			if release is None:
				raise LauncherError("No suitable release was found on GitHub")

		if args.launch_only:
			print("[launcher] Launch-only mode requested; skipping update step.")
			if not has_existing_payload(install_dir):
				raise LauncherError(
					"Launch-only mode requested but no executable payload was found. "
					"Remove --launch-only or install the client first."
				)
		else:
			ensure_installation(
				owner=args.owner,
				repo=args.repo,
				channel=args.channel,
				install_dir=install_dir,
				force_install=args.force_install,
				assume_yes=args.assume_yes,
				release=release,
			)

		if args.update_launcher:
			if release is None:
				include_prerelease = args.channel == "prerelease"
				release = fetch_latest_release(
					args.owner,
					args.repo,
					include_prerelease=include_prerelease,
				)
				if release is None:
					raise LauncherError("No suitable release was found on GitHub")
			try:
				update_launcher_executable(base_dir, release, args.assume_yes)
			except LauncherError as exc:
				print(f"[launcher] Launcher update warning: {exc}")

		metadata = ensure_install_metadata_exists(install_dir, read_local_version(install_dir))

		if args.install_only:
			print("[launcher] Install-only mode requested; exiting without launching the client.")
			return 0

		preferred_executable = verify_installed_payload(install_dir, metadata)
		return launch_application(install_dir, forward_args, preferred_executable=preferred_executable)
	except LauncherError as exc:
		print(f"[launcher] Error: {exc}")
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
