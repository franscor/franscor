# Releasing the FRANSCOR SDK

Publishing is done by a maintainer, with their own PyPI and npm accounts (two-factor
authentication on). Tokens and passwords never go into this repository or into chat.
Commands below are for Windows PowerShell, run from the repository root.

## 1. Before publishing

- [ ] Version agrees everywhere (`pyproject.toml`, `_version.py`, `package.json`,
      `detect.ts`) and `CHANGELOG.md` has its entry — checked by `tests/test_release.py`.
- [ ] All tests pass, run separately (one OpenTelemetry test clashes when both suites
      share a process):

```powershell
.venv\Scripts\python.exe -m pytest packages\sdk-python\tests -q
.venv\Scripts\python.exe -m pytest tests -q
cd packages\sdk-typescript; npm.cmd test; cd ..\..
```

- [ ] The CI workflow (`.github/workflows/ci.yml`) is green on the commit to release.
- [ ] Repository links are set once the public repository is chosen:
      `[project.urls] Repository` in `pyproject.toml`, `repository` in `package.json`,
      and relative links in the three README files (they do not work on PyPI or npm).

## 2. Python (PyPI)

```powershell
.venv\Scripts\python.exe -m pip install --upgrade build twine
.venv\Scripts\python.exe -m build packages\sdk-python --outdir dist\python
.venv\Scripts\python.exe -m twine check dist\python\*
# Optional rehearsal on TestPyPI (separate account):
.venv\Scripts\python.exe -m twine upload --repository testpypi dist\python\*
# Real upload: twine asks for the API token (username __token__)
.venv\Scripts\python.exe -m twine upload dist\python\*
```

## 3. Node.js (npm)

```powershell
cd packages\sdk-typescript
npm.cmd login
npm.cmd publish --dry-run      # check the file list: dist, README.md, package.json only
npm.cmd publish                # runs the tests first (prepublishOnly); asks for the 2FA code
cd ..\..
```

## 4. After publishing

- [ ] Install from the registries in an empty folder and run a smoke test:
      `pip install franscor==0.2.0` and `npm install franscor@0.2.0`, then
      `franscor detect` in both.
- [ ] Tag the commit: `git tag -a v0.2.0 -m "franscor 0.2.0"` and push the tag.
- [ ] Change the website `/sdk` page status from "In development" to "Available"
      (all 8 languages) — only now that the packages really exist.
- [ ] Set the date of the release in `CHANGELOG.md`.

A published version can never be replaced on PyPI or npm: fix mistakes with a new
version number.
