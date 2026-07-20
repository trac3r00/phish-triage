# Release and merge policy

This document defines the repository's merge and release requirements. A passing test run is necessary but does not replace review of scope, documentation, and release impact.

## Current release surfaces

- Package version: `project.version` in `pyproject.toml`.
- Runtime version output: `__version__` in `src/phish_triage/__init__.py`.
- Distribution build backend: setuptools.
- Automated CI or release workflow: none currently present.
- Changelog: none currently present.

Keep the two version declarations synchronized until the project adopts a single version source.

## Merge gates

A pull request is ready to merge only when all applicable conditions are met:

1. The pull request has one coherent purpose and does not mix unrelated refactoring.
2. The description explains the reason for the change, links relevant issues, and includes verification evidence.
3. `pytest` passes on the exact commit being reviewed after installing `.[dev,web]`.
4. User-facing behavior and documentation agree.
5. Interface or route changes have direct usage evidence in addition to automated tests.
6. Security-related failures are resolved rather than waived.
7. Version, migration, rollback, and release-note impact are explicitly assessed.

If CI is added later, required checks must pass on the current commit. Until then, local command output is the available test evidence.

## Branch and commit policy

- Do not push directly to `main`; use a pull request.
- Use one branch per task with a descriptive prefix such as `feat/`, `fix/`, `docs/`, `test/`, `refactor/`, or `chore/`.
- Use Conventional Commit subjects.
- Do not force-push without explicit approval.
- Do not commit credentials, local environment files, caches, or generated build artifacts.
- Write pull request, issue, review, commit, and release text in English.

## Versioning

The project follows Semantic Versioning:

- patch: backward-compatible defect or documentation correction;
- minor: backward-compatible user-facing functionality;
- major: incompatible public behavior, interface, or data-format change.

A documentation-only change normally has no version impact unless it corrects documentation packaged in an imminent release and the maintainer chooses to issue a patch.

## Release checklist

Before creating a release:

1. Confirm the target commit contains the intended changes and no unrelated files.
2. Update both version declarations.
3. Prepare concise user-facing release notes. If a changelog is introduced, update it in the same pull request.
4. Install development and web dependencies and run the tests:

   ```bash
   python -m pip install -e ".[dev,web]"
   pytest
   ```

5. Build the source distribution and wheel with an independently installed PEP 517 frontend, then inspect the artifacts. The project does not currently declare `build` as a dependency.
6. Verify `phish-triage --version`, parser output, enrichment without keys, and the local web health endpoint from the built artifact or an equivalent clean environment.
7. Tag the exact reviewed commit as `vX.Y.Z` and publish notes that match that tag.

Do not describe a release as CI-verified while the repository has no CI workflow.

## Hotfixes and rollback

Use a `hotfix/<name>` branch for urgent defects. Keep the change minimal, run the same applicable gates, and issue a patch release when users need the correction immediately.

Prefer a pull request containing `git revert` to roll back a merged change. This preserves history and allows the normal verification path to run. A release tag can identify a known version, but it does not replace a reviewed rollback commit.
