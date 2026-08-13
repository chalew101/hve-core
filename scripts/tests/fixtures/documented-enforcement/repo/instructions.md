---
description: "Fixture instructions for Test-DocumentedEnforcement.ps1 tests"
---

# Fixture Instructions

## Direct Script Rule

**Enforcement:** Violations are detected by `scripts/security/Test-Fixture.ps1`.

## Reusable Workflow Rule

**Enforcement:** Violations are detected by `scripts/security/Test-Reusable-Fixture.ps1`.

## Not Gated Rule

**Enforcement:** Violations are detected by `scripts/security/Test-NotGated-Fixture.ps1`.

## Not Wired Into Gate Rule

**Enforcement:** Violations are detected by `scripts/security/Test-Elsewhere-Fixture.ps1`.

## Not Wired At All Rule

**Enforcement:** Violations are detected by `scripts/security/Test-NotWired-Fixture.ps1`.

## Missing Script Rule

**Enforcement:** Violations are detected by `scripts/security/Test-Missing-Fixture.ps1`.

## Npm Alias Rule

**Enforcement:** Run `npm run lint:fixture` before merging.

## Unresolved Npm Alias Rule

**Enforcement:** Run `npm run lint:does-not-exist` before merging.

## No Script Path In Npm Command Rule

**Enforcement:** Run `npm run lint:no-script` before merging.

## Enforcement Statement

The following scripts enforce compliance:

* `scripts/security/Test-Fixture.ps1` - dedupe check

## Advisory Note

This script is monitored weekly and is not part of the blocking gate.

**Monitoring:** `scripts/security/Test-Advisory-Fixture.ps1` flags issues but does not block merge.
