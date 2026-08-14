#Requires -Modules Pester
# Copyright (c) 2026 Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

BeforeAll {
    . (Join-Path $PSScriptRoot '../../security/Test-DocumentedEnforcement.ps1')

    $script:FixturesPath = Join-Path $PSScriptRoot '../fixtures/documented-enforcement/repo'
    $script:InstructionsPath = Join-Path $script:FixturesPath 'instructions.md'
    $script:WorkflowsPath = Join-Path $script:FixturesPath '.github/workflows'
    $script:PackageJsonPath = Join-Path $script:FixturesPath 'package.json'
    $script:GateWorkflowPath = Join-Path $script:WorkflowsPath 'gate.yml'
    $script:PackageJsonScripts = (Get-Content -Raw -Path $script:PackageJsonPath | ConvertFrom-Json).scripts

    Mock Write-Host {}
}

Describe 'Get-DocumentedEnforcementReference' -Tag 'Unit' {
    BeforeAll {
        $script:References = Get-DocumentedEnforcementReference -InstructionsPath $script:InstructionsPath
    }

    It 'Extracts direct script references from enforcement-triggered blocks' {
        $script:References | Where-Object { $_.Kind -eq 'Script' -and $_.Value -eq 'scripts/security/Test-Fixture.ps1' } | Should -Not -BeNullOrEmpty
    }

    It 'Extracts npm alias references from enforcement-triggered blocks' {
        $script:References | Where-Object { $_.Kind -eq 'Npm' -and $_.Value -eq 'lint:fixture' } | Should -Not -BeNullOrEmpty
    }

    It 'Extracts the same script mentioned twice as two raw references' {
        @($script:References | Where-Object { $_.Kind -eq 'Script' -and $_.Value -eq 'scripts/security/Test-Fixture.ps1' }).Count | Should -Be 2
    }

    It 'Does not extract references from an advisory-only block' {
        $script:References | Where-Object { $_.Value -eq 'scripts/security/Test-Advisory-Fixture.ps1' } | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-DocumentedEnforcementRule' -Tag 'Unit' {
    It 'Resolves a Script reference to itself' {
        $reference = [pscustomobject]@{ Kind = 'Script'; Value = 'scripts/security/Test-Fixture.ps1' }
        $resolved = Resolve-DocumentedEnforcementRule -Reference $reference -PackageJsonScripts $script:PackageJsonScripts
        $resolved.ScriptPath | Should -Be 'scripts/security/Test-Fixture.ps1'
        $resolved.UnresolvedReason | Should -BeNullOrEmpty
    }

    It 'Resolves a defined npm alias to its underlying script path' {
        $reference = [pscustomobject]@{ Kind = 'Npm'; Value = 'lint:fixture' }
        $resolved = Resolve-DocumentedEnforcementRule -Reference $reference -PackageJsonScripts $script:PackageJsonScripts
        $resolved.ScriptPath | Should -Be 'scripts/security/Test-Fixture.ps1'
        $resolved.NpmAlias | Should -Be 'lint:fixture'
    }

    It 'Reports an unresolved reason when the npm alias is undefined' {
        $reference = [pscustomobject]@{ Kind = 'Npm'; Value = 'lint:does-not-exist' }
        $resolved = Resolve-DocumentedEnforcementRule -Reference $reference -PackageJsonScripts $script:PackageJsonScripts
        $resolved.ScriptPath | Should -BeNullOrEmpty
        $resolved.UnresolvedReason | Should -Match 'is not defined in package.json'
    }

    It 'Reports an unresolved reason when the npm alias command has no script path' {
        $reference = [pscustomobject]@{ Kind = 'Npm'; Value = 'lint:no-script' }
        $resolved = Resolve-DocumentedEnforcementRule -Reference $reference -PackageJsonScripts $script:PackageJsonScripts
        $resolved.ScriptPath | Should -BeNullOrEmpty
        $resolved.UnresolvedReason | Should -Match 'no resolvable'
    }
}

Describe 'Get-DocumentedEnforcementRule' -Tag 'Unit' {
    BeforeAll {
        $script:Rules = Get-DocumentedEnforcementRule -InstructionsPaths @($script:InstructionsPath) -PackageJsonPath $script:PackageJsonPath
    }

    It 'Dedupes a script mentioned directly and via npm alias into one rule' {
        $fixtureRules = @($script:Rules | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Fixture.ps1' })
        $fixtureRules.Count | Should -Be 1
        $fixtureRules[0].References.Count | Should -Be 3
    }

    It 'Keeps unresolved npm aliases as distinct rules' {
        @($script:Rules | Where-Object { $_.NpmAlias -eq 'lint:does-not-exist' }).Count | Should -Be 1
        @($script:Rules | Where-Object { $_.NpmAlias -eq 'lint:no-script' }).Count | Should -Be 1
    }

    It 'Excludes advisory-only references entirely' {
        $script:Rules | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Advisory-Fixture.ps1' } | Should -BeNullOrEmpty
    }
}

Describe 'Get-WorkflowDefinition' -Tag 'Unit' {
    BeforeEach {
        $script:Cache = @{}
    }

    It 'Parses a workflow YAML file into a structured object' {
        $definition = Get-WorkflowDefinition -WorkflowPath $script:GateWorkflowPath -Cache $script:Cache
        $definition.jobs.Keys | Should -Contain 'direct-job'
    }

    It 'Caches the parsed definition across repeated calls' {
        Get-WorkflowDefinition -WorkflowPath $script:GateWorkflowPath -Cache $script:Cache | Out-Null
        $script:Cache.ContainsKey($script:GateWorkflowPath) | Should -BeTrue
        $second = Get-WorkflowDefinition -WorkflowPath $script:GateWorkflowPath -Cache $script:Cache
        $second | Should -Be $script:Cache[$script:GateWorkflowPath]
    }

    It 'Returns null for a workflow path that does not exist' {
        $definition = Get-WorkflowDefinition -WorkflowPath (Join-Path $script:WorkflowsPath 'does-not-exist.yml') -Cache $script:Cache
        $definition | Should -BeNullOrEmpty
    }
}

Describe 'Test-StepInvokesTarget' -Tag 'Unit' {
    BeforeAll {
        $script:Cache = @{}
        $script:GateDefinition = Get-WorkflowDefinition -WorkflowPath $script:GateWorkflowPath -Cache $script:Cache
    }

    It 'Returns true when a step run command contains the script path' {
        $job = $script:GateDefinition.jobs['direct-job']
        Test-StepInvokesTarget -Job $job -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null | Should -BeTrue
    }

    It 'Returns true when a step run command matches the npm alias' {
        $job = $script:GateDefinition.jobs['npm-job']
        Test-StepInvokesTarget -Job $job -ScriptPath $null -NpmAlias 'lint:fixture' | Should -BeTrue
    }

    It 'Returns false when no step matches the script path or npm alias' {
        $job = $script:GateDefinition.jobs['direct-job']
        Test-StepInvokesTarget -Job $job -ScriptPath 'scripts/security/Test-NotWired-Fixture.ps1' -NpmAlias $null | Should -BeFalse
    }

    It 'Returns false when the script path only appears in a comment or echo statement' {
        $job = $script:GateDefinition.jobs['echo-only-job']
        Test-StepInvokesTarget -Job $job -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null | Should -BeFalse
    }

    It 'Returns false when the npm alias only appears in an echo statement' {
        $job = $script:GateDefinition.jobs['echo-only-job']
        Test-StepInvokesTarget -Job $job -ScriptPath $null -NpmAlias 'lint:fixture' | Should -BeFalse
    }

    It 'Returns false when the script path only appears in a comment line, with no echo present' {
        $job = $script:GateDefinition.jobs['comment-only-job']
        Test-StepInvokesTarget -Job $job -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null | Should -BeFalse
    }

    It 'Returns false when the npm alias only appears in a comment line, with no echo present' {
        $job = $script:GateDefinition.jobs['comment-only-job']
        Test-StepInvokesTarget -Job $job -ScriptPath $null -NpmAlias 'lint:fixture' | Should -BeFalse
    }

    It 'Returns false when the script path is mentioned only as an argument to an unrelated command' {
        $job = $script:GateDefinition.jobs['argument-only-job']
        Test-StepInvokesTarget -Job $job -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null | Should -BeFalse
    }

    It 'Returns false for a null job' {
        Test-StepInvokesTarget -Job $null -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null | Should -BeFalse
    }

    It 'Returns false for a job with no steps' {
        $jobWithNoSteps = [pscustomobject]@{ steps = $null }
        Test-StepInvokesTarget -Job $jobWithNoSteps -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null | Should -BeFalse
    }
}

Describe 'Find-EnforcementInvocation' -Tag 'Unit' {
    BeforeAll {
        $script:Cache = @{}
        $script:AllWorkflowFiles = @(Get-ChildItem -Path $script:WorkflowsPath -Filter '*.yml' -File | ForEach-Object { $_.FullName })
    }

    It 'Finds a job that invokes the script in any workflow file, including non-gate workflows' {
        $invocations = Find-EnforcementInvocation -WorkflowFiles $script:AllWorkflowFiles -ScriptPath 'scripts/security/Test-Elsewhere-Fixture.ps1' -NpmAlias $null -Cache $script:Cache
        $invocations.Count | Should -Be 1
        $invocations[0].JobId | Should -Be 'elsewhere-job'
    }

    It 'Returns an empty array when no workflow invokes the script' {
        $invocations = Find-EnforcementInvocation -WorkflowFiles $script:AllWorkflowFiles -ScriptPath 'scripts/security/Test-NotWired-Fixture.ps1' -NpmAlias $null -Cache $script:Cache
        $invocations.Count | Should -Be 0
    }
}

Describe 'Find-GatingJob' -Tag 'Unit' {
    BeforeEach {
        $script:Cache = @{}
    }

    It 'Finds a job in the gate workflow that directly invokes the script' {
        $jobs = Find-GatingJob -GateWorkflowPath $script:GateWorkflowPath -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null -Cache $script:Cache -RepoRoot $script:FixturesPath
        $jobs | Should -Contain 'direct-job'
    }

    It 'Attributes a reusable-workflow-chain invocation to the calling job' {
        $jobs = Find-GatingJob -GateWorkflowPath $script:GateWorkflowPath -ScriptPath 'scripts/security/Test-Reusable-Fixture.ps1' -NpmAlias $null -Cache $script:Cache -RepoRoot $script:FixturesPath
        $jobs | Should -Contain 'reusable-caller-job'
    }

    It 'Returns an empty array when no job in the gate workflow reaches the script' {
        $jobs = Find-GatingJob -GateWorkflowPath $script:GateWorkflowPath -ScriptPath 'scripts/security/Test-Elsewhere-Fixture.ps1' -NpmAlias $null -Cache $script:Cache -RepoRoot $script:FixturesPath
        $jobs.Count | Should -Be 0
    }

    It 'Returns an empty array when the gate workflow path does not exist' {
        $jobs = Find-GatingJob -GateWorkflowPath (Join-Path $script:WorkflowsPath 'does-not-exist.yml') -ScriptPath 'scripts/security/Test-Fixture.ps1' -NpmAlias $null -Cache $script:Cache -RepoRoot $script:FixturesPath
        $jobs.Count | Should -Be 0
    }
}

Describe 'Get-GateNeedsList' -Tag 'Unit' {
    BeforeEach {
        $script:Cache = @{}
    }

    It 'Returns the aggregator gate job needs list' {
        $needs = Get-GateNeedsList -GateWorkflowPath $script:GateWorkflowPath -GateJobId 'fixture-gate-success' -Cache $script:Cache
        $needs | Should -Contain 'direct-job'
        $needs | Should -Contain 'reusable-caller-job'
        $needs | Should -Contain 'npm-job'
        $needs | Should -Not -Contain 'notgated-job'
    }

    It 'Returns an empty array when the gate job id does not exist' {
        $needs = Get-GateNeedsList -GateWorkflowPath $script:GateWorkflowPath -GateJobId 'nonexistent-gate' -Cache $script:Cache
        $needs.Count | Should -Be 0
    }
}

Describe 'Get-DocumentedEnforcementResult' -Tag 'Unit' {
    BeforeAll {
        $script:Results = Get-DocumentedEnforcementResult `
            -InstructionsPaths @($script:InstructionsPath) `
            -WorkflowsPath $script:WorkflowsPath `
            -PackageJsonPath $script:PackageJsonPath `
            -GateWorkflowPath $script:GateWorkflowPath `
            -GateJobId 'fixture-gate-success' `
            -RepoRoot $script:FixturesPath
    }

    It 'Passes a script invoked directly by a gated job' {
        $result = $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Fixture.ps1' }
        $result.Status | Should -Be 'Pass'
    }

    It 'Passes a script invoked only via a reusable workflow chain' {
        $result = $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Reusable-Fixture.ps1' }
        $result.Status | Should -Be 'Pass'
    }

    It 'Flags a script invoked by a job absent from the gate needs list' {
        $result = $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-NotGated-Fixture.ps1' }
        $result.Status | Should -Be 'Violation'
        $result.BrokenLink | Should -Be 'not-gated'
    }

    It 'Flags a script invoked only outside the gate workflow' {
        $result = $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Elsewhere-Fixture.ps1' }
        $result.Status | Should -Be 'Violation'
        $result.BrokenLink | Should -Be 'not-wired-into-gate'
    }

    It 'Flags a script that no workflow invokes' {
        $result = $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-NotWired-Fixture.ps1' }
        $result.Status | Should -Be 'Violation'
        $result.BrokenLink | Should -Be 'not-wired'
    }

    It 'Flags a documented script that does not exist on disk' {
        $result = $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Missing-Fixture.ps1' }
        $result.Status | Should -Be 'Violation'
        $result.BrokenLink | Should -Be 'script-missing'
    }

    It 'Flags an undefined npm alias' {
        $result = $script:Results | Where-Object { $_.NpmAlias -eq 'lint:does-not-exist' }
        $result.Status | Should -Be 'Violation'
        $result.BrokenLink | Should -Be 'npm-alias-unresolved'
    }

    It 'Flags an npm alias with no resolvable script path' {
        $result = $script:Results | Where-Object { $_.NpmAlias -eq 'lint:no-script' }
        $result.Status | Should -Be 'Violation'
        $result.BrokenLink | Should -Be 'npm-alias-unresolved'
    }

    It 'Excludes advisory-only references from the result set' {
        $script:Results | Where-Object { $_.ScriptPath -eq 'scripts/security/Test-Advisory-Fixture.ps1' } | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-DocumentedEnforcementCheck' -Tag 'Unit' {
    BeforeEach {
        $script:OutputPath = Join-Path $TestDrive 'documented-enforcement-results.json'
    }

    It 'Returns exit code 1 under FailOnViolation when violations exist' {
        $exitCode = Invoke-DocumentedEnforcementCheck `
            -InstructionsPaths @($script:InstructionsPath) `
            -WorkflowsPath $script:WorkflowsPath `
            -PackageJsonPath $script:PackageJsonPath `
            -GateWorkflowPath $script:GateWorkflowPath `
            -GateJobId 'fixture-gate-success' `
            -OutputPath $script:OutputPath `
            -RepoRoot $script:FixturesPath `
            -FailOnViolation
        $exitCode | Should -Be 1
    }

    It 'Returns exit code 0 in soft-fail mode when violations exist' {
        $exitCode = Invoke-DocumentedEnforcementCheck `
            -InstructionsPaths @($script:InstructionsPath) `
            -WorkflowsPath $script:WorkflowsPath `
            -PackageJsonPath $script:PackageJsonPath `
            -GateWorkflowPath $script:GateWorkflowPath `
            -GateJobId 'fixture-gate-success' `
            -OutputPath $script:OutputPath `
            -RepoRoot $script:FixturesPath
        $exitCode | Should -Be 0
    }

    It 'Writes a JSON results file with the violation count' {
        Invoke-DocumentedEnforcementCheck `
            -InstructionsPaths @($script:InstructionsPath) `
            -WorkflowsPath $script:WorkflowsPath `
            -PackageJsonPath $script:PackageJsonPath `
            -GateWorkflowPath $script:GateWorkflowPath `
            -GateJobId 'fixture-gate-success' `
            -OutputPath $script:OutputPath `
            -RepoRoot $script:FixturesPath | Out-Null

        Test-Path -Path $script:OutputPath | Should -BeTrue
        $json = Get-Content -Raw -Path $script:OutputPath | ConvertFrom-Json
        $json.violationCount | Should -Be 6
        $json.totalRules | Should -Be 8
    }

    It 'Resolves relative path parameters against RepoRoot, not the current working directory' {
        # Regression test: every path parameter used to be passed straight to
        # Get-Content/Test-Path/Get-ChildItem without joining RepoRoot, so a
        # caller invoking from outside the repository with relative paths plus
        # -RepoRoot would inspect the caller's current directory instead of
        # the requested repository.
        $unrelatedDirectory = Join-Path $TestDrive 'unrelated-cwd'
        New-Item -ItemType Directory -Path $unrelatedDirectory -Force | Out-Null

        Push-Location -Path $unrelatedDirectory
        try {
            $exitCode = Invoke-DocumentedEnforcementCheck `
                -InstructionsPaths @('instructions.md') `
                -WorkflowsPath '.github/workflows' `
                -PackageJsonPath 'package.json' `
                -GateWorkflowPath '.github/workflows/gate.yml' `
                -GateJobId 'fixture-gate-success' `
                -OutputPath $script:OutputPath `
                -RepoRoot $script:FixturesPath `
                -FailOnViolation
        }
        finally {
            Pop-Location
        }

        $exitCode | Should -Be 1
        $json = Get-Content -Raw -Path $script:OutputPath | ConvertFrom-Json
        $json.totalRules | Should -Be 8
        $json.violationCount | Should -Be 6
    }

}

Describe 'Test-DocumentedEnforcement against the real repository' -Tag 'Integration' {
    BeforeAll {
        $script:RepoRoot = Join-Path $PSScriptRoot '../../..'
    }

    It 'Passes with zero violations against the current repository state' {
        $outputPath = Join-Path $TestDrive 'real-repo-results.json'
        $exitCode = Invoke-DocumentedEnforcementCheck `
            -InstructionsPaths @(
                (Join-Path $script:RepoRoot '.github/instructions/workflows.instructions.md'),
                (Join-Path $script:RepoRoot '.github/instructions/dependency-feeds.instructions.md'),
                (Join-Path $script:RepoRoot '.github/instructions/skill-security-model.instructions.md')
            ) `
            -WorkflowsPath (Join-Path $script:RepoRoot '.github/workflows') `
            -PackageJsonPath (Join-Path $script:RepoRoot 'package.json') `
            -GateWorkflowPath (Join-Path $script:RepoRoot '.github/workflows/pr-validation.yml') `
            -GateJobId 'pr-validation-success' `
            -OutputPath $outputPath `
            -RepoRoot $script:RepoRoot `
            -FailOnViolation
        $exitCode | Should -Be 0
    }
}
