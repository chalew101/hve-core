#!/usr/bin/env pwsh
# Copyright (c) 2026 Microsoft Corporation. All rights reserved.
# SPDX-License-Identifier: MIT

#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'PowerShell-Yaml'; RequiredVersion = '0.4.7' }

<#
.SYNOPSIS
    Validates that MUST-level enforcement rules documented in security-relevant
    instructions files are actually wired into CI and gated by the PR validation gate.

.DESCRIPTION
    Cross-references documented enforcement script references in security-relevant
    instructions files against real CI wiring so a rule can never again be
    documented without something checking it. For each configured instructions
    file, this script:

      1. Extracts documented enforcement references: backtick-quoted
         'scripts/**/*.ps1' paths and backtick-quoted 'npm run <alias>'
         commands, scoped to Markdown sections whose body text asserts
         enforcement (containing 'enforc' or 'must pass'). A script mentioned
         only in an advisory or scheduled-only context elsewhere in the same
         file is not treated as a rule requiring gate membership.
      2. Resolves each 'npm run <alias>' reference to its underlying script via
         'package.json', flagging an unresolvable alias as a violation.
      3. Verifies the resolved script file exists on disk.
      4. Verifies the script is actually invoked by a job in a
         '.github/workflows/*.yml' file, either directly or through a job that
         calls a local reusable workflow ('uses: ./.github/workflows/<file>.yml')
         whose steps invoke the script.
      5. Verifies that invoking job (or, for a reusable-workflow call, the
         calling job in the gate workflow) is a member of the gate workflow's
         aggregator job (default 'pr-validation-success') 'needs:' list.

    Each rule resolves to exactly one of: 'script-missing' (the file does not
    exist), 'npm-alias-unresolved' (the npm script name is not defined, or its
    command has no resolvable script path), 'not-wired' (no workflow job
    anywhere invokes the script), 'not-gated' (the script is invoked, but the
    invoking job never reaches the gate workflow's aggregator 'needs:' list), or
    'pass'.

    Results are emitted as a JSON object under logs/ and a human-readable summary
    is written to the console. With -FailOnViolation, the script exits 1 and
    names the offending instructions file, rule, and broken link in the chain
    when any violation is detected; otherwise it exits 0.

.PARAMETER InstructionsPaths
    Instructions files to scan for documented enforcement references. Defaults
    to the three security-relevant instructions files named by the initiative:
    'workflows.instructions.md', 'dependency-feeds.instructions.md', and
    'skill-security-model.instructions.md'.

.PARAMETER WorkflowsPath
    Directory containing GitHub Actions workflow YAML files. Defaults to
    '.github/workflows'.

.PARAMETER PackageJsonPath
    Path to 'package.json', used to resolve 'npm run <alias>' references to
    their underlying script command. Defaults to 'package.json'.

.PARAMETER GateWorkflowPath
    Path to the workflow file whose aggregator job gates merge. Defaults to
    '.github/workflows/pr-validation.yml'.

.PARAMETER GateJobId
    Job ID of the aggregator gate that must depend on every job that enforces a
    documented rule. Defaults to 'pr-validation-success'.

.PARAMETER OutputPath
    Path for the JSON results file. Defaults to
    'logs/documented-enforcement-results.json'.

.PARAMETER RepoRoot
    Repository root that documented script paths and 'uses: ./...' local
    reusable workflow paths are resolved against. Defaults to '.'.

.PARAMETER FailOnViolation
    When set, exits with a non-zero code if any rule resolves to a broken link
    in the documentation-to-enforcement chain.

.EXAMPLE
    ./scripts/security/Test-DocumentedEnforcement.ps1

.EXAMPLE
    ./scripts/security/Test-DocumentedEnforcement.ps1 -FailOnViolation

.NOTES
    Part of the HVE Core security validation suite. Generalizes the pattern that
    led to 'scripts/security/Test-WorkflowRunner.ps1': a MUST rule documented in
    an instructions file with no automated check until a gap was found manually.

.LINK
    https://github.com/microsoft/hve-core
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$InstructionsPaths = @(
        '.github/instructions/workflows.instructions.md',
        '.github/instructions/dependency-feeds.instructions.md',
        '.github/instructions/skill-security-model.instructions.md'
    ),

    [Parameter(Mandatory = $false)]
    [string]$WorkflowsPath = '.github/workflows',

    [Parameter(Mandatory = $false)]
    [string]$PackageJsonPath = 'package.json',

    [Parameter(Mandatory = $false)]
    [string]$GateWorkflowPath = '.github/workflows/pr-validation.yml',

    [Parameter(Mandatory = $false)]
    [string]$GateJobId = 'pr-validation-success',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = 'logs/documented-enforcement-results.json',

    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = '.',

    [Parameter(Mandatory = $false)]
    [switch]$FailOnViolation
)

$ErrorActionPreference = 'Stop'

Import-Module powershell-yaml -ErrorAction Stop

#region Functions

function Get-DocumentedEnforcementReference {
    <#
    .SYNOPSIS
        Extracts documented enforcement references from an instructions file.

    .DESCRIPTION
        Splits the raw Markdown text into blank-line-delimited blocks (a
        paragraph or a contiguous bullet list), keeping only blocks whose text
        asserts enforcement (containing 'enforc' or 'must pass',
        case-insensitive, e.g. '**Enforcement:**', 'CI enforces', 'must
        pass'). A bullet list block that itself carries no such wording
        inherits enforcement scope from an immediately preceding intro block
        that both asserts enforcement and ends with ':' (for example, "The
        following scripts enforce compliance ...:" followed by the list it
        introduces). Within qualifying blocks, extracts backtick-quoted
        'scripts/**/*.ps1' paths and backtick-quoted 'npm run <alias>'
        commands. Block-level scoping keeps a script mentioned only in an
        adjacent advisory or scheduled-only paragraph from being treated as a
        rule requiring gate membership. Returns one record per distinct raw
        reference, preserving duplicates so callers can dedupe.

    .PARAMETER InstructionsPath
        Path to the instructions Markdown file to scan.

    .OUTPUTS
        [pscustomobject[]] with Kind ('Script' or 'Npm') and Value properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstructionsPath
    )

    $content = Get-Content -Raw -Path $InstructionsPath

    # Split into blank-line-delimited blocks. Each block is either a
    # paragraph or a contiguous bullet list (no blank lines between items).
    $blocks = [regex]::Split($content, "(?:\r?\n){2,}")

    $references = [System.Collections.Generic.List[pscustomobject]]::new()

    for ($i = 0; $i -lt $blocks.Count; $i++) {
        $block = $blocks[$i]
        $isTriggered = $block -match '(?i)enforc|must pass'

        if (-not $isTriggered -and $i -gt 0 -and $block -match '(?m)^\s*[*-]\s+') {
            $previous = $blocks[$i - 1]
            if ($previous -match '(?i)enforc|must pass' -and $previous.TrimEnd() -match ':$') {
                $isTriggered = $true
            }
        }

        if (-not $isTriggered) {
            continue
        }

        foreach ($match in [regex]::Matches($block, '`(scripts/[^`\s]+\.ps1)`')) {
            $references.Add([pscustomobject]@{ Kind = 'Script'; Value = $match.Groups[1].Value })
        }

        foreach ($match in [regex]::Matches($block, '`npm run ([a-zA-Z0-9:_-]+)`')) {
            $references.Add([pscustomobject]@{ Kind = 'Npm'; Value = $match.Groups[1].Value })
        }
    }

    return $references.ToArray()
}

function Resolve-DocumentedEnforcementRule {
    <#
    .SYNOPSIS
        Resolves a documented reference to a canonical script path.

    .DESCRIPTION
        A 'Script' reference resolves to itself. An 'Npm' reference resolves by
        looking up the alias in the package.json 'scripts' map and extracting a
        'scripts/**/*.ps1' path from the underlying command. An npm alias that
        is undefined, or whose command has no resolvable script path, resolves
        to $null with an explanatory reason.

    .PARAMETER Reference
        A reference record produced by Get-DocumentedEnforcementReference.

    .PARAMETER PackageJsonScripts
        The 'scripts' map from package.json (property bag of name -> command).

    .OUTPUTS
        [pscustomobject] with ScriptPath (string or $null), NpmAlias (string or
        $null), and UnresolvedReason (string or $null) properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Reference,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$PackageJsonScripts
    )

    if ($Reference.Kind -eq 'Script') {
        return [pscustomobject]@{
            ScriptPath       = $Reference.Value.TrimStart('.', '/')
            NpmAlias         = $null
            UnresolvedReason = $null
        }
    }

    $alias = $Reference.Value
    $command = $null
    if ($null -ne $PackageJsonScripts -and $PackageJsonScripts.PSObject.Properties.Name -contains $alias) {
        $command = $PackageJsonScripts.$alias
    }

    if ($null -eq $command) {
        return [pscustomobject]@{
            ScriptPath       = $null
            NpmAlias         = $alias
            UnresolvedReason = "npm script '$alias' is not defined in package.json"
        }
    }

    $scriptMatch = [regex]::Match($command, 'scripts/\S+\.ps1')
    if (-not $scriptMatch.Success) {
        return [pscustomobject]@{
            ScriptPath       = $null
            NpmAlias         = $alias
            UnresolvedReason = "npm script '$alias' has no resolvable scripts/**/*.ps1 path in its command"
        }
    }

    return [pscustomobject]@{
        ScriptPath       = $scriptMatch.Value.TrimStart('.', '/')
        NpmAlias         = $alias
        UnresolvedReason = $null
    }
}

function Get-DocumentedEnforcementRule {
    <#
    .SYNOPSIS
        Builds the deduplicated list of documented enforcement rules per file.

    .DESCRIPTION
        Extracts and resolves every documented reference in each instructions
        file, then dedupes by resolved script path (or by npm alias when the
        script path could not be resolved) so a rule mentioned multiple times
        in the same file is reported once.

    .PARAMETER InstructionsPaths
        Instructions files to scan.

    .PARAMETER PackageJsonPath
        Path to package.json.

    .OUTPUTS
        [pscustomobject[]] with InstructionsFile, ScriptPath, NpmAlias,
        UnresolvedReason, and References (raw backtick strings) properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InstructionsPaths,

        [Parameter(Mandatory = $true)]
        [string]$PackageJsonPath
    )

    $packageJsonScripts = $null
    if (Test-Path -Path $PackageJsonPath) {
        $packageJson = Get-Content -Raw -Path $PackageJsonPath | ConvertFrom-Json
        $packageJsonScripts = $packageJson.scripts
    }

    $rules = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($instructionsPath in $InstructionsPaths) {
        if (-not (Test-Path -Path $instructionsPath)) {
            throw "Instructions file not found: $instructionsPath"
        }

        $references = Get-DocumentedEnforcementReference -InstructionsPath $instructionsPath
        $seen = [System.Collections.Generic.Dictionary[string, pscustomobject]]::new()

        foreach ($reference in $references) {
            $resolved = Resolve-DocumentedEnforcementRule -Reference $reference -PackageJsonScripts $packageJsonScripts
            $rawText = if ($reference.Kind -eq 'Script') { $reference.Value } else { "npm run $($reference.Value)" }
            $dedupeKey = if ($resolved.ScriptPath) { $resolved.ScriptPath } else { "npm:$($resolved.NpmAlias)" }

            if ($seen.ContainsKey($dedupeKey)) {
                $seen[$dedupeKey].References.Add($rawText) | Out-Null
                continue
            }

            $rule = [pscustomobject]@{
                InstructionsFile = $instructionsPath
                ScriptPath       = $resolved.ScriptPath
                NpmAlias         = $resolved.NpmAlias
                UnresolvedReason = $resolved.UnresolvedReason
                References       = [System.Collections.Generic.List[string]]::new()
            }
            $rule.References.Add($rawText) | Out-Null
            $seen[$dedupeKey] = $rule
        }

        foreach ($rule in $seen.Values) {
            $rules.Add($rule) | Out-Null
        }
    }

    return $rules.ToArray()
}

function Get-WorkflowDefinition {
    <#
    .SYNOPSIS
        Parses a workflow YAML file, caching results across repeated lookups.

    .PARAMETER WorkflowPath
        Path to the workflow YAML file to parse.

    .PARAMETER Cache
        A hashtable used to memoize parsed workflow definitions across calls.

    .OUTPUTS
        [object] The parsed workflow object, or $null if the file does not exist.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkflowPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )

    if ($Cache.ContainsKey($WorkflowPath)) {
        return $Cache[$WorkflowPath]
    }

    $definition = if (Test-Path -Path $WorkflowPath) {
        Get-Content -Raw -Path $WorkflowPath | ConvertFrom-Yaml
    }
    else {
        $null
    }

    $Cache[$WorkflowPath] = $definition
    return $definition
}

function Test-StepInvokesTarget {
    <#
    .SYNOPSIS
        Checks whether a job's steps invoke a script path or npm alias.

    .PARAMETER Job
        A parsed workflow job object.

    .PARAMETER ScriptPath
        The normalized script path (no leading './') to search for.

    .PARAMETER NpmAlias
        Optional npm script alias to also search for as 'npm run <alias>'.

    .OUTPUTS
        [bool] Whether any step's 'run:' text references the script or alias.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Job,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$NpmAlias
    )

    if ($null -eq $Job -or $null -eq $Job.steps) {
        return $false
    }

    foreach ($step in @($Job.steps)) {
        if ($null -eq $step -or $null -eq $step.run -or $step.run -isnot [string]) {
            continue
        }

        if ($ScriptPath -and $step.run.Contains($ScriptPath)) {
            return $true
        }

        if ($NpmAlias -and $step.run -match "npm run $([regex]::Escape($NpmAlias))(\s|$)") {
            return $true
        }
    }

    return $false
}

function Find-EnforcementInvocation {
    <#
    .SYNOPSIS
        Finds every workflow job across the repository that invokes a script.

    .DESCRIPTION
        Scans every workflow file's own jobs directly. This is used for
        diagnostics when a script is invoked somewhere in CI but not reachable
        from the gate workflow, so the failure message can name where it is
        actually wired.

    .PARAMETER WorkflowFiles
        All workflow YAML file paths to scan.

    .PARAMETER ScriptPath
        The normalized script path to search for.

    .PARAMETER NpmAlias
        Optional npm script alias to also search for.

    .PARAMETER Cache
        Workflow-definition memoization cache.

    .OUTPUTS
        [pscustomobject[]] with WorkflowFile and JobId properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$WorkflowFiles,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$NpmAlias,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )

    $invocationMatches = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($workflowFile in $WorkflowFiles) {
        $definition = Get-WorkflowDefinition -WorkflowPath $workflowFile -Cache $Cache
        if ($null -eq $definition -or $null -eq $definition.jobs) {
            continue
        }

        foreach ($jobId in @($definition.jobs.Keys)) {
            if (Test-StepInvokesTarget -Job $definition.jobs[$jobId] -ScriptPath $ScriptPath -NpmAlias $NpmAlias) {
                $invocationMatches.Add([pscustomobject]@{ WorkflowFile = $workflowFile; JobId = $jobId }) | Out-Null
            }
        }
    }

    return $invocationMatches.ToArray()
}

function Find-GatingJob {
    <#
    .SYNOPSIS
        Finds the gate workflow job(s) that reach a script's enforcement.

    .DESCRIPTION
        Checks the gate workflow's own jobs directly, then checks every job
        that calls a local reusable workflow ('uses: ./.github/workflows/*.yml')
        for whether any job inside the called workflow invokes the script. A
        reusable-workflow match is attributed to the calling job in the gate
        workflow, since that is the job the gate's 'needs:' list must depend on.

    .PARAMETER GateWorkflowPath
        Path to the gate workflow file.

    .PARAMETER ScriptPath
        The normalized script path to search for.

    .PARAMETER NpmAlias
        Optional npm script alias to also search for.

    .PARAMETER Cache
        Workflow-definition memoization cache.

    .PARAMETER RepoRoot
        Repository root that 'uses: ./...' local reusable workflow paths are
        resolved against. Defaults to '.'.

    .OUTPUTS
        [string[]] Distinct job IDs, in the gate workflow, that reach the script.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GateWorkflowPath,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$NpmAlias,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = '.'
    )

    $definition = Get-WorkflowDefinition -WorkflowPath $GateWorkflowPath -Cache $Cache
    if ($null -eq $definition -or $null -eq $definition.jobs) {
        return @()
    }

    $candidates = [System.Collections.Generic.List[string]]::new()

    foreach ($jobId in @($definition.jobs.Keys)) {
        $job = $definition.jobs[$jobId]

        if (Test-StepInvokesTarget -Job $job -ScriptPath $ScriptPath -NpmAlias $NpmAlias) {
            $candidates.Add($jobId) | Out-Null
            continue
        }

        if ($job.uses -is [string] -and $job.uses.StartsWith('./')) {
            # 'uses: ./...' in GitHub Actions is repo-root relative, not relative
            # to the calling workflow file's own directory.
            $targetPath = Join-Path -Path $RepoRoot -ChildPath $job.uses.Substring(2)
            $targetDefinition = Get-WorkflowDefinition -WorkflowPath $targetPath -Cache $Cache
            if ($null -eq $targetDefinition -or $null -eq $targetDefinition.jobs) {
                continue
            }

            foreach ($targetJobId in @($targetDefinition.jobs.Keys)) {
                if (Test-StepInvokesTarget -Job $targetDefinition.jobs[$targetJobId] -ScriptPath $ScriptPath -NpmAlias $NpmAlias) {
                    $candidates.Add($jobId) | Out-Null
                    break
                }
            }
        }
    }

    return @($candidates | Select-Object -Unique)
}

function Get-GateNeedsList {
    <#
    .SYNOPSIS
        Returns the aggregator gate job's 'needs:' list.

    .PARAMETER GateWorkflowPath
        Path to the gate workflow file.

    .PARAMETER GateJobId
        Job ID of the aggregator gate.

    .PARAMETER Cache
        Workflow-definition memoization cache.

    .OUTPUTS
        [string[]] The gate job's 'needs:' entries, or an empty array if the
        gate job is absent or declares no 'needs:'.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GateWorkflowPath,

        [Parameter(Mandatory = $true)]
        [string]$GateJobId,

        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )

    $definition = Get-WorkflowDefinition -WorkflowPath $GateWorkflowPath -Cache $Cache
    if ($null -eq $definition -or $null -eq $definition.jobs -or -not $definition.jobs.ContainsKey($GateJobId)) {
        return @()
    }

    $gateJob = $definition.jobs[$GateJobId]
    return @($gateJob.needs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Get-DocumentedEnforcementResult {
    <#
    .SYNOPSIS
        Computes the enforcement-chain verdict for every documented rule.

    .DESCRIPTION
        For each documented rule, walks the chain: script exists -> script is
        invoked by a workflow job -> that job (or its reusable-workflow caller)
        is a member of the gate's 'needs:' list. Reports the first broken link.

    .PARAMETER InstructionsPaths
        Instructions files to scan for documented enforcement references.

    .PARAMETER WorkflowsPath
        Directory containing workflow YAML files.

    .PARAMETER PackageJsonPath
        Path to package.json.

    .PARAMETER GateWorkflowPath
        Path to the gate workflow file.

    .PARAMETER GateJobId
        Job ID of the aggregator gate.

    .PARAMETER RepoRoot
        Repository root that documented script paths and 'uses: ./...' local
        reusable workflow paths are resolved against. Defaults to '.'.

    .OUTPUTS
        [pscustomobject[]] with InstructionsFile, References, ScriptPath,
        NpmAlias, Status ('Pass' or 'Violation'), BrokenLink, and Detail
        properties.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InstructionsPaths,

        [Parameter(Mandatory = $true)]
        [string]$WorkflowsPath,

        [Parameter(Mandatory = $true)]
        [string]$PackageJsonPath,

        [Parameter(Mandatory = $true)]
        [string]$GateWorkflowPath,

        [Parameter(Mandatory = $true)]
        [string]$GateJobId,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = '.'
    )

    $rules = Get-DocumentedEnforcementRule -InstructionsPaths $InstructionsPaths -PackageJsonPath $PackageJsonPath

    $workflowFiles = @()
    if (Test-Path -Path $WorkflowsPath) {
        $workflowFiles = @(Get-ChildItem -Path $WorkflowsPath -Filter '*.yml' -File | ForEach-Object { $_.FullName -replace [regex]::Escape((Get-Location).Path + [System.IO.Path]::DirectorySeparatorChar), '' })
    }

    $cache = @{}
    $needsList = Get-GateNeedsList -GateWorkflowPath $GateWorkflowPath -GateJobId $GateJobId -Cache $cache

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($rule in $rules) {
        $status = 'Pass'
        $brokenLink = $null
        $detail = $null

        if ($rule.UnresolvedReason) {
            $status = 'Violation'
            $brokenLink = 'npm-alias-unresolved'
            $detail = $rule.UnresolvedReason
        }
        elseif (-not (Test-Path -Path (Join-Path -Path $RepoRoot -ChildPath $rule.ScriptPath))) {
            $status = 'Violation'
            $brokenLink = 'script-missing'
            $detail = "Script file does not exist: $($rule.ScriptPath)"
        }
        else {
            $gatingJobs = Find-GatingJob -GateWorkflowPath $GateWorkflowPath -ScriptPath $rule.ScriptPath -NpmAlias $rule.NpmAlias -Cache $cache -RepoRoot $RepoRoot
            $gatedJobs = @($gatingJobs | Where-Object { $_ -in $needsList })

            if ($gatedJobs.Count -gt 0) {
                $status = 'Pass'
            }
            elseif ($gatingJobs.Count -gt 0) {
                $status = 'Violation'
                $brokenLink = 'not-gated'
                $detail = "Invoked by job(s) '$($gatingJobs -join ', ')' in $GateWorkflowPath, but none appear in '$GateJobId' needs list"
            }
            else {
                $anywhere = Find-EnforcementInvocation -WorkflowFiles $workflowFiles -ScriptPath $rule.ScriptPath -NpmAlias $rule.NpmAlias -Cache $cache
                $status = 'Violation'
                if ($anywhere.Count -gt 0) {
                    $brokenLink = 'not-wired-into-gate'
                    $locations = ($anywhere | ForEach-Object { "$($_.WorkflowFile):$($_.JobId)" }) -join ', '
                    $detail = "Invoked only outside $GateWorkflowPath (in: $locations); not reachable from the gate workflow"
                }
                else {
                    $brokenLink = 'not-wired'
                    $detail = "No job in any '$WorkflowsPath/*.yml' file invokes this script"
                }
            }
        }

        $results.Add([pscustomobject]@{
                InstructionsFile = $rule.InstructionsFile
                References       = $rule.References.ToArray()
                ScriptPath       = $rule.ScriptPath
                NpmAlias         = $rule.NpmAlias
                Status           = $status
                BrokenLink       = $brokenLink
                Detail           = $detail
            }) | Out-Null
    }

    return $results.ToArray()
}

function Invoke-DocumentedEnforcementCheck {
    <#
    .SYNOPSIS
        Orchestrates the documented-enforcement validation.

    .DESCRIPTION
        Computes enforcement-chain results for every documented rule, writes a
        JSON results object to the output path, prints a human-readable
        summary, and returns an exit code.

    .PARAMETER InstructionsPaths
        Instructions files to scan for documented enforcement references.

    .PARAMETER WorkflowsPath
        Directory containing workflow YAML files.

    .PARAMETER PackageJsonPath
        Path to package.json.

    .PARAMETER GateWorkflowPath
        Path to the gate workflow file.

    .PARAMETER GateJobId
        Job ID of the aggregator gate.

    .PARAMETER OutputPath
        Path for the JSON results file.

    .PARAMETER RepoRoot
        Repository root that documented script paths and 'uses: ./...' local
        reusable workflow paths are resolved against. Defaults to '.'.

    .PARAMETER FailOnViolation
        When set, returns 1 if any rule resolves to a broken link.

    .OUTPUTS
        [int] Exit code: 0 when clean (or soft-fail mode), 1 on violations.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$InstructionsPaths = @(
            '.github/instructions/workflows.instructions.md',
            '.github/instructions/dependency-feeds.instructions.md',
            '.github/instructions/skill-security-model.instructions.md'
        ),

        [Parameter(Mandatory = $false)]
        [string]$WorkflowsPath = '.github/workflows',

        [Parameter(Mandatory = $false)]
        [string]$PackageJsonPath = 'package.json',

        [Parameter(Mandatory = $false)]
        [string]$GateWorkflowPath = '.github/workflows/pr-validation.yml',

        [Parameter(Mandatory = $false)]
        [string]$GateJobId = 'pr-validation-success',

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = 'logs/documented-enforcement-results.json',

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = '.',

        [Parameter(Mandatory = $false)]
        [switch]$FailOnViolation
    )

    Write-Host "🔍 Validating documented enforcement rules against CI wiring" -ForegroundColor Cyan
    Write-Host "   Instructions: $($InstructionsPaths -join ', ')" -ForegroundColor Gray
    Write-Host "   Gate workflow: $GateWorkflowPath ($GateJobId)" -ForegroundColor Gray

    $results = Get-DocumentedEnforcementResult `
        -InstructionsPaths $InstructionsPaths `
        -WorkflowsPath $WorkflowsPath `
        -PackageJsonPath $PackageJsonPath `
        -GateWorkflowPath $GateWorkflowPath `
        -GateJobId $GateJobId `
        -RepoRoot $RepoRoot

    $violations = @($results | Where-Object { $_.Status -eq 'Violation' })

    $resultObject = [ordered]@{
        instructionsPaths = $InstructionsPaths
        gateWorkflowPath  = $GateWorkflowPath
        gateJobId         = $GateJobId
        totalRules        = $results.Count
        violationCount    = $violations.Count
        rules             = $results
        timestamp         = (Get-Date).ToUniversalTime().ToString('o')
    }

    $outputDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    if ($outputDir -and -not (Test-Path -Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    $resultObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Host "   Results written to: $OutputPath" -ForegroundColor Gray

    if ($results.Count -eq 0) {
        Write-Host "⚠️  No documented enforcement references were found." -ForegroundColor Yellow
    }

    if ($violations.Count -eq 0) {
        Write-Host "✅ All $($results.Count) documented enforcement rule(s) are wired and gated." -ForegroundColor Green
        return 0
    }

    Write-Host "❌ $($violations.Count) documented-enforcement violation(s) found:" -ForegroundColor Red
    foreach ($violation in $violations) {
        $reference = $violation.References -join ', '
        Write-Host "   - [$($violation.InstructionsFile)] rule '$reference' -> $($violation.BrokenLink): $($violation.Detail)" -ForegroundColor Red
    }

    if ($FailOnViolation) {
        Write-Host "❌ Failing due to documented-enforcement violation(s)." -ForegroundColor Red
        return 1
    }

    Write-Host "⚠️  Violation(s) found - soft fail mode." -ForegroundColor Yellow
    return 0
}

#endregion Functions

#region Main Execution

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $params = @{
            WorkflowsPath    = $WorkflowsPath
            PackageJsonPath  = $PackageJsonPath
            GateWorkflowPath = $GateWorkflowPath
            GateJobId        = $GateJobId
            OutputPath       = $OutputPath
            RepoRoot         = $RepoRoot
            FailOnViolation  = $FailOnViolation
        }
        $params['InstructionsPaths'] = $InstructionsPaths

        $exitCode = Invoke-DocumentedEnforcementCheck @params
        exit $exitCode
    }
    catch {
        Write-Host "❌ Fatal error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        exit 1
    }
}

#endregion Main Execution
