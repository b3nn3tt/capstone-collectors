<#
.SYNOPSIS
    Pester tests for the Voight-Kampff runner and build-source invocation contract.

.DESCRIPTION
    These tests are STATIC. They parse the runner and the standalone build
    template with the PowerShell AST parser and assert on their structure.

    Nothing here executes the collector, dot-sources a module, or touches live
    host configuration. Parsing a file does not run it.

    Covers:
    - Host.NetworkConfig is invoked exactly once by the runner
    - Host.NetworkConfig is emitted exactly once by the build source
    - no host module is invoked more than once by either
    - the runner and the build source agree on host module order

.NOTES
    Tranche 1. Run with Pester v5. See tests/README.md for the command.
#>

BeforeAll {

    $script:AgentRoot    = Split-Path -Parent $PSScriptRoot
    $script:RunnerPath   = Join-Path $script:AgentRoot 'core\Invoke-VKScan.ps1'
    $script:BuildPath    = Join-Path $script:AgentRoot 'build\Build-Standalone.ps1'

    function Get-VKAst {
        param([Parameter(Mandatory)][string]$Path)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

        if ($errors -and $errors.Count -gt 0) {
            throw "Parse errors in '$Path': $($errors | ForEach-Object { $_.Message } | Select-Object -First 3)"
        }

        return $ast
    }

    # All command invocations in a file, by resolved command name.
    function Get-VKCommandNames {
        param([Parameter(Mandatory)]$Ast)

        $commands = $Ast.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.CommandAst] },
            $true
        )

        return @($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    }

    # The string elements of a named array-literal assignment, e.g. $hostModuleFiles = @( 'a.ps1', 'b.ps1' )
    function Get-VKArrayAssignment {
        param(
            [Parameter(Mandatory)]$Ast,
            [Parameter(Mandatory)][string]$VariableName
        )

        $assignment = $Ast.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq $VariableName
            },
            $true
        ) | Select-Object -First 1

        if (-not $assignment) {
            throw "Could not locate an assignment to `$$VariableName."
        }

        $strings = $assignment.Right.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] },
            $true
        )

        return @($strings | ForEach-Object { $_.Value })
    }

    $script:RunnerAst = Get-VKAst -Path $script:RunnerPath
    $script:BuildAst  = Get-VKAst -Path $script:BuildPath

    $script:RunnerCommands = Get-VKCommandNames -Ast $script:RunnerAst

    # Ordered list of host module functions the runner actually invokes.
    $script:RunnerHostInvocations = @(
        $script:RunnerCommands | Where-Object { $_ -like 'Invoke-VKHost*' }
    )

    $script:BuildHostModuleFiles = Get-VKArrayAssignment -Ast $script:BuildAst -VariableName 'hostModuleFiles'
}


Describe 'Runner: duplicate module invocation' {

    It 'invokes Invoke-VKHostNetworkConfig exactly once' {
        $matched = @($script:RunnerCommands | Where-Object { $_ -eq 'Invoke-VKHostNetworkConfig' })
        $matched.Count | Should -Be 1 -Because 'the duplicate Host.NetworkConfig execution was removed in Tranche 1 and must not reappear'
    }

    It 'dot-sources Host.NetworkConfig.ps1 exactly once' {
        $literals = $script:RunnerAst.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] },
            $true
        )
        $matched = @($literals | Where-Object { $_.Value -eq 'Host.NetworkConfig.ps1' })
        $matched.Count | Should -Be 1
    }

    It 'records host.network_config in modules_executed exactly once' {
        $literals = $script:RunnerAst.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] },
            $true
        )
        $matched = @($literals | Where-Object { $_.Value -eq 'host.network_config' })
        $matched.Count | Should -Be 1
    }

    It 'invokes no host module more than once' {
        $duplicates = @(
            $script:RunnerHostInvocations |
                Group-Object |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object { "$($_.Name) x$($_.Count)" }
        )
        $duplicates -join ', ' | Should -BeNullOrEmpty -Because 'each module represents one observation point; a repeated call silently overwrites the earlier result'
    }
}


Describe 'Build source: duplicate module invocation' {

    It 'lists Host.NetworkConfig.ps1 exactly once in $hostModuleFiles' {
        $matched = @($script:BuildHostModuleFiles | Where-Object { $_ -eq 'Host.NetworkConfig.ps1' })
        $matched.Count | Should -Be 1 -Because 'the build emits one invocation per entry in this array'
    }

    It 'lists no host module file more than once' {
        $duplicates = @(
            $script:BuildHostModuleFiles |
                Group-Object |
                Where-Object { $_.Count -gt 1 } |
                ForEach-Object { "$($_.Name) x$($_.Count)" }
        )
        $duplicates -join ', ' | Should -BeNullOrEmpty
    }

    It 'maps Host.NetworkConfig.ps1 to Invoke-VKHostNetworkConfig' {
        $script:BuildAst.Extent.Text | Should -Match 'Host\.NetworkConfig\.ps1"?\s*=\s*@\{\s*Func\s*=\s*"Invoke-VKHostNetworkConfig"'
    }
}


Describe 'Runner and build source agree on host module order' {

    It 'invokes host modules in the same order the build source emits them' {
        # Derive the expected function order from the build template's file list,
        # translating file name -> function name using the runner's own ordering
        # convention (Host.Foo.ps1 -> Invoke-VKHostFoo is not mechanical, so we
        # compare positions of the shared set instead).
        $buildOrder = @($script:BuildHostModuleFiles)

        # Map each build file to the runner invocation index it corresponds to,
        # using the dot-source string literals in the runner as the anchor.
        $runnerSourceOrder = @(
            $script:RunnerAst.FindAll(
                { param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst] },
                $true
            ) | ForEach-Object { $_.Value } | Where-Object { $_ -like 'Host.*.ps1' }
        )

        $runnerSourceOrder | Should -Be $buildOrder -Because 'the standalone build must reproduce the source-of-truth module order exactly'
    }
}


Describe 'Modules: no case-insensitive parameter/variable collision' {

    # REGRESSION GUARD.
    #
    # PowerShell variable names are case-insensitive, so a local named
    # $isAdmin resolves to a function's [bool]$IsAdmin PARAMETER. Because
    # that parameter is type-constrained, assigning $null to it is silently
    # coerced to $false - which once turned "group membership was never
    # established" into the substantive claim "this account is not an
    # administrator", and corrupted the parameter for the rest of the call.
    #
    # This walks every Invoke-VK* function and fails on any assignment
    # whose target differs from a declared parameter only by case.

    BeforeAll {
        $script:ModuleRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'modules'

        $script:CollisionFindings = @()

        foreach ($file in @(Get-ChildItem -Path $script:ModuleRoot -Recurse -Filter *.ps1)) {
            $errors = $null
            $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)

            $functions = $ast.FindAll(
                { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -like 'Invoke-VK*' },
                $true)

            foreach ($function in $functions) {
                $parameterNames = @()
                if ($function.Body.ParamBlock) {
                    $parameterNames = @($function.Body.ParamBlock.Parameters |
                        ForEach-Object { $_.Name.VariablePath.UserPath })
                }
                if ($parameterNames.Count -eq 0) { continue }

                $assignments = $function.FindAll(
                    { param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                                $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] },
                    $true)

                foreach ($assignment in $assignments) {
                    $target = $assignment.Left.VariablePath.UserPath

                    foreach ($parameter in $parameterNames) {
                        # Differs only by case => same variable to PowerShell.
                        if ($target -ne $parameter -and $target -ieq $parameter) {
                            $script:CollisionFindings += "$($file.Name):$($assignment.Extent.StartLineNumber) `$$target collides with parameter `$$parameter in $($function.Name)"
                        }
                    }
                }
            }
        }
    }

    It 'finds no assignment colliding with a declared parameter by case alone' {
        $script:CollisionFindings -join ' | ' | Should -BeNullOrEmpty
    }

    It 'actually inspected some Invoke-VK functions (guards the guard)' {
        # Ensures the walk above is not silently finding nothing to check.
        $count = 0
        foreach ($file in @(Get-ChildItem -Path $script:ModuleRoot -Recurse -Filter *.ps1)) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
            $count += @($ast.FindAll(
                { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -like 'Invoke-VK*' },
                $true)).Count
        }
        $count | Should -BeGreaterThan 30
    }
}


Describe 'Runner: output envelope declaration' {

    It 'declares the five required top-level sections (schema 1.1)' {
        # Updated from four to five in Tranche 2A. The acquisition section
        # is additive for existing consumers but REQUIRED by the schema 1.1
        # study contract.
        foreach ($section in @('scan_metadata', 'acquisition', 'host', 'security', 'vulnerability')) {
            $script:RunnerAst.Extent.Text | Should -Match "`"$section`"\s*=\s*\[ordered\]" -Because "the envelope must declare the $section section"
        }
    }

    It 'declares the envelope sections in contract order' {
        $envelopeOrder = @(
            [regex]::Matches($script:RunnerAst.Extent.Text, '"(scan_metadata|acquisition|host|security|vulnerability)"\s*=\s*\[ordered\]@\{\}') |
                ForEach-Object { $_.Groups[1].Value }
        )
        $envelopeOrder | Should -Be @('scan_metadata', 'acquisition', 'host', 'security', 'vulnerability')
    }

    It 'serialises using the configured JSON depth rather than a hardcoded value' {
        $script:RunnerAst.Extent.Text | Should -Match 'ConvertTo-Json\s+-Depth\s+\$script:VKJsonDepth'
    }

    It 'takes schema_version from the central config rather than a literal' {
        $script:RunnerAst.Extent.Text | Should -Match '"schema_version"\s*=\s*\$script:VKSchemaVersion'
    }

    It 'initialises the acquisition store before any module runs' {
        $script:RunnerCommands | Should -Contain 'Initialize-VKAcquisition'
    }

    It 'resolves unfinished acquisition units before serialisation' {
        $text = $script:RunnerAst.Extent.Text
        $sweepIndex     = $text.IndexOf('Complete-VKAcquisitionReport')
        $serialiseIndex = $text.IndexOf('ConvertTo-Json')

        $sweepIndex | Should -BeGreaterThan 0 -Because 'the fail-closed backstop must be present'
        $sweepIndex | Should -BeLessThan $serialiseIndex -Because 'unresolved units must be swept before export'
    }
}
