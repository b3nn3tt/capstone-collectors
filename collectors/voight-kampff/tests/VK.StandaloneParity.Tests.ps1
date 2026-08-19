<#
.SYNOPSIS
    Pester tests for modular/standalone parity and generated-agent integrity.

.DESCRIPTION
    The generated standalone script is the controlled-collection artefact,
    so it must emit the same evidence contract as the modular runner and
    must remain dependency-free on target machines.

    These tests:
      - compare required metadata and envelope declarations between the
        modular runner and the build source, by static AST/text analysis;
      - GENERATE the standalone script into the Pester TestDrive;
      - parse the generated script for syntax errors;
      - assert schema 1.1, acquisition support, required metadata, depth 10;
      - assert that no development dependency is referenced.

    IMPORTANT: generating the script does NOT execute the collector. The
    build concatenates source files and writes an output file; it never
    invokes the result. The generated script is only ever PARSED here.

    TEST LIFECYCLE
    Generation happens in a BeforeAll inside the 'Generated standalone
    script' Describe, so it runs during the RUN phase, when TestDrive
    exists. It must not be hoisted into a -Skip: expression: -Skip: is
    evaluated during DISCOVERY, before any BeforeAll has run, so a
    discovery-time reference to a run-phase variable silently skips every
    dependent test regardless of whether generation succeeded.

    Generation failure is therefore surfaced as an explicit FAILING test
    carrying the captured error, never as a skip.

.NOTES
    Tranche 2A. Pester 5.5+ (developed against 6.1). See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot  = Split-Path -Parent $PSScriptRoot
    $script:RunnerPath = Join-Path $script:AgentRoot 'core\Invoke-VKScan.ps1'
    $script:BuildPath  = Join-Path $script:AgentRoot 'build\Build-Standalone.ps1'
    $script:ConfigPath = Join-Path $script:AgentRoot 'core\VK.Config.ps1'

    . $script:ConfigPath
    $script:ConfiguredAgent  = $script:VKAgentVersion
    $script:ConfiguredSchema = $script:VKSchemaVersion
    $script:ConfiguredDepth  = $script:VKJsonDepth

    # Test-only semantic analysis helpers; never part of the collector.
    . (Join-Path $PSScriptRoot 'helpers\VK.StaticAnalysis.ps1')

    $script:RunnerText = Get-Content -Path $script:RunnerPath -Raw
    $script:BuildText  = Get-Content -Path $script:BuildPath  -Raw

    $script:RequiredMetadata = @(
        'schema_version'
        'agent_version'
        'hostname'
        'running_user'
        'running_user_sid'
        'scan_start'
        'scan_end'
        'scan_duration_seconds'
        'ran_as_admin'
        'modules_executed'
    )

    $script:RequiredSections = @('scan_metadata', 'acquisition', 'host', 'security', 'vulnerability')
}


Describe 'Static parity: modular runner and build source' {

    It 'the modular runner declares the <_> metadata field' -ForEach @(
        'schema_version', 'agent_version', 'hostname', 'running_user', 'running_user_sid',
        'scan_start', 'scan_end', 'scan_duration_seconds', 'ran_as_admin', 'modules_executed'
    ) {
        $script:RunnerText | Should -Match "`"$_`"\s*="
    }

    It 'the build source emits the <_> metadata field' -ForEach @(
        'schema_version', 'agent_version', 'hostname', 'running_user', 'running_user_sid',
        'scan_start', 'scan_end', 'scan_duration_seconds', 'ran_as_admin', 'modules_executed'
    ) {
        # The known Tranche 1 divergence was that the build omitted
        # schema_version, running_user and running_user_sid.
        $script:BuildText | Should -Match "`"$_`"\s+="
    }

    It 'the modular runner declares the <_> envelope section' -ForEach @(
        'scan_metadata', 'acquisition', 'host', 'security', 'vulnerability'
    ) {
        $script:RunnerText | Should -Match "`"$_`"\s*=\s*\[ordered\]"
    }

    It 'the build source emits the <_> envelope section' -ForEach @(
        'scan_metadata', 'acquisition', 'host', 'security', 'vulnerability'
    ) {
        $script:BuildText | Should -Match "`"$_`"\s+=\s+\[ordered\]"
    }

    It 'both take schema_version from the central config rather than a literal' {
        $script:RunnerText | Should -Match '"schema_version"\s*=\s*\$script:VKSchemaVersion'
        $script:BuildText  | Should -Match '"schema_version"\s+=\s+\$script:VKSchemaVersion'
        $script:RunnerText | Should -Not -Match '"schema_version"\s*=\s*"1\.'
    }

    It 'both take the JSON depth from the central config' {
        $script:RunnerText | Should -Match 'ConvertTo-Json\s+-Depth\s+\$script:VKJsonDepth'
        $script:BuildText  | Should -Match 'ConvertTo-Json\s+-Depth\s+\$script:VKJsonDepth'
    }

    It 'both initialise and finalise the acquisition store' {
        foreach ($text in @($script:RunnerText, $script:BuildText)) {
            $text | Should -Match 'Initialize-VKAcquisition'
            $text | Should -Match 'Complete-VKAcquisitionReport'
            $text | Should -Match 'Get-VKAcquisitionReport'
        }
    }

    It 'the build source captures the identity needed for running_user_sid' {
        $script:BuildText | Should -Match '\$script:CurrentIdentity\s*=\s*\[Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)'
    }

    It 'the build source concatenates the utilities that define the helpers' {
        # The acquisition helpers live in VK.Utilities.ps1, which must be
        # embedded before any module or runner logic references them.
        $script:BuildText | Should -Match 'VK\.Utilities\.ps1'
        $script:BuildText | Should -Match 'VK\.Config\.ps1'
    }
}


Describe 'Generated standalone script' {

    # Generation runs HERE, in the run phase, where TestDrive exists.
    # It is deliberately not guarded by -Skip:, which Pester evaluates
    # during discovery - before this BeforeAll has assigned anything.
    BeforeAll {
        $script:GeneratedPath   = $null
        $script:GeneratedText   = $null
        $script:GeneratedAst    = $null
        $script:GenerationError = $null

        try {
            # -Quiet suppresses console output; -PassThru returns the path.
            # The output goes only to TestDrive, which Pester disposes of
            # automatically at the end of the container.
            $buildOutput = & $script:BuildPath -OutputPath $TestDrive -Quiet -PassThru

            $candidate = @($buildOutput | Where-Object { $_ -is [string] -and $_ -like '*.ps1' }) |
                Select-Object -Last 1

            if (-not ($candidate -and (Test-Path $candidate))) {
                $candidate = (Get-ChildItem -Path $TestDrive -Filter 'VoightKampff_Standalone_*.ps1' -ErrorAction SilentlyContinue |
                    Select-Object -First 1).FullName
            }

            if ($candidate -and (Test-Path $candidate)) {
                $script:GeneratedPath = $candidate
                # Read only. The generated script is parsed and pattern
                # matched; it is never dot-sourced or invoked.
                $script:GeneratedText = Get-Content -Path $candidate -Raw
                $script:GeneratedAst  = ConvertTo-VKScriptAst -Path $candidate
            }
            else {
                $script:GenerationError = "The build produced no standalone script in '$TestDrive'."
            }
        }
        catch {
            $script:GenerationError = $_.Exception.Message
        }
    }

    It 'generates a standalone script into TestDrive without error' {
        # Generation failure fails loudly here, carrying the captured
        # error, rather than silently skipping every dependent test.
        $script:GenerationError | Should -BeNullOrEmpty -Because 'the build must produce a standalone script for the generated-artefact tests to assert against'
        $script:GeneratedPath   | Should -Not -BeNullOrEmpty
        $script:GeneratedText   | Should -Not -BeNullOrEmpty
    }

    It 'writes the generated script only into the disposable TestDrive' {
        $script:GeneratedPath | Should -Not -BeNullOrEmpty
        # Neither the repository nor agent/dist is written to by the suite.
        $script:GeneratedPath | Should -Not -BeLike "$($script:AgentRoot)*"
    }

    It 'parses without syntax errors' {
        $script:GeneratedPath | Should -Not -BeNullOrEmpty -Because 'generation must have succeeded'

        $errors = $null
        $tokens = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:GeneratedPath, [ref]$tokens, [ref]$errors)

        $messages = @($errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" })
        $messages -join ' | ' | Should -BeNullOrEmpty
    }

    # Both Contexts below inherit the generated script from the Describe's
    # BeforeAll. Neither is guarded by a discovery-time expression, so both
    # execute whenever generation succeeds - and fail, visibly, when it
    # does not.

    Context 'contract, versions and parity' {

        It 'declares schema version 1.1' {
            $script:GeneratedText | Should -Match '\$script:VKSchemaVersion\s*=\s*"1\.1"'
        }

        It 'declares agent version 2.1.0' {
            $script:GeneratedText | Should -Match '\$script:VKAgentVersion\s*=\s*"2\.1\.0"'
        }

        It 'declares JSON depth 10' {
            $script:GeneratedText | Should -Match '\$script:VKJsonDepth\s*=\s*10'
        }

        It 'declares the <_> envelope section' -ForEach @(
            'scan_metadata', 'acquisition', 'host', 'security', 'vulnerability'
        ) {
            $script:GeneratedText | Should -Match "`"$_`"\s+=\s+\[ordered\]"
        }

        It 'emits the <_> metadata field' -ForEach @(
            'schema_version', 'agent_version', 'hostname', 'running_user', 'running_user_sid',
            'scan_start', 'scan_end', 'scan_duration_seconds', 'ran_as_admin', 'modules_executed'
        ) {
            $script:GeneratedText | Should -Match "`"$_`"\s+="
        }

        It 'contains every acquisition helper the runner logic calls' -ForEach @(
            'Initialize-VKAcquisition'
            'Start-VKAcquisition'
            'Complete-VKAcquisition'
            'Set-VKAcquisitionFailure'
            'Set-VKAcquisitionUnavailable'
            'Get-VKAcquisitionClassification'
            'Complete-VKAcquisitionReport'
            'Get-VKAcquisitionReport'
        ) {
            $script:GeneratedText | Should -Match "function\s+$_\s*\{"
        }

        It 'defines every acquisition helper it calls' {
            # Guards against a helper being invoked by an embedded module but
            # never defined, which would fail only at collection time.
            $script:GeneratedPath | Should -Not -BeNullOrEmpty

            $errors = $null
            $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:GeneratedPath, [ref]$tokens, [ref]$errors)

            $defined = @(
                $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
                    ForEach-Object { $_.Name }
            )

            $calledAcquisitionHelpers = @(
                $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } |
                    Where-Object { $_ -and $_ -like '*VKAcquisition*' } |
                    Sort-Object -Unique
            )

            $calledAcquisitionHelpers.Count | Should -BeGreaterThan 0

            $missing = @($calledAcquisitionHelpers | Where-Object { $defined -notcontains $_ })
            $missing -join ', ' | Should -BeNullOrEmpty -Because 'the generated script must be self-contained'
        }

        It 'instruments collection unit <_>' -ForEach @(
            # Tranche 2A
            'security.legacy_protocols.llmnr'
            'security.legacy_protocols.mdns'
            'security.host_security.device_guard'
            'security.antivirus.products'
            'security.antivirus.defender_status'
            # Tranche 2B.1
            'security.defender_advanced.asr_rules'
            'security.defender_advanced.protection_preferences'
            'security.defender_advanced.tamper_protection'
            'security.firewall.profiles'
            'security.firewall.inbound_rules'
            'security.smb.smbv1'
            'security.smb.server_registry'
            'security.smb.client_registry'
            'security.smb.server_configuration'
            'security.rdp.terminal_server'
            'security.rdp.rdp_tcp'
            'security.rdp.allowed_users'
            'security.winrm.service'
            'security.winrm.server_registry'
            'security.winrm.client_registry'
            'security.winrm.trusted_hosts'
            'security.winrm.listeners'
            'security.uac.configuration'
            'security.fde.os_drive'
            'security.fde.additional_volumes'
            # Tranche 2B.2
            'host.identification.hostname'
            'host.identification.operating_system'
            'host.identification.computer_system'
            'host.network_config.tcp_connections'
            'host.network_config.udp_listeners'
            'host.services.inventory'
            'host.processes.inventory'
            'host.software.hklm_native'
            'host.software.hklm_wow6432'
            'host.users.local_accounts'
            'host.users.group_memberships'
            'vulnerability.token_privileges.current_token'
            # Tranche 2C
            'host.sessions.current_sessions'
            'host.sessions.session_principals'
            'host.sessions.user_profiles'
        ) {
            $script:GeneratedText | Should -BeLike "*$_*"
        }

        It 'embeds the Tranche 2C WTS interop the sessions module depends on' -ForEach @(
            'Initialize-VKWtsInterop'
            'Get-VKWtsSessionRecords'
            'Get-VKWtsSessionString'
            'Get-VKWtsSessionProtocolType'
            'Get-VKWtsNativeErrorCode'
            'Set-VKWtsAcquisitionFailure'
            'Invoke-VKHostSessions'
        ) {
            $script:GeneratedText | Should -Match "function\s+$_\s*\{"
        }

        It 'carries the WTS native source and its memory release into the artefact' {
            $script:GeneratedText | Should -Match 'WTSEnumerateSessionsW'
            $script:GeneratedText | Should -Match 'WTSFreeMemory'
            $script:GeneratedText | Should -Match '\$script:VKSessionWindowHours\s*=\s*24'
        }

        # --- EXCLUSION TESTS: semantic, not textual -----------------
        #
        # The generated artefact intentionally EMBEDS the module's
        # exclusion documentation, which names quser.exe, qwinsta.exe,
        # wevtutil.exe, WTSLogonTime and 4624. A whole-text scan therefore
        # fails on the very comments that record the exclusions. These
        # assert executable use through the generated script's AST, in
        # which comments do not appear.

        It 'invokes no external session-collection executable' {
            $findings = Get-VKExternalCommandUsage -Ast $script:GeneratedAst
            $findings -join ', ' | Should -BeNullOrEmpty
        }

        It 'contains no executable Event Log collection path' {
            # Event 4624 is deliberately excluded: its empty results could
            # never be shown to mean "no recent logon".
            $findings = Get-VKEventLogCollectionUsage -Ast $script:GeneratedAst
            $findings -join ', ' | Should -BeNullOrEmpty
        }

        It 'admits only WTS information classes 5, 7 and 16' {
            # Scoped to the named Host.Sessions positions. The artefact
            # concatenates every module, so unrelated numerals elsewhere -
            # notably Host.WindowsUpdates' QueryHistory(0, $maxHistory) COM
            # start index - must not be mistaken for an information class.
            $used = Get-VKWtsInfoClassUsage -Ast $script:GeneratedAst
            $used | Should -Be @(5, 7, 16)
            $used | Should -Not -Contain 18

            # CONTRAST, proving the scoping rather than assuming it: the
            # same unrelated construct in isolation yields nothing, while a
            # genuine Host.Sessions call still yields its class.
            $unrelatedAst = ConvertTo-VKScriptAst -Text '$h = $updateSearcher.QueryHistory(0, $maxHistory)'
            Get-VKWtsInfoClassUsage -Ast $unrelatedAst | Should -BeNullOrEmpty

            $genuineAst = ConvertTo-VKScriptAst -Text 'Get-VKWtsSessionString -SessionId 1 -InfoClass 18'
            Get-VKWtsInfoClassUsage -Ast $genuineAst | Should -Contain 18
        }

        It 'makes no active WTS query for information class 18' {
            $embedded = Get-VKEmbeddedCSharpSource -Source $script:GeneratedText
            $embedded | Should -Not -BeNullOrEmpty -Because 'the interop must be embedded in the artefact'

            $literals = Get-VKCSharpWtsInfoClassLiteral -CSharpSource $embedded
            $literals | Should -Not -Contain 18
            $literals | Should -Be @(16)
        }

        It 'detects a prohibited external invocation (negative control)' {
            # Single-quoted literal path: statically determinable, as any
            # real invocation in generated source would be. A name built at
            # runtime (& "$env:SystemRoot\...") is not statically knowable
            # and is a documented limit of every static check.
            $syntheticAst = ConvertTo-VKScriptAst -Text @'
# wevtutil named in a comment must NOT be flagged
& 'C:\Windows\System32\wevtutil.exe' qe Security
'@
            $findings = Get-VKExternalCommandUsage -Ast $syntheticAst
            $findings -join ', ' | Should -BeLike '*wevtutil.exe*'
        }

        It 'detects embedded Event Log collection (negative control)' {
            $syntheticAst = ConvertTo-VKScriptAst -Text @'
# Get-EventLog in a comment must NOT be flagged
Get-EventLog -LogName Security -InstanceId 4624
'@
            Get-VKEventLogCollectionUsage -Ast $syntheticAst | Should -Not -BeNullOrEmpty
        }

        It 'embeds the Tranche 2B.2 helper function the software module depends on' {
            $script:GeneratedText | Should -Match 'function\s+Get-VKSoftwareHiveEntries\s*\{'
        }

        It 'no longer contains the Tranche 2B.2 fabricated-state pathways' {
            # The in-band group-member sentinel is gone from live code.
            $script:GeneratedText | Should -Not -Match '\$groupDetails\["members"\]\s*=\s*@\("Error retrieving members"\)'
            # whoami output is no longer piped straight into the CSV parser.
            $script:GeneratedText | Should -Not -Match 'whoami\s+/priv\s+/fo\s+csv\s+2>&1\s*\|\s*ConvertFrom-Csv'
        }

        It 'embeds the Tranche 2B.1 helper functions the modules depend on' {
            # Get-VKFDEVolumeDetails is a module-scope helper introduced in
            # this tranche; the generated script must be self-contained.
            $script:GeneratedText | Should -Match 'function\s+Get-VKFDEVolumeDetails\s*\{'
        }

        It 'no longer contains the Tranche 2B.1 fabricated-state pathways' {
            # Defender no longer re-queries SecurityCenter2 for its own
            # applicability precondition.
            $script:GeneratedText | Should -Not -Match 'Get-CimInstance\s+-Namespace\s+"root\\SecurityCenter2"[^\r\n]*SilentlyContinue'
            # WinRM no longer falls back to the string "Unknown".
            $script:GeneratedText | Should -Not -Match '\$winrmData\["service_state"\]\s*=\s*"Unknown"'
        }

        It 'no longer contains the corrected false-evidence pathways' {
            # The three schema 1.0 fabrications, as they appeared in source.
            $script:GeneratedText | Should -Not -Match '\$protocolData\["llmnr_enabled"\]\s*=\s*\$true\s*#\s*Assume'
            $script:GeneratedText | Should -Not -Match '"product_name"\s*=\s*"Not Detected"'
        }
    }

    Context 'dependency-free on target machines' {

        It 'does not reference <_>' -ForEach @(
            'Invoke-Pester'
            'Import-Module Pester'
            'Should -Be'
            'BeforeAll'
            'Install-Module'
            'Find-Module'
            'PowerShellGet'
            'Invoke-RestMethod'
            'Invoke-WebRequest'
            'System.Data.SqlClient'
        ) {
            $script:GeneratedText | Should -Not -BeLike "*$_*"
        }

        It 'invokes no Python interpreter' {
            # AST-based, deliberately NOT a textual match on the word.
            #
            # The generated header documents the dependency position it is
            # being tested for - "No Pester, no Python, no gallery modules,
            # no API, database or network access" - so a wildcard check on
            # "python" rejected the artefact precisely because it states the
            # property under test. Only an actual command invocation is
            # evidence of a dependency; prose and comments are not.
            $script:GeneratedPath | Should -Not -BeNullOrEmpty

            $errors = $null
            $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:GeneratedPath, [ref]$tokens, [ref]$errors)

            $forbidden = @('python', 'python.exe', 'py', 'py.exe')

            $pythonInvocations = @(
                $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } |
                    Where-Object { $_ } |
                    Where-Object {
                        # Compare on the leaf so a path-qualified invocation
                        # such as C:\Python313\python.exe is caught too.
                        # Split on separators rather than using path APIs,
                        # which can throw on an unusual command name.
                        $leaf = ($_ -split '[\\/]')[-1]
                        $forbidden -contains $leaf.ToLowerInvariant()
                    }
            )

            $pythonInvocations -join ', ' | Should -BeNullOrEmpty -Because 'the collector must not shell out to a Python interpreter on a target machine'
        }

        It 'declares no #Requires -Modules dependency' {
            $script:GeneratedText | Should -Not -Match '(?m)^\s*#Requires\s+-Modules'
        }

        It 'imports no module at all' {
            $script:GeneratedText | Should -Not -Match '(?m)^\s*Import-Module\s'
        }

        It 'contains no Pester Describe block' {
            $script:GeneratedText | Should -Not -Match '(?m)^\s*Describe\s+[''"]'
        }

        It 'does not embed the test-only schema validator' {
            $script:GeneratedText | Should -Not -Match 'Test-VKEvidenceArtefact'
            $script:GeneratedText | Should -Not -Match 'VK\.SchemaValidation'
        }

        It 'uses only Windows PowerShell 5.1 compatible operators' {
            # PowerShell 7-only syntax would break the collection runtime.
            $script:GeneratedText | Should -Not -Match '\?\?='
            $script:GeneratedText | Should -Not -Match '(?m)^\s*using\s+namespace'
        }
    }
}


Describe 'Build source: safe generation parameters' {

    It 'accepts an OutputPath parameter' {
        $script:BuildText | Should -Match '\[string\]\$OutputPath'
    }

    It 'accepts a Quiet switch for automated generation' {
        $script:BuildText | Should -Match '\[switch\]\$Quiet'
    }

    It 'accepts a PassThru switch so the generated path can be inspected' {
        $script:BuildText | Should -Match '\[switch\]\$PassThru'
    }

    It 'never invokes the generated script' {
        # The build writes the file and stops. Anything that executes it
        # would turn a build into a collection.
        $script:BuildText | Should -Not -Match '&\s*\$outputFile'
        $script:BuildText | Should -Not -Match 'Invoke-Expression'
        $script:BuildText | Should -Not -Match '\.\s+\$outputFile'
    }
}
