<#
.SYNOPSIS
    Focused regression tests for Host.WindowsUpdates acquisition semantics.

.DESCRIPTION
    Every provider is mocked. Nothing queries the live Windows Update client,
    registry, network or host state.

    Proves that a successful empty result remains distinguishable from an
    unsuccessful query: zero updates emits an empty array with success, while
    provider failure emits null values with a structured failed acquisition
    outcome.
#>

BeforeAll {
    $script:AgentRoot = Split-Path -Parent $PSScriptRoot

    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')
    . (Join-Path $script:AgentRoot 'modules\host\Host.WindowsUpdates.ps1')

    function New-TestWindowsUpdateSearcher {
        $searcher = [pscustomobject]@{}

        $searcher | Add-Member -MemberType ScriptMethod -Name Search -Value {
            param([string]$Criteria)

            if ($script:PendingSearchError) {
                throw $script:PendingSearchError
            }

            return [pscustomobject]@{
                Updates = @($script:PendingUpdates)
            }
        }

        $searcher | Add-Member -MemberType ScriptMethod -Name GetTotalHistoryCount -Value {
            return @($script:UpdateHistory).Count
        }

        $searcher | Add-Member -MemberType ScriptMethod -Name QueryHistory -Value {
            param([int]$StartIndex, [int]$Count)
            return @($script:UpdateHistory)
        }

        return $searcher
    }

    function New-TestWindowsUpdateSession {
        $session = [pscustomobject]@{}

        $session | Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value {
            return $script:UpdateSearcher
        }

        return $session
    }

    function Invoke-TestWindowsUpdateCollection {
        $script:Section = [ordered]@{}

        Invoke-VKHostWindowsUpdates -Data $script:Section -IsAdmin $true
        Complete-VKAcquisitionReport

        $script:WindowsUpdateData = $script:Section['windows_updates']
        $script:AcquisitionReport = Get-VKAcquisitionReport
        $script:PendingEntry =
            $script:AcquisitionReport['host.windows_updates.pending_updates']
    }
}

Describe 'Host.WindowsUpdates pending-update acquisition semantics' {
    BeforeEach {
        Initialize-VKAcquisition

        Mock Write-VKStatus { }
        Mock Write-LogMessage { }
        Mock Test-Path { $false }
        Mock Get-ItemProperty {
            [pscustomobject]@{ PendingFileRenameOperations = $null }
        }

        $script:PendingUpdates = @()
        $script:UpdateHistory = @()
        $script:PendingSearchError = $null
        $script:UpdateSearcher = New-TestWindowsUpdateSearcher
        $script:UpdateSession = New-TestWindowsUpdateSession
        $script:AutoUpdate = [pscustomobject]@{
            Results = [pscustomobject]@{
                LastSearchSuccessDate = [datetime]::MinValue
                LastInstallationSuccessDate = [datetime]::MinValue
            }
        }

        Mock New-Object {
            return $script:UpdateSession
        } -ParameterFilter {
            $ComObject -eq 'Microsoft.Update.Session'
        }

        Mock New-Object {
            return $script:AutoUpdate
        } -ParameterFilter {
            $ComObject -eq 'Microsoft.Update.AutoUpdate'
        }
    }

    Context 'when the provider successfully finds zero pending updates' {
        BeforeEach {
            Invoke-TestWindowsUpdateCollection
        }

        It 'records a genuine numeric zero' {
            $script:WindowsUpdateData['pending_count'] | Should -Be 0
        }

        It 'emits a real empty collection rather than null' {
            [object]::ReferenceEquals(
                $null,
                $script:WindowsUpdateData['pending_updates']
            ) | Should -BeFalse

            @($script:WindowsUpdateData['pending_updates']).Count |
                Should -Be 0
        }

        It 'records the acquisition as success' {
            $script:PendingEntry.acquisition_outcome | Should -Be 'success'
            $script:PendingEntry.error | Should -BeNullOrEmpty
        }

        It 'governs exactly the two pending-update paths' {
            @($script:PendingEntry.data_paths) | Should -Be @(
                'host.windows_updates.pending_count'
                'host.windows_updates.pending_updates'
            )
        }
    }

    Context 'when the provider successfully returns an update' {
        BeforeEach {
            $script:PendingUpdates = @(
                [pscustomobject]@{
                    Title = 'Synthetic security update'
                    KBArticleIDs = @('5000001')
                    MsrcSeverity = 'Critical'
                    IsDownloaded = $false
                    IsMandatory = $true
                    Categories = @(
                        [pscustomobject]@{ Name = 'Security Updates' }
                    )
                }
            )

            Invoke-TestWindowsUpdateCollection
        }

        It 'retains the observed result and reports success' {
            $script:WindowsUpdateData['pending_count'] | Should -Be 1
            $script:WindowsUpdateData['pending_updates'][0]['title'] |
                Should -Be 'Synthetic security update'
            $script:WindowsUpdateData['pending_updates'][0]['kb_numbers'] |
                Should -Contain 'KB5000001'
            $script:PendingEntry.acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when the pending-update search throws' {
        BeforeEach {
            $script:PendingSearchError =
                [System.Runtime.InteropServices.COMException]::new(
                    'Synthetic Windows Update name-resolution failure.',
                    -2145107924
                )

            Invoke-TestWindowsUpdateCollection
        }

        It 'withholds both governed payload values' {
            $script:WindowsUpdateData['pending_count'] |
                Should -BeNullOrEmpty

            [object]::ReferenceEquals(
                $null,
                $script:WindowsUpdateData['pending_updates']
            ) | Should -BeTrue
        }

        It 'records a machine-readable failed outcome' {
            $script:PendingEntry.acquisition_outcome |
                Should -Be 'failed'
            $script:PendingEntry.error.category |
                Should -Be 'provider_query_failed'
            $script:PendingEntry.error.provider |
                Should -Be 'Microsoft.Update.Session.CreateUpdateSearcher().Search("IsInstalled=0")'
            $script:PendingEntry.error.exception_type |
                Should -Not -BeNullOrEmpty
        }

        It 'does not leave the unit pending or incomplete' {
            $script:PendingEntry.acquisition_outcome |
                Should -Not -Be 'success'
            $script:PendingEntry.acquisition_outcome |
                Should -Not -Be 'pending'
            $script:PendingEntry.error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'when the Windows Update session cannot be created' {
        BeforeEach {
            Mock New-Object {
                throw [System.Runtime.InteropServices.COMException]::new(
                    'Synthetic Windows Update session failure.',
                    -2145107924
                )
            } -ParameterFilter {
                $ComObject -eq 'Microsoft.Update.Session'
            }

            Invoke-TestWindowsUpdateCollection
        }

        It 'retains a self-describing null pending-update state' {
            $script:WindowsUpdateData | Should -Not -BeNullOrEmpty
            $script:WindowsUpdateData['pending_count'] |
                Should -BeNullOrEmpty

            [object]::ReferenceEquals(
                $null,
                $script:WindowsUpdateData['pending_updates']
            ) | Should -BeTrue
        }

        It 'records session creation as a provider-query failure' {
            $script:PendingEntry.acquisition_outcome |
                Should -Be 'failed'
            $script:PendingEntry.error.category |
                Should -Be 'provider_query_failed'
            $script:PendingEntry.error |
                Should -Not -BeNullOrEmpty
        }
    }
}
