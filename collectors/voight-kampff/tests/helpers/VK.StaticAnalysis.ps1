<#
.SYNOPSIS
    Semantic (AST-based) static analysis helpers for exclusion tests.

.DESCRIPTION
    TEST-ONLY. Never included in the generated standalone collector and
    not referenced by the build template.

    WHY THIS EXISTS
    Exclusion tests previously searched whole-file text for forbidden
    terms such as "quser", "wevtutil", "4624" and "WTSLogonTime". Those
    terms legitimately appear in the module's comment-based help, which
    DOCUMENTS the exclusions - so the tests failed precisely because the
    module correctly explains what it does not collect.

    Deleting or weakening that documentation to satisfy a test would be
    the wrong repair. Instead these helpers assert EXECUTABLE USE:

      - invoked command names come from CommandAst.GetCommandName();
      - referenced types come from type-expression nodes;
      - string values come from live string-literal nodes.

    Comments are not AST nodes at all, so they are excluded structurally
    rather than by pattern. Comment-based help therefore cannot produce a
    false positive, while a real invocation still fails the test.

    This mirrors the approach already adopted for the standalone
    Python-interpreter check.

.NOTES
    Tranche 2C repair.
#>

function ConvertTo-VKScriptAst {
    <#
    .SYNOPSIS
        Parses a script file or a synthetic script string into an AST.

    .DESCRIPTION
        Parsing never executes the script. Synthetic text is supported so
        negative controls can prove a detector fires without any
        prohibited command ever being run.
    #>
    param(
        [string]$Path,
        [string]$Text
    )

    $tokens = $null
    $errors = $null

    if ($Path) {
        return [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    }

    return [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
}


function Get-VKInvokedCommandName {
    <#
    .SYNOPSIS
        Returns the lower-cased leaf names of every command actually
        invoked in the AST.

    .DESCRIPTION
        Path-qualified invocations are reduced to their leaf, so
        "C:\Windows\System32\quser.exe" and a bare "quser" both resolve to
        a comparable name. Splitting on separators avoids path APIs, which
        can throw on an unusual command name.

        Returns nothing for a command whose name is not statically
        determinable (for example "& $someVariable") - a documented limit
        of any static check.
    #>
    param([Parameter(Mandatory)]$Ast)

    $commands = $Ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.CommandAst] },
        $true)

    return @(
        $commands |
            ForEach-Object { $_.GetCommandName() } |
            Where-Object { $_ } |
            ForEach-Object { (($_ -split '[\\/]')[-1]).ToLowerInvariant() } |
            Sort-Object -Unique
    )
}


function Get-VKReferencedTypeName {
    <#
    .SYNOPSIS
        Returns the full names of every type referenced in executable
        positions (type expressions and type constraints).
    #>
    param([Parameter(Mandatory)]$Ast)

    $typeNodes = $Ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.TypeExpressionAst] -or
            $node -is [System.Management.Automation.Language.TypeConstraintAst]
        },
        $true)

    return @(
        $typeNodes |
            ForEach-Object { $_.TypeName.FullName } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}


function Get-VKLiveStringValue {
    <#
    .SYNOPSIS
        Returns the values of live string literals.

    .DESCRIPTION
        Live strings only - comments are not string literals and are never
        returned. Used to detect CIM class names such as Win32_NTLogEvent
        passed as arguments.
    #>
    param([Parameter(Mandatory)]$Ast)

    $stringNodes = $Ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
        },
        $true)

    return @($stringNodes | ForEach-Object { $_.Value } | Where-Object { $_ })
}


function Get-VKExternalCommandUsage {
    <#
    .SYNOPSIS
        Finds invocations of forbidden external executables.

    .OUTPUTS
        String[] of findings. Empty means none are invoked.
    #>
    param(
        [Parameter(Mandatory)]$Ast,
        [string[]]$Forbidden = @('quser', 'quser.exe', 'qwinsta', 'qwinsta.exe', 'wevtutil', 'wevtutil.exe')
    )

    $invoked   = Get-VKInvokedCommandName -Ast $Ast
    $forbidLow = @($Forbidden | ForEach-Object { $_.ToLowerInvariant() })

    return @($invoked | Where-Object { $forbidLow -contains $_ } | ForEach-Object { "invokes '$_'" })
}


function Get-VKEventLogCollectionUsage {
    <#
    .SYNOPSIS
        Finds any executable Event Log collection path.

    .DESCRIPTION
        Deliberately broader than a single command: the claim under test is
        that NO executable Event Log collection exists, so cmdlets, the
        external tool, the CIM class and the .NET reader types are all
        checked.
    #>
    param([Parameter(Mandatory)]$Ast)

    $findings = @()

    $forbiddenCommands = @('get-winevent', 'get-eventlog', 'wevtutil', 'wevtutil.exe')
    foreach ($name in (Get-VKInvokedCommandName -Ast $Ast)) {
        if ($forbiddenCommands -contains $name) { $findings += "invokes Event Log command '$name'" }
    }

    $forbiddenTypeFragments = @(
        'System.Diagnostics.EventLog',
        'System.Diagnostics.Eventing.Reader'
    )
    foreach ($typeName in (Get-VKReferencedTypeName -Ast $Ast)) {
        foreach ($fragment in $forbiddenTypeFragments) {
            if ($typeName -like "$fragment*") { $findings += "references Event Log type '$typeName'" }
        }
    }

    $forbiddenClasses = @('win32_ntlogevent')
    foreach ($value in (Get-VKLiveStringValue -Ast $Ast)) {
        if ($forbiddenClasses -contains $value.ToLowerInvariant()) {
            $findings += "references Event Log CIM class '$value'"
        }
    }

    return @($findings | Sort-Object -Unique)
}


# The exact Host.Sessions names that genuinely carry a WTS information
# class. Allow-listed by name rather than by wildcard: the generated
# standalone concatenates every module, so a broad rule such as "any
# member invocation starting with Query" or "any parameter named
# InfoClass" harvests unrelated literals from elsewhere in the artefact.
#
# This is not hypothetical. The wildcard form previously collected 0 from
# Host.WindowsUpdates' $updateSearcher.QueryHistory(0, $maxHistory) - a
# Windows Update COM start-index argument with no relation to WTS.
$script:VKWtsInfoClassConstantNames = @(
    'VKWtsInfoUserName'
    'VKWtsInfoDomainName'
    'VKWtsInfoProtocolType'
)

# The only Host.Sessions wrapper that accepts an information class.
$script:VKWtsInfoClassCommandNames = @('Get-VKWtsSessionString')

# The only interop method that accepts an information class, and the
# zero-based position of that argument. QueryProtocolType takes a session
# id only and is deliberately absent.
$script:VKWtsInfoClassStaticType     = 'VoightKampff.WtsNative'
$script:VKWtsInfoClassStaticMethod   = 'QueryString'
$script:VKWtsInfoClassStaticArgIndex = 1


function Get-VKWtsInfoClassUsage {
    <#
    .SYNOPSIS
        Returns every WTS information-class value used in executable
        PowerShell by Host.Sessions.

    .DESCRIPTION
        Deliberately narrow. Only three positions genuinely carry a WTS
        information class, and each is matched by exact name:

          1. assignment to one of the admitted VKWtsInfo* constants;
          2. the -InfoClass argument of Get-VKWtsSessionString;
          3. argument 1 of [VoightKampff.WtsNative]::QueryString.

        Everything else is ignored, including arbitrary numeric zeroes,
        WTSEnumerateSessions reserved/version arguments, default parameter
        values, state and protocol mapping keys, similarly named but
        unrelated variables, unrelated commands elsewhere in the generated
        standalone, and comments.
    #>
    param([Parameter(Mandatory)]$Ast)

    $values = @()

    # 1. Assignments to the ADMITTED constants only, matched by exact
    #    name. A scope prefix such as "script:" is tolerated.
    $assignments = $Ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst]
        },
        $true)

    foreach ($assignment in $assignments) {
        $variableName = ($assignment.Left.VariablePath.UserPath -split ':')[-1]
        if ($script:VKWtsInfoClassConstantNames -notcontains $variableName) { continue }

        $constant = $assignment.Right.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.ConstantExpressionAst] },
            $true) | Select-Object -First 1

        if ($constant -and $constant.Value -is [int]) { $values += [int]$constant.Value }
    }

    # 2. -InfoClass <constant> on the named Host.Sessions wrapper only.
    $commands = $Ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.CommandAst] },
        $true)

    foreach ($command in $commands) {
        $commandName = $command.GetCommandName()
        if (-not $commandName) { continue }
        if ($script:VKWtsInfoClassCommandNames -notcontains $commandName) { continue }

        for ($i = 0; $i -lt $command.CommandElements.Count; $i++) {
            $element = $command.CommandElements[$i]
            if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and
                $element.ParameterName -ieq 'InfoClass') {

                $argument = if ($element.Argument) { $element.Argument } else { $command.CommandElements[$i + 1] }
                if ($argument -is [System.Management.Automation.Language.ConstantExpressionAst] -and
                    $argument.Value -is [int]) {
                    $values += [int]$argument.Value
                }
            }
        }
    }

    # 3. The single interop method that takes an information class, on the
    #    WtsNative type only, at its declared argument position.
    $invocations = $Ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $node.Static -and
            $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $node.Member.Value -eq $script:VKWtsInfoClassStaticMethod -and
            $node.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and
            $node.Expression.TypeName.FullName -eq $script:VKWtsInfoClassStaticType
        },
        $true)

    foreach ($invocation in $invocations) {
        $arguments = @($invocation.Arguments)
        if ($arguments.Count -le $script:VKWtsInfoClassStaticArgIndex) { continue }

        $argument = $arguments[$script:VKWtsInfoClassStaticArgIndex]
        if ($argument -is [System.Management.Automation.Language.ConstantExpressionAst] -and
            $argument.Value -is [int]) {
            $values += [int]$argument.Value
        }
    }

    return @($values | Sort-Object -Unique)
}


function Remove-VKCSharpComment {
    <#
    .SYNOPSIS
        Strips C# block and line comments so only active code is examined.

    .DESCRIPTION
        Comments explaining an exclusion must not be mistaken for the
        excluded behaviour. This does not attempt to honour "//" inside a
        C# string literal; the interop body contains none, and a false
        NEGATIVE is not possible here because stripping only ever removes
        text.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Source)

    $withoutBlocks = $Source -replace '(?s)/\*.*?\*/', ''

    return (
        ($withoutBlocks -split "`r?`n" | ForEach-Object { $_ -replace '//.*$', '' }) -join "`n"
    )
}


function Get-VKCSharpWtsInfoClassLiteral {
    <#
    .SYNOPSIS
        Returns the literal information-class arguments of active
        WTSQuerySessionInformation calls in a C# body.

    .DESCRIPTION
        Comments are stripped first. A non-literal argument - the module
        passes a parameter named infoClass - yields no value, because there
        is no literal to report.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$CSharpSource)

    $active = Remove-VKCSharpComment -Source $CSharpSource

    $matchesFound = [regex]::Matches(
        $active,
        'WTSQuerySessionInformation\s*\(\s*[^,]+,\s*[^,]+,\s*(\d+)\s*,')

    return @($matchesFound | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique)
}


function Get-VKEmbeddedCSharpSource {
    <#
    .SYNOPSIS
        Extracts the WTS interop C# body from PowerShell source text.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Source)

    if ($Source -match "(?s)VKWtsSourceCodeDefinition\s*=\s*@'(.*?)'@") {
        return $Matches[1]
    }

    return ''
}
