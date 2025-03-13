[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Scope = 'Function', Target = 'Warp-*', Justification = 'Warp-* functions are ours')]
param()

# Wrap things in a module to avoid cluttering the global scope. We assign it to '$null' to suppress
# the console output from creating the module.
# NOTE: If you do need a function to be global and also have access to variables in this scope, add
# the function name to the 'Export-ModuleMember' call at the end.
$null = New-Module -Name Warp-Module -ScriptBlock {
    # Byte sequence used to signal the start of an OSC for Warp JSON messages.
    $oscStart = "$([char]0x1b)]9278;"

    # Appended to $oscStart to signal that the following message is JSON-encoded.
    $oscJsonMarker = 'd'

    $oscParamSeparator = ';'

    # Byte used to signal the end of an OSC for Warp JSON messages.
    $oscEnd = "$([char]0x07)"

    # Writes a hex-encoded JSON message to the PTY.
    function Warp-Send-JsonMessage([System.Collections.Hashtable]$table) {
        $json = ConvertTo-Json -InputObject $table -Compress
        # Sends a message to the controlling terminal as an OSC control sequence.
        # TODO(CORE-2718): Determine if we need to hex encode the payload.
        # Note that because the JSON string may contain characters that we don't control (including
        # unicode), we encode it as hexadecimal string to avoid prematurely calling unhook if
        # one of the bytes in JSON is 9c (ST) or other (CAN, SUB, ESC).
        $encodedMessage = Warp-Encode-HexString $json
        Write-Host -NoNewline "$oscStart$oscJsonMarker$oscParamSeparator$encodedMessage$oscEnd"
    }

    # This script block contains commands and constants that are needed in background threads.
    # If you want to be able to use it in a background thread, stick it in this block
    $warpCommon = {
        # OSC used to mark the start of in-band command output.
        #
        # Printable characters received this OSC and oscEndGeneratorOutput are parsed and handled as
        # output for an in-band command.
        $oscStartGeneratorOutput = "$([char]0x1b)]9277;A$oscEnd"

        # OSC used to mark the end of in-band command output.
        #
        # Printable characters received between oscStartGeneratorOutput and this are parsed and
        # handled as output for an in-band command.
        $oscEndGeneratorOutput = "$([char]0x1b)]9277;B$oscEnd"

        $oscResetGrid = "$([char]0x1b)]9279$oscEnd"

        function Warp-Send-ResetGridOSC() {
            Write-Host -NoNewline $oscResetGrid
        }

        # Encode a string as hex-encoded UTF-8.
        function Warp-Encode-HexString([string]$str) {
            [BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($str)).Replace('-', '')
        }

        # Hex-encodes the given argument and writes it to the PTY, wrapped in the OSC
        # sequences for generator output.
        #
        # The payload of the OSC is "<content_length>;<hex-encoded content>".
        function Warp-Send-GeneratorOutputOsc {
            param([string]$message)

            $hexEncodedMessage = Warp-Encode-HexString $message
            $byteCount = [System.Text.Encoding]::ASCII.GetByteCount($hexEncodedMessage)

            Write-Host -NoNewline "$oscStartGeneratorOutput$byteCount;$hexEncodedMessage$oscEndGeneratorOutput"
            Warp-Send-ResetGridOSC
        }

        # Do not run this in the main thread. It mucks around with some env vars
        function Warp-Run-InBandGenerator {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'We actually need it')]
            param([string]$commandId, [string]$command)

            try {
                # We do not have a good way to simultaneously capture
                # the command status $? and the command output of our command.
                # this is because Invoke-Expression will always set $? to true.
                # To get around this, we append a small bit of code to the original
                # command that makes Invoke-Expression throw if the last command
                # did not succeed.
                $modifiedCommand = "$command" + '; if (-Not $?) { throw }'

                # We set this immediately before running Invoke-Expression,
                # that way it will default to 0
                $LASTEXITCODE = 0

                # Note: parens are important here. Without them
                # parsing order gets messed up on the 2>&1
                $rawOutput = Invoke-Expression -Command "$modifiedCommand" 2>&1
                $exitCode = $LASTEXITCODE

                # If the generator command returns multi-line output,
                # we make sure to join the lines together with a newline, so
                # they are properly parsed by warp
                $stringifiedOutput = $rawOutput -Join "$([char]0x0a)"

                # This is a best-effort attempt to get an error code.
                # We cannot duplicate our error code logic from Warp-Precmd
                # b/c Invoke-Expression will swallow the value of $? and always
                # return true. So we do our best to return a legit error code
                Write-Output "$commandId;$stringifiedOutput;$exitCode"
            } catch {
                # This catches a terminating error (ex: entering a command that does not exist)
                # In this case, we return an error code of 1
                Write-Output "$commandId;1;"
            }
        }
    }

    # Load the Warp Common functions in the current session
    . $warpCommon

    # Implementation copied from here:
    # https://stackoverflow.com/questions/70977897/get-epoch-time-with-fractions-of-a-second-powershell
    function Warp-Get-EpochTime {
        [decimal]((((Get-Date).ToUniversalTime()) - (Get-Date '01/01/1970')).TotalSeconds)
    }

    function Warp-Bootstrapped {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'WARP_BOOTSTRAPPED', Justification = 'False positive as we are assigning to global')]
        param([decimal]$rcStartTime, [decimal]$rcEndTime)

        $envVarNames = (Get-ChildItem env: | Select-Object -ExpandProperty Name | ForEach-Object { 'env:' + $_ }) +
            (Get-Variable | Select-Object -ExpandProperty Name) -join ' '
        $aliasesRaw = Get-Command -CommandType Alias | Select-Object -ExpandProperty DisplayName
        $aliases = $aliasesRaw -join [Environment]::NewLine
        $functionNamesRaw = Get-Command -CommandType Function | Where-Object { -not $_.Name.StartsWith('Warp') } | Select-Object -ExpandProperty Name
        $functionNames = $functionNamesRaw -join [Environment]::NewLine
        $builtinsRaw = Get-Command -CommandType Cmdlet | Select-Object -ExpandProperty Name
        $builtins = $builtinsRaw -join [Environment]::NewLine
        $shellVersion = $PSVersionTable.PSVersion.ToString()
        # PowerShell wasn't cross-platform until version 6. Anything before that is definitely on Windows.
        $osCategory = if ($PSVersionTable.PSVersion.Major -le 5) {
            'Windows'
        } elseif ($IsLinux) {
            'Linux'
        } elseif ($IsMacOS) {
            'MacOS'
        } elseif ($IsWindows) {
            'Windows'
        } else {
            ''
        }

        # We do not have an equivalent to 'compgen -k' here, so we are dropping
        # in a hardcoded list. List is take from
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_reserved_words?view=powershell-7.4
        $PSKeywords = @(
            'begin', 'break', 'catch', 'class', 'continue', 'data', 'define',
            'do', 'dynamicparam', 'else', 'elseif', 'end', 'enum', 'exit',
            'filter', 'finally', 'for', 'foreach', 'from', 'function', 'hidden',
            'if', 'in', 'param', 'process', 'return', 'static', 'switch', 'throw',
            'trap', 'try', 'until', 'using', 'var', 'while', 'inlinescript',
            'parallel', 'sequence', 'workflow'
        ) -join [environment]::NewLine

        $linuxDistribution = $null
        if ($osCategory -eq 'Linux') {
            $osReleaseFile = if (Test-Path -Path '/etc/os-release') {
                '/etc/os-release'
            } elseif (Test-Path -Path '/usr/lib/os-release') {
                '/usr/lib/os-release'
            } else {
                $null
            }
            if ($null -ne $osReleaseFile) {
                # This is meant to be the equivalent to the bash command
                # cat $os_release_file | sed -nE 's/^NAME="(.*)"$/\1/p'. We filter
                # specifically for the Name= line of the osRelease file, and then
                # pull out the OS name
                $linuxDistribution = switch -Regex -File $osReleaseFile {
                    '^\s*NAME="(.*)"' {
                        $Matches[1]
                        break
                    }
                }
            }
        }

        # TODO(PLAT-681) - finish the information here
        # for keywords, see 'Get-Help about_Language_Keywords'
        $bootstrappedMsg = @{
            hook = 'Bootstrapped'
            value = @{
                histfile = $(Get-PSReadLineOption).HistorySavePath
                shell = 'pwsh'
                home_dir = "$HOME"
                path = $env:PATH
                env_var_names = $envVarNames
                abbreviations = ''
                aliases = $aliases
                function_names = $functionNames
                builtins = $builtins
                keywords = "$PSKeywords"
                shell_version = $shellVersion
                shell_options = ''
                rcfiles_start_time = "$rcStartTime"
                rcfiles_end_time = "$rcEndTime"
                shell_plugins = ''
                os_category = $osCategory
                linux_distribution = "$linuxDistribution"
            }
        }
        Warp-Send-JsonMessage $bootstrappedMsg
        $global:WARP_BOOTSTRAPPED = 1
    }

    function Warp-Preexec([string]$command) {
        $HOST.UI.RawUI.WindowTitle = $command
        $preexecMsg = @{
            hook = 'Preexec'
            value = @{
                command = $command
            }
        }
        Warp-Send-JsonMessage $preexecMsg
        Warp-Send-ResetGridOSC

        # If this preexec is called for user command, kill ongoing generator command jobs and clean
        # up the bookkeeping temp files used to bookkeep.
        if (-not "$command" -match '^Warp-Run-GeneratorCommand') {
            Warp-Stop-ActiveThread
        }

        # Clean up any completed warp jobs so they do not show up on the user's 'get-job'
        # comands
        Warp-Clean-CompletedThread

        # Remove any instance of the 'Warp-Run-GeneratorCommand' call from the user's history
        Clear-History -CommandLine 'Warp-Run-GeneratorCommand*'
    }

    function Warp-Finish-Update([string]$updateId) {
        $updateMsg = @{
            hook = 'FinishUpdate'
            value = @{
                update_id = $updateId
            }
        }
        Warp-Send-JsonMessage $updateMsg
    }

    function Warp-Handle-DistUpgrade {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'We actually need it')]
        param([string]$sourceFileName)

        $aptConfig = Get-Command -Type Application apt-config | Select-Object -First 1
        & $aptConfig shell '$aptSourcesDir' 'Dir::Etc::sourceparts/d' | Invoke-Expression

        $sourceFilePath = "${aptSourcesDir}${sourceFileName}"

        if (
            -not (Test-Path "${sourceFilePath}.list") -and
            -not (Test-Path "${sourceFilePath}.sources") -and
        (Test-Path "${sourceFilePath}.list.distUpgrade")
        ) {
            # DO NOT DO THIS. We should never run a command for user with 'sudo'. The only reason this
            # is safe here is because we insert this function into the input for the user to determine
            # if they want to execute (we never run it on their behalf without their permission).
            sudo cp "${sourceFilePath}.list.distUpgrade" "${sourceFilePath}.list"
        }
    }

    # We need this for a few reasons
    # 1. We need to make sure the environment variable GIT_OPTIONAL_LOCKS=0.
    #    See https://stackoverflow.com/questions/71836872/git-environment-variables-on-powershell-on-windows
    #    for why this is complicated
    # 2. We need to make sure that we are calling the Application git, and not
    #    an alias or cmdlet named Git
    #
    # NOTE: Inlining this call in the function has a weird side effect of outputing
    #    an escape sequence '^[i'. Since it made it more convenient to have a wrapper
    #    function anyway, I have not investigated this, but in case someone is working
    #    on this in the future, beware attempting to inline this function.
    function Warp-Git {
        $GIT_OPTIONAL_LOCKS = $env:GIT_OPTIONAL_LOCKS
        $env:GIT_OPTIONAL_LOCKS = 0
        try {
            &(Get-Command -CommandType Application git | Select-Object -First 1) $args
        } finally {
            $env:GIT_OPTIONAL_LOCKS = $GIT_OPTIONAL_LOCKS
        }
    }

    # Helper function that resets the values of '$?' and
    # $LASTEXITCODE. Note that it cannot force '$?' to $true
    # if it is currently $false
    #
    # Make sure when you call this you call it with -ErrorAction SilentlyContinue
    # or it will print out error information when it is invoked.
    function Warp-Restore-ErrorStatus {
        [CmdletBinding()]
        param([boolean]$status, [int]$code)

        $global:LASTEXITCODE = $code
        if ($status -eq $false) {
            $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                    [Exception]::new("$([char]0x00)"),
                    'warp-reset-error',
                    [System.Management.Automation.ErrorCategory]::NotSpecified,
                    $null
                ))
        }
    }

    # Tracks whether or not powershell is unable to find a command.
    # See the $ExecutionContext.InvokeCommand.CommandNotFoundAction where it is set to $true,
    # and both $ExecutionContext.InvokeCommand.PostCommandLookupAction and Warp-Precmd where
    # it is set to $false.
    $script:commandNotFound = $false

    function Warp-Configure-PSReadLine {
        # Set-PSReadLineKeyHandler is the PowerShell equivalent of zsh's bindkey.
        Set-PSReadLineKeyHandler -Chord 'Control+p' -Function BackwardDeleteLine

        # Input reporting
        Set-PSReadLineKeyHandler -Chord 'Alt+i' -ScriptBlock {
            $inputBuffer = $null
            $cursorPosition = $null
            [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$inputBuffer, [ref]$cursorPosition)
            $inputBufferMsg = @{
                hook = 'InputBuffer'
                value = @{
                    buffer = $inputBuffer
                }
            }
            Warp-Send-JsonMessage $inputBufferMsg
            [Microsoft.PowerShell.PSConsoleReadLine]::BackwardDeleteLine()
            # This is triggered after precmd, so output here goes to the "early output" handler,
            # i.e. the background block. This clears the line the cursor is on. We clear it out b/c
            # at this point, the only stuff in the early output handler is typeahead, and that
            # shouldn't be displayed in a background block at all. It should be in the input
            # editor. Most shells will automatically emit the correct ANSI escape codes to delete
            # the contents of the early output handler when we kill the line editor's buffer.
            # However, PowerShell doesn't do this correctly due to cursor position mismatch. So,
            # we do it manually here instead.
            Write-Host -NoNewline "$([char]0x1b)[2K"
        }

        # Sets the prompt mode to custom prompt (PS1)
        # Is the equivalent of warp_change_prompt_modes_to_ps1 in other shells
        Set-PSReadLineKeyHandler -Chord 'Alt+p' -ScriptBlock {
            $env:WARP_HONOR_PS1 = '1'
            Warp-Redraw-Prompt
        }

        # Sets the prompt mode to warp prompt
        # Is the equivalent of warp_change_prompt_modes_to_warp_prompt in other shells
        Set-PSReadLineKeyHandler -Chord 'Alt+w' -ScriptBlock {
            $env:WARP_HONOR_PS1 = '0'
            Warp-Redraw-Prompt
        }

        Set-PSReadLineOption -AddToHistoryHandler {
            param([string]$line)

            if ($line -match '^Warp-Run-GeneratorCommand') {
                return $false
            }
            return $true
        }

        Warp-Disable-PSPrediction
    }

    # Force use of the Inline PredictionViewStyle. The ListView style can occassionally cause some
    # flickering when using Warp and it doesn't matter what the value of this setting is because
    # Warp has its own input editor.
    function Warp-Disable-PSPrediction {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Errors are ignored')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '', Justification = 'Errors expected')]
        param()
        try {
            Set-PSReadLineOption -PredictionSource None
            Set-PSReadLineOption -PredictionViewStyle InlineView
        } catch {
        }
    }

    function Warp-Precmd {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Warp-Git should use positionals')]
        param([bool]$status, [int]$code)
        # Our logic here is:
        #
        # if $status == True, always set $exitCode to 0
        # if $status == False and $script:commandNotFound is true
        #     (meaning we triggered the CommandNotFoundHandler), set $exitCode to 127
        # if $status == False and $LASTEXITCODE is zero, set $exitCode to 1
        # else set $exitCode to $LASTEXITCODE
        #
        # Note that this is not going to be 100% accurate, as some cmdlets will fail
        # without setting a $LASTEXITCODE, meaning the $LASTEXITCODE will be stale.
        $warpCommandNotFound = $script:commandNotFound
        $script:commandNotFound = $false

        $exitCode = if ($status) {
            0
        } elseif ($warpCommandNotFound) {
            127
        } elseif ($code -eq 0) {
            1
        } else {
            $code
        }

        $newTitle = (Get-Location).Path
        # Replace the literal home dir with a tilde.
        if ($newTitle.StartsWith($HOME)) {
            $newTitle = '~' + $newTitle.Substring($HOME.length)
        }
        $HOST.UI.RawUI.WindowTitle = $newTitle

        $blockId = $script:nextBlockId++
        $commandFinishedMsg = @{
            hook = 'CommandFinished'
            value = @{
                exit_code = $exitCode
                next_block_id = "precmd-${global:_warpSessionId}-$blockId"
            }
        }
        Warp-Send-JsonMessage $commandFinishedMsg
        Warp-Send-ResetGridOSC

        Warp-Configure-PSReadLine

        # If this is being called for a generator command, short circuit and send an unpopulated
        # precmd payload (except for pwd), since we don't re-render the prompt after generator commands
        # are run.
        if ($script:generatorCommand -eq $true) {
            # TODO(CORE-2639): handle user PreCmds here

            $script:generatorCommand = $false

            $precmdMsg = @{
                hook = 'Precmd'
                value = @{
                    pwd = ''
                    ps1 = ''
                    git_branch = ''
                    virtual_env = ''
                    conda_env = ''
                    session_id = $global:_warpSessionId
                }
            }
            Warp-Send-JsonMessage $precmdMsg
        } else {
            # TODO(CORE-2678): Figure out resetting bindkeys here

            $virtualEnv = ''
            $condaEnv = ''
            $kubeConfig = ''
            $gitBranch = ''

            # Only fill these fields once we've finished bootstrapping, as the
            # blocks created during the bootstrap process don't have visible
            # prompts, and we don't want to invoke 'git' before we've sourced the
            # user's rcfiles and have a fully-populated PATH.
            if ($global:WARP_BOOTSTRAPPED -eq 1) {
                if (Test-Path env:VIRTUAL_ENV) {
                    $virtualEnv = $env:VIRTUAL_ENV
                }
                if (Test-Path env:CONDA_DEFAULT_ENV) {
                    $condaEnv = $env:CONDA_DEFAULT_ENV
                }
                if (Test-Path env:KUBECONFIG) {
                    $kubeConfig = $env:KUBECONFIG
                }

                # We do not inline $hasGitCommand b/c the linter does not like seeing '>'
                # in an if statement; it thinks we are trying to do -gt incorrectly.
                # Since this is a good warning and we do not want to turn off this lint rule,
                # we do a little indirection here
                $hasGitCommand = Get-Command -CommandType Application git 2>$null
                if ($hasGitCommand) {
                    # This is deliberately not using || b/c || only works in Powershell >=7
                    $gitBranchTmp = Warp-Git symbolic-ref --short HEAD 2>$null
                    if ($null -eq $gitBranchTmp) {
                        $gitBranchTmp = Warp-Git rev-parse --short HEAD 2>$null
                    }
                    if ($null -ne $gitBranchTmp) {
                        $gitBranch = $gitBranchTmp
                    }
                }
            }

            $honor_ps1 = "$env:WARP_HONOR_PS1" -eq '1'

            $precmdMsg = @{
                hook = 'Precmd'
                value = @{
                    pwd = (Get-Location).Path
                    # TODO(PLAT-687) - honor the PS1
                    ps1 = ''
                    honor_ps1 = $honor_ps1
                    # TODO(PLAT-687) - pwsh does not by default support rprompt, but
                    # oh-my-posh does. If there is a way to easily extract the oh-my-posh
                    # rprompt, we might want to use it here
                    rprompt = ''
                    git_branch = $gitBranch
                    virtual_env = $virtualEnv
                    conda_env = $condaEnv
                    session_id = $global:_warpSessionId
                    kube_config = $kubeConfig
                }
            }
            Warp-Send-JsonMessage $precmdMsg
        }
    }

    $script:inBandCommandCount = 0
    $script:threadInner = @{}
    $script:threadOuter = @{}

    # The inner runspace pool maintains a pool of runspaces that can execute
    # arbitrary commands against the user's current environment without
    # writing to the screen. Initialize to minimum of 10 runspaces
    # to handle double the number of context chips we currently have
    # that use in-band commands
    $script:innerRunspacePool = [runspacefactory]::CreateRunspacePool(10, 20)
    $script:innerRunspacePool.ApartmentState = [System.Threading.ApartmentState]::STA
    $script:innerRunspacePool.ThreadOptions = 'ReuseThread'
    $script:innerRunspacePool.Open() | Out-Null

    # The outer runspace pool maintains a pool of runspaces that
    # share the same host as the user's session. This allows them
    # to send OSC commands via Write-Host. These outer runspaces
    # handle receiving results from the inner runspaces and formatting
    # those results into OSCs.
    # Initialized to minimum of 5 runspaces since we currently do not
    # run more than one outer command at a time.
    $script:outerRunspacePool = [runspacefactory]::CreateRunspacePool(5, 10, $Host)
    $script:outerRunspacePool.ApartmentState = [System.Threading.ApartmentState]::STA
    $script:outerRunspacePool.ThreadOptions = 'ReuseThread'
    $script:outerRunspacePool.Open() | Out-Null

    class WarpGeneratorCommand {
        [string]$CommandId
        [string]$Command
    }

    function Warp-Run-GeneratorCommandImpl {
        param(
            [WarpGeneratorCommand[]]$commands
        )

        $jobNumber = $script:inBandCommandCount++

        $batchNumber = 0
        $jobs = $commands | ForEach-Object {
            $commandId = $_.CommandId
            $command = $_.Command

            # Creates a powershell instance on one of our inner runspaces
            # that first loads all the warp common functions, and then
            # executes the in-band generator in the current directory
            $ps = [powershell]::Create()
            $ps.RunspacePool = $script:innerRunspacePool
            $ps.AddScript($warpCommon) | Out-Null
            $ps.AddScript({
                    param([string]$loc, [string]$commandId, [string]$command)
                    Set-Location $loc
                    Warp-Run-InBandGenerator -commandId $commandId -command "$command"
                }).AddParameters(@($PWD.Path, $commandId, "$command")) | Out-Null

            $script:threadInner["Warp-Inner-$jobNumber-$batchNumber"] = $psInner
            $batchNumber++

            @{
                commandId = $commandId
                ps = $ps
            }
        }

        # Creates the outer job, which waits on all the inner jobs
        # and then sends the results back to Warp via OSC
        $psOuter = [powershell]::Create()
        $psOuter.RunspacePool = $script:outerRunspacePool
        $psOuter.AddScript($warpCommon) | Out-Null
        $psOuter.AddScript({
                param([object[]]$jobs)

                $invocations = $jobs | ForEach-Object {
                    @{
                        commandId = $_.commandId
                        ps = $_.ps
                        async = $_.ps.BeginInvoke()
                    }
                }

                $invocations | ForEach-Object {
                    $commandId = $_.commandId
                    $ps = $_.ps
                    $async = $_.async

                    $output = "$commandId;1;"

                    try {
                        $output = $ps.EndInvoke($async)
                    } catch {
                        $output = "$commandId;1;"
                    }
                    Warp-Send-GeneratorOutputOsc $output
                }
            }).AddParameters(@($jobs)) | Out-Null

        # Note: we are beginning the invocation, but are explicitly
        # not stopping it as we do not want to block the main thread.
        $async = $psOuter.BeginInvoke()

        $script:threadOuter["Warp-Outer-$jobNumber"] = $psOuter
    }

    function Warp-Stop-ActiveThread {
        $script:threadInner.values | ForEach-Object {
            $_.Stop()
        }
    }

    function Warp-Clean-CompletedThread {
        # Powershell instances states > 2 are terminal.
        # See https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.psinvocationstate
        if ($script:threadInner.Count -gt 0) {
            $script:threadInner.Keys.Clone() | ForEach-Object {
                $thread = $script:threadInner[$_]
                $state = [int]$thread.InvocationStateInfo.State
                if ($state -gt 2) {
                    $thread.Dispose()
                    $script:threadInner.Remove($_)
                }
            }
        }
        if ($script:threadOuter.Count -gt 0) {
            $script:threadOuter.Keys.Clone() | ForEach-Object {
                $thread = $script:threadOuter[$_]
                $state = [int]$thread.InvocationStateInfo.State
                if ($state -gt 2) {
                    $thread.Dispose()
                    $script:threadOuter.Remove($_)
                }
            }
        }
    }

    function Warp-Run-GeneratorCommand {
        [CmdletBinding()]
        param(
            [parameter(ValueFromRemainingArguments = $true)][string[]]$passedArgs
        )

        $status = $?
        $code = $global:LASTEXITCODE

        # Setting this environment variable prevents warp_precmd from emitting the
        # 'Block started' hook to the Rust app.
        $script:generatorCommand = $true

        # TODO(CORE-2639) If we ever start supporting user precmd or preexec
        # (which doesn't really exist in powershell, but :shrug:), we need
        # to properly handle them here like we do in bashzshfish

        # Converts the passed in args to WarpGeneratorCommand objects to group them together
        # note that if an odd number of arguments is passed in, the last arg will be silently ignored
        [WarpGeneratorCommand[]] $jobs = @()
        for ($i = 0; $i -lt $passedArgs.Length; $i += 2) {
            $commandId = $passedArgs[$i]
            $command = $passedArgs[$i + 1]

            if ($null -ne $command) {
                $jobs += [WarpGeneratorCommand]@{
                    commandId = $commandId
                    command = $command
                }
            }
        }

        try {
            Warp-Run-GeneratorCommandImpl -commands $jobs
        } finally {
            # NOTE: for some reason the Warp-Restore-ErrorStatus does not work
            # for this function, so we are inlining it in here.
            $global:LASTEXITCODE = $code
            if ($status -eq $false) {
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new(
                        [Exception]::new("$([char]0x00)"),
                        'warp-reset-error',
                        [System.Management.Automation.ErrorCategory]::NotSpecified,
                        $null
                    ))
            }
        }

    }

    function Warp-Render-Prompt {
        param([bool]$status, [int]$code, [bool]$isGeneratorCommand)

        # If this is a generator command, we do not want to recompute
        # the prompt, and instead want to return the original prompt.
        if ($isGeneratorCommand) {
            return $script:lastRenderedPrompt
        }

        # Reset error code for computing prompt
        $global:LASTEXITCODE = $code
        if (-not $status) {
            # Set's $? to false for the next function call,
            # so it can be used for computing the prompt
            Write-Error '' -ErrorAction Ignore
        }

        # Compute prompt and cache it as the last rendered prompt
        $basePrompt = & $global:_warpOriginalPrompt
        $script:lastRenderedPrompt = $basePrompt

        return $basePrompt
    }

    function Warp-Decorate-Prompt {
        param([string]$basePrompt)

        $e = "$([char]0x1b)"

        # Wrap prompt in Prompt Marker OSCs
        $startPromptMarker = "$e]133;A$oscEnd"
        $startRPromptMarker = "$e]133;P;k=r$oscEnd"
        if ("$env:WARP_HONOR_PS1" -eq '0') {
            $endPromptMarker = "$e]133;B$oscEnd$oscResetGrid"
        } else {
            $endPromptMarker = "$e]133;B$oscEnd"
        }
        $decoratedPrompt = "$basePrompt"

        # We only redecorate the prompt if it is not already decorated
        if (-Not ($basePrompt -Match '^\x1b]133;A')) {
            $decoratedPrompt = "$startPromptMarker$basePrompt$endPromptMarker"
            # Special case for ohmyposh that prints an rprompt. If it matches the format of ohmyposh
            # rprompt, we properly parse it into lprompt and rprompt
            if ($basePrompt -Match '(?<lprompt>.*)[\x1b]7\s*(?<rprompt>\S.*)[\x1b]8') {
                $lprompt = $Matches.lprompt
                $rprompt = $Matches.rprompt
                $decoratedPrompt = "$startPromptMarker$lprompt$endPromptMarker${e}7$startRPromptMarker$rprompt$endPromptMarker${e}8"
            }
        }

        return $decoratedPrompt
    }

    $script:dontRunPrecmdForPrompt = $false
    # Redraws the prompt. Since our prompt also triggers the precmd hook
    # we need to signal that we do not want that to happen
    function Warp-Redraw-Prompt {
        param()

        $y = $Host.UI.RawUI.CursorPosition.Y
        $script:dontRunPrecmdForPrompt = $true
        try {
            [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt($null, $y)
        } finally {
            $script:dontRunPrecmdForPrompt = $false
        }
    }

    function Warp-Prompt {
        param()

        # We need to capture all the data related to exit codes and such
        # as soon as possible for a few reasons
        # 1. We need to make sure that these values are as fresh as possible
        #    and are not impacted by our Warp- functions
        # 2. After we finish running Warp-Precmd and Warp-Render-Prompt, we want to set these values
        #    back to what they were originally
        $status = $?
        $code = $LASTEXITCODE
        $isGeneratorCommand = [bool]($script:generatorCommand -eq $true)

        if ($script:dontRunPrecmdForPrompt -ne $true) {
            Warp-Precmd -status $status -code $code
        }

        $script:preexecHandled = $false

        $renderedPrompt = Warp-Render-Prompt -status $status -code $code -isGeneratorCommand $isGeneratorCommand
        $decoratedPrompt = Warp-Decorate-Prompt -basePrompt $renderedPrompt
        $extraLines = ($decoratedPrompt -split "$([char]0x0a)").Length - 1
        Set-PSReadLineOption -ExtraPromptLineCount $extraLines

        # NOTE: Because we are in the prompt, we do not need to reset
        # the $? automatic variable (apparently $prompt does not impact it).
        # However, we do need to reset the LASTEXITCODE. If we ever refactor
        # this to not use the prompt, then watch out for $?
        $global:LASTEXITCODE = $code

        return $decoratedPrompt
    }

    if ((Test-Path env:WARP_INITIAL_WORKING_DIR) -and -not [String]::IsNullOrEmpty($env:WARP_INITIAL_WORKING_DIR)) {
        Set-Location $env:WARP_INITIAL_WORKING_DIR 2> $null
        Remove-Item -Path env:WARP_INITIAL_WORKING_DIR
    }

    # In some cases, the Clear-Host command will not interface properly with the blocklist.
    # Clear-Host defers to whatever the 'clear' command is defined, and if that command
    # is not set up to work with Warp (or has funky other behaviors) it can cause problems.
    #
    # Specific examples:
    # - The default /usr/bin/clear on mac creates a giant, empty block to clear content
    #   off of the screen.
    # - if miniconda is installed on an osx system, the miniconda 'clear' command will be
    #   invoked for 'Clear-Host', which does not play with Warp and winds up doing nothing.

    # Because of the above, we explicitly override both 'Clear-Host' and 'clear' to
    # instead send a DCS command to Warp instructing it to clear the blocklist.
    # We are explicitly NOT calling the underlying clear implementation:
    # 1. B/c traditional clear sends an escape sequence that ends up creating an
    #    empty block that is the full height of the screen.
    # 1. B/c our other bootstrap scripts (bash, zsh, fish) do not.

    # If we ever want to call the underlying clear command, we could do so by:
    # 1. Capturing it with '$_warp_original_clear = (Get-Command Clear-Host).Definition'
    # 2. Invoking it with 'Invoke-Expression $_warp_original_clear'

    # TODO(PLAT-781): On windows, these two functions should both clear the visible screen
    # AND the scrollback
    function Clear-Host() {
        $inputBufferMsg = @{
            hook = 'Clear'
            value = @{}
        }
        Warp-Send-JsonMessage $inputBufferMsg
    }

    function clear() {
        $inputBufferMsg = @{
            hook = 'Clear'
            value = @{}
        }
        Warp-Send-JsonMessage $inputBufferMsg
    }

    function Warp-Finish-Bootstrap {
        param([decimal]$rcStartTime, [decimal]$rcEndTime)
        # This is the closest we can get in PowerShell to a proper preexec hook. We wrap the
        # invocation of PSConsoleHostReadline, and call our preexec hook before returning the
        # returned value. This allows us to preserve the any custom implementations of
        # PSConsoleHostReadLine.
        $script:oldPSConsoleHostReadLine = $function:global:PSConsoleHostReadLine
        $function:global:PSConsoleHostReadLine = {
            $line = & $script:oldPSConsoleHostReadLine

            Warp-Preexec "$line"

            $line
        }

        # This handles the case when a command is not found (ex "ehco foo"). As long as it is a
        # user-executed command, we set the $script:commandNotFound variable to $true, so we know
        # that the command failed b/c of a command lookup failure.
        $ExecutionContext.InvokeCommand.CommandNotFoundAction = {
            $commandLine = $MyInvocation.Line
            # Only trigger the preexec hook for user-submitted commands
            # $EventArgs.CommandOrigin is either 'Runspace' or 'Internal'. Internal commands are run
            # automatically by PowerShell internals. Runspace is for user-submitted/configured stuff.
            # However, Runspace still includes stuff like the prompt function, PostCommandLookupAction,
            # and the stuff we set during this bootstrap. So, add a condition to prevent preexec from
            # triggering in those cases. Note that we prefix our own functions with the "Warp-" prefix
            # so that we can ignore them here.
            if ($EventArgs.CommandOrigin -ne 'Runspace' -or ($commandLine -match '^prompt$|^Warp-')) {
                return
            }
            $script:commandNotFound = $true
        }

        # This sets up our wrapper around $function:prompt, which runs the precmd hook
        # and computes the user's custom prompt.
        $function:global:prompt = (Get-Command Warp-Prompt).ScriptBlock
        Warp-Bootstrapped -rcStartTime $rcStartTime -rcEndTime $rcEndTime
    }

    ###########################################################
    # NOTE: NO non-bootstrap / non-user calls below this line #
    ###########################################################

    # Send a precmd message to the terminal to differentiate between the warp
    # bootstrap logic pasted into the PTY and the output of shell startup files.
    Warp-Precmd -status $global:? -code $global:LASTEXITCODE

    Export-ModuleMember -Function clear, Clear-Host, Warp-Get-EpochTime, Warp-Finish-Update, Warp-Handle-DistUpgrade, Warp-Run-GeneratorCommand, Warp-Finish-Bootstrap
}

# Finally, get ready to source the user's RC files. This must be done in the global scope (not
# inside Warp-Module) in order to obey the expected scoping in PowerShell's typical startup process.
. {
    # Reset the prompt to the original prompt that loaded with powershell.
    # This way, if a user profile changes the prompt and wants to wrap
    # the original PS prompt, they can access it. Important b/c we do NOT
    # want profiles to capture our noop prompt that we set in pwsh_init_shell.
    # We ran into this with ZPosition, and it lead to a broken terminal.
    $warpInitPrompt = $function:global:prompt
    $function:global:prompt = $global:_warpOriginalPrompt

    $rcStartTime = Warp-Get-EpochTime
    # Source the user's RC files
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.4#profile-types-and-locations
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.4#the-profile-variable
    foreach ($file in @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)) {
        if ([System.IO.File]::Exists($file)) {
            . $file
        }
    }

    # This is a workaround for oh-my-posh's "transient prompt" feature. When enabled, it causes the
    # whole screen to clear on every command execution. It is implemented by overwriting the Enter
    # and ctrl-c key handlers. Resetting those back to default effectively disables it.
    # TODO(CORE-3234) - Find a workaround which allows transient prompt to work.
    $enterHandler = Get-PSReadLineKeyHandler | Where-Object -Property Key -EQ -Value 'Enter'
    if ($enterHandler -ne $null -and $enterHandler.Function -eq 'OhMyPoshEnterKeyHandler') {
        Set-PSReadLineKeyHandler -Chord Enter -Function AcceptLine
    }
    $ctrlcHandler = Get-PSReadLineKeyHandler | Where-Object -Property Key -EQ -Value 'Control+c'
    if ($ctrlcHandler -ne $null -and $ctrlcHandler.Function -eq 'OhMyPoshCtrlCKeyHandler') {
        Set-PSReadLineKeyHandler -Chord 'Control+c' -Function CopyOrCancelLine
    }

    $rcEndTime = Warp-Get-EpochTime

    # Capture the current prompt (potentially modified by a profile),
    # and then reset the prompt to our current noop prompt.
    $global:_warpOriginalPrompt = $function:global:prompt
    $function:global:prompt = $warpInitPrompt

    Warp-Finish-Bootstrap -rcStartTime $rcStartTime -rcEndTime $rcEndTime
    Remove-Variable -Name enterHandler, ctrlcHandler, warpInitPrompt, rcStartTime, rcEndTime -Scope global -ErrorAction Ignore

    # Restore the process's original execution policy now that the user's RC files have been loaded.
    if ($PSEdition -eq 'Desktop' -or $IsWindows) {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy $global:_warp_PSProcessExecPolicy
    }
}

# SIG # Begin signature block
# MII+NAYJKoZIhvcNAQcCoII+JTCCPiECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUj24sOeBwIoWh
# cY/PkoC6Kd3TJC4TsSVOXZAAn1kxnKCCIvYwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggcPMIIE96ADAgECAhMzAAH55+nN
# q9cb495xAAAAAfnnMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDEwHhcNMjUwMzA2MDcyMTIwWhcNMjUwMzA5
# MDcyMTIwWjCBjTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE5ldyBZb3JrMREwDwYD
# VQQHEwhOZXcgWW9yazErMCkGA1UEChMiRGVudmVyIFRlY2hub2xvZ2llcywgSW5j
# LiBkYmEgV2FycDErMCkGA1UEAxMiRGVudmVyIFRlY2hub2xvZ2llcywgSW5jLiBk
# YmEgV2FycDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAJCHssGDoRin
# irbMkmmQOYZHzfaGDFkzEy+bl8IG2XiMuELwYEStZhvBHX3sWddCug/3IRWRCRwa
# uzFkiv8rJTGabUTEoIkMn0s3dj90O4cdzOYXWbTWKkgSfXaZO3uha7rvn1tin4xV
# fDAd02Buki3XXVnmUJM67ruWKkobS8LzfCKgR2Bw2xVDcZFvf5Nn/z61aP8GDLei
# /ChisrQ0mnARdl1I4qUE9CEhF3Yuni1lH0S9m5XTT8XOOCiDhbZY9A3a4BkEqe+J
# MTz5ByzbKhaoch1IMUBT82UEChzAAIUz6kCuP7ZCFx4J8IGSHFcXuoEJDkdH5LQp
# mY70Xx+kQLKwagPWA4jdtNf+JlR99ueKvWEf8lEQDLbe7IHPxEmQtB5+x7TBh2zq
# 3i3Ck5VK6zECTltXR2IV8GxX1UiD1Wqna6xsJqf9swFPI25tMIS/Li784Sy/2jsa
# kiRXkn3yLJknVYBwlMO6P8qpeDuvOVtUTXkujqC94pcDubT/9ImnHQIDAQABo4IC
# GDCCAhQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwOwYDVR0lBDQwMgYK
# KwYBBAGCN2EBAAYIKwYBBQUHAwMGGisGAQQBgjdhgpDv2jHKof5agpXp5jTT+sAV
# MB0GA1UdDgQWBBT5/PlO7bXKLyGOu4iqI8mLQZ5+ejAfBgNVHSMEGDAWgBR2nDZ0
# E9GQfWFfswLrgPSZS6U+hTBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVk
# JTIwQ1MlMjBFT0MlMjBDQSUyMDAxLmNybDCBpQYIKwYBBQUHAQEEgZgwgZUwZAYI
# KwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAwMS5j
# cnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2Nz
# cDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQBBidU/7tNJZVPSYkjM0XHld0we
# T3kqNc8ywgb5q2ITNmi1+WxLdGXXdx7obIUxlnPUSvb7letSVnSMly+c6AjLsPlT
# n+csmcoifTDVN9rcmOOMwETGnr8axbHUjrentN1CzJcfrHg1I+2GDZ7gj1ghoeq7
# hRCPJUBOo/nAX7x3J/9XQxFK5aGJY82RpQO/pMLZyOlLUCvMTajj9+LIgDLurFDH
# ZKG6HmjdZB+lnl7ErimuY0joLPJf61uafks68aeBtklZBOyjI9+vzyD6QPzZDHeg
# 8kZs6D/1VHz1Ac5//j/x/ma2TiynRHtNGXg3zYLskXzzv0HYxNqPUftklHuvMcLB
# 20s6A5RaZcpLbNVzP8Es6j/4N32OZyd1YD73WsfFTHkDo5gOmemqFhkktIAovT9e
# nO4TCpSH3jxF4hU9a9PAhtl1YuTCuIz4IFoECHk4M8MWApDyzkJJyXupnS232uQl
# wAvcyh/OdOhaOchCdglxREud5xj+FZQVH+Ob0Hkr7ZdmB73sPzGyuOSOWLURY2ef
# R+yhthqwV49WPeJRVQ204TVCWQ1TJrLBsvCAaLG2bgSw7KXt1KkPXWj3rg1tkkN4
# j6CZpn8Zpavcsh1rFHGPiXasjUElPa/ENlfy7OwGRungYTFxP+60BMPZ9FpZ5+IY
# LlSFxwsm3ZsAqxtzojCCBw8wggT3oAMCAQICEzMAAfnn6c2r1xvj3nEAAAAB+ecw
# DQYJKoZIhvcNAQEMBQAwWjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0IElEIFZlcmlmaWVkIENT
# IEVPQyBDQSAwMTAeFw0yNTAzMDYwNzIxMjBaFw0yNTAzMDkwNzIxMjBaMIGNMQsw
# CQYDVQQGEwJVUzERMA8GA1UECBMITmV3IFlvcmsxETAPBgNVBAcTCE5ldyBZb3Jr
# MSswKQYDVQQKEyJEZW52ZXIgVGVjaG5vbG9naWVzLCBJbmMuIGRiYSBXYXJwMSsw
# KQYDVQQDEyJEZW52ZXIgVGVjaG5vbG9naWVzLCBJbmMuIGRiYSBXYXJwMIIBojAN
# BgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAkIeywYOhGKeKtsySaZA5hkfN9oYM
# WTMTL5uXwgbZeIy4QvBgRK1mG8EdfexZ10K6D/chFZEJHBq7MWSK/yslMZptRMSg
# iQyfSzd2P3Q7hx3M5hdZtNYqSBJ9dpk7e6Fruu+fW2KfjFV8MB3TYG6SLdddWeZQ
# kzruu5YqShtLwvN8IqBHYHDbFUNxkW9/k2f/PrVo/wYMt6L8KGKytDSacBF2XUji
# pQT0ISEXdi6eLWUfRL2bldNPxc44KIOFtlj0DdrgGQSp74kxPPkHLNsqFqhyHUgx
# QFPzZQQKHMAAhTPqQK4/tkIXHgnwgZIcVxe6gQkOR0fktCmZjvRfH6RAsrBqA9YD
# iN201/4mVH3254q9YR/yURAMtt7sgc/ESZC0Hn7HtMGHbOreLcKTlUrrMQJOW1dH
# YhXwbFfVSIPVaqdrrGwmp/2zAU8jbm0whL8uLvzhLL/aOxqSJFeSffIsmSdVgHCU
# w7o/yql4O685W1RNeS6OoL3ilwO5tP/0iacdAgMBAAGjggIYMIICFDAMBgNVHRMB
# Af8EAjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3YQEABggr
# BgEFBQcDAwYaKwYBBAGCN2GCkO/aMcqh/lqClenmNNP6wBUwHQYDVR0OBBYEFPn8
# +U7ttcovIY67iKojyYtBnn56MB8GA1UdIwQYMBaAFHacNnQT0ZB9YV+zAuuA9JlL
# pT6FMGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUy
# MENBJTIwMDEuY3JsMIGlBggrBgEFBQcBAQSBmDCBlTBkBggrBgEFBQcwAoZYaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJ
# RCUyMFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAxLmNydDAtBggrBgEFBQcw
# AYYhaHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMGYGA1UdIARfMF0w
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAEwDQYJ
# KoZIhvcNAQEMBQADggIBAEGJ1T/u00llU9JiSMzRceV3TB5PeSo1zzLCBvmrYhM2
# aLX5bEt0Zdd3HuhshTGWc9RK9vuV61JWdIyXL5zoCMuw+VOf5yyZyiJ9MNU32tyY
# 44zARMaevxrFsdSOt6e03ULMlx+seDUj7YYNnuCPWCGh6ruFEI8lQE6j+cBfvHcn
# /1dDEUrloYljzZGlA7+kwtnI6UtQK8xNqOP34siAMu6sUMdkoboeaN1kH6WeXsSu
# Ka5jSOgs8l/rW5p+Szrxp4G2SVkE7KMj36/PIPpA/NkMd6DyRmzoP/VUfPUBzn/+
# P/H+ZrZOLKdEe00ZeDfNguyRfPO/QdjE2o9R+2SUe68xwsHbSzoDlFplykts1XM/
# wSzqP/g3fY5nJ3VgPvdax8VMeQOjmA6Z6aoWGSS0gCi9P16c7hMKlIfePEXiFT1r
# 08CG2XVi5MK4jPggWgQIeTgzwxYCkPLOQknJe6mdLbfa5CXAC9zKH8506Fo5yEJ2
# CXFES53nGP4VlBUf45vQeSvtl2YHvew/MbK45I5YtRFjZ59H7KG2GrBXj1Y94lFV
# DbThNUJZDVMmssGy8IBosbZuBLDspe3UqQ9daPeuDW2SQ3iPoJmmfxmlq9yyHWsU
# cY+JdqyNQSU9r8Q2V/Ls7AZG6eBhMXE/7rQEw9n0Wlnn4hguVIXHCybdmwCrG3Oi
# MIIHWjCCBUKgAwIBAgITMwAAAAZKGvrPBWFqdAAAAAAABjANBgkqhkiG9w0BAQwF
# ADBjMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTQwMgYDVQQDEytNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ29kZSBTaWduaW5nIFBD
# QSAyMDIxMB4XDTIxMDQxMzE3MzE1NFoXDTI2MDQxMzE3MzE1NFowWjELMAkGA1UE
# BhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMi
# TWljcm9zb2Z0IElEIFZlcmlmaWVkIENTIEVPQyBDQSAwMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAMfjyD/0Id3GGcC7xcurrieH06d5Z+xqrO7PJU1c
# n4DiVj9WgAcJNv6MXVY30h1KuDEz14pS+e6ov3x+2J3RCuCp3d7uXHnRcK9mh0k6
# er5fzy9XQC/bH6A7zaXRtDf0fOAIWDaQUE4aTuPwasZgoJd4iEX4YdqBVTrok4g1
# Vr1wYO+m3I5x5xBLV87wFsCbtGwVO6EUakHneFVybSAlbfmaClEo6mOcFJYQHcB4
# ft9QZ6QTwsxbSlYi6esxLUcjsUXoGoBVPsi4F775ndOyAzdEtky2LomY08PpHGDr
# aDYCq+5NAuhPVn9x+Ix2r5NjMahabYHy9IC/s20m/lQTSolU9Jqs1ySCZlpqsNCv
# g9zCn5gnq93twm6z/heUbQm9F2hNLkXCT2SY1sHIgwcQSG5DReBi9doZeb8nYBTJ
# s0HDbqHSsl//95Sydattq6B1UtXILbC4KY1mGZQZYQk3FyXmd8bmib12Qfa3Cwl9
# eToFy9tbVFMCQixNu1eQBmcZDt4ueJoEgrMLTpllOACnfwf3tyrV7+lwVESrgLXn
# s9RKYJaGmcEHo/ZeXTfVIfFtfQWYPSJS5fsR0V+Lw4jFgFH/+wDXuDKEvfBeOa++
# iBidIQtNhDLjGcQBK8GY9JZ9Gi+dxM5TGuSQokTm29FKCx3xknTSbDINLo9wwEA3
# VVkxAgMBAAGjggIOMIICCjAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMC
# AQAwHQYDVR0OBBYEFHacNnQT0ZB9YV+zAuuA9JlLpT6FMFQGA1UdIARNMEswSQYE
# VR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBD
# AEEwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTZQSmwDw9jbO9p1/XN
# KZ6kSGow5jBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlmaWVkJTIwQ29kZSUy
# MFNpZ25pbmclMjBQQ0ElMjAyMDIxLmNybDCBrgYIKwYBBQUHAQEEgaEwgZ4wbQYI
# KwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENB
# JTIwMjAyMS5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29m
# dC5jb20vb2NzcDANBgkqhkiG9w0BAQwFAAOCAgEAai8Jn9iwdUI1IGtBu8xZGxnf
# DQUCxz9CjhQVjSRWYk7Sn6TtG2dln7Or+b6iCoxN9kOjPPRuGZFXL1rhAAPnb4y0
# 4UsvPWNP/5v1k0isGLYkdRMJ+8dZMPxYPd8EKbNgtVlI/tNP+rjaxfneDFScVdR6
# ASA/veWSFtCpKmaKZzgOMObz+E+XAaa2UAJT/7zBsgdB/fqRzaNI0/UPIHyiTcx0
# vYtQ4AZprnxnVvUwcrp6PBgIsxTIS5SLNPG+ZYpSJBOc9xTAFAK/l4CCNRTWZ2+N
# ziOkHdszoo242H7q7F1AjRwvkUsCRpuVC8z8pmIIJyfpISTqu6EpajxqW6+9IRgX
# j8Pye/5pkqqe4U4LdJj4pEtYuGqfMfj98npmEoZxa4Fde+dkyPgLOvS34C7YZCE7
# 3+2xRwfL5iIWnWQjktL0wsdwfvzlXBDCzTtmydDvYpHNSakdBb6se5wMDEUodxVa
# qLIMwW1p1ZECau6FhcDFXxSGJ+iz0WTLePLuojFAhQUj3XbDwP+pPOZhL/tPFOVg
# kO8nY9SlVdkx63v/Jix4npvcH/ws6IakZ7cTNhP8fjR8ukwTJ0j0EaoYTX7joFAw
# FhGJpTP2RxmjyG+8Tr31ci0P+5emH6IE93qbcKeBjhkYx+c/oBvZKQSMfEK0Zejo
# pZ5cURMaJJjH5S+5ddkwggeeMIIFhqADAgECAhMzAAAAB4ejNKN7pY4cAAAAAAAH
# MA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVudGl0eSBWZXJp
# ZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAyMDAeFw0yMTA0
# MDEyMDA1MjBaFw0zNjA0MDEyMDE1MjBaMGMxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNDAyBgNVBAMTK01pY3Jvc29mdCBJRCBW
# ZXJpZmllZCBDb2RlIFNpZ25pbmcgUENBIDIwMjEwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCy8MCvGYgo4t1UekxJbGkIVQm0Uv96SvjB6yUo92cXdylN
# 65Xy96q2YpWCiTas7QPTkGnK9QMKDXB2ygS27EAIQZyAd+M8X+dmw6SDtzSZXyGk
# xP8a8Hi6EO9Zcwh5A+wOALNQbNO+iLvpgOnEM7GGB/wm5dYnMEOguua1OFfTUITV
# MIK8faxkP/4fPdEPCXYyy8NJ1fmskNhW5HduNqPZB/NkWbB9xxMqowAeWvPgHtpz
# yD3PLGVOmRO4ka0WcsEZqyg6efk3JiV/TEX39uNVGjgbODZhzspHvKFNU2K5MYfm
# Hh4H1qObU4JKEjKGsqqA6RziybPqhvE74fEp4n1tiY9/ootdU0vPxRp4BGjQFq28
# nzawuvaCqUUF2PWxh+o5/TRCb/cHhcYU8Mr8fTiS15kRmwFFzdVPZ3+JV3s5MulI
# f3II5FXeghlAH9CvicPhhP+VaSFW3Da/azROdEm5sv+EUwhBrzqtxoYyE2wmuHKw
# s00x4GGIx7NTWznOm6x/niqVi7a/mxnnMvQq8EMse0vwX2CfqM7Le/smbRtsEeOt
# bnJBbtLfoAsC3TdAOnBbUkbUfG78VRclsE7YDDBUbgWt75lDk53yi7C3n0WkHFU4
# EZ83i83abd9nHWCqfnYa9qIHPqjOiuAgSOf4+FRcguEBXlD9mAInS7b6V0UaNwID
# AQABo4ICNTCCAjEwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0G
# A1UdDgQWBBTZQSmwDw9jbO9p1/XNKZ6kSGow5jBUBgNVHSAETTBLMEkGBFUdIAAw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMA8G
# A1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUyH7SaoUqG8oZmAQHJ89QEE9oqKIw
# gYQGA1UdHwR9MHsweaB3oHWGc2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY3Jvc29mdCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9v
# dCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMC5jcmwwgcMGCCsGAQUF
# BwEBBIG2MIGzMIGBBggrBgEFBQcwAoZ1aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJZGVudGl0eSUyMFZlcmlmaWNhdGlv
# biUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMjAuY3J0MC0G
# CCsGAQUFBzABhiFodHRwOi8vb25lb2NzcC5taWNyb3NvZnQuY29tL29jc3AwDQYJ
# KoZIhvcNAQEMBQADggIBAH8lKp7+1Kvq3WYK21cjTLpebJDjW4ZbOX3HD5ZiG84v
# jsFXT0OB+eb+1TiJ55ns0BHluC6itMI2vnwc5wDW1ywdCq3TAmx0KWy7xulAP179
# qX6VSBNQkRXzReFyjvF2BGt6FvKFR/imR4CEESMAG8hSkPYso+GjlngM8JPn/ROU
# rTaeU/BRu/1RFESFVgK2wMz7fU4VTd8NXwGZBe/mFPZG6tWwkdmA/jLbp0kNUX7e
# lxu2+HtHo0QO5gdiKF+YTYd1BGrmNG8sTURvn09jAhIUJfYNotn7OlThtfQjXqe0
# qrimgY4Vpoq2MgDW9ESUi1o4pzC1zTgIGtdJ/IvY6nqa80jFOTg5qzAiRNdsUvzV
# koYP7bi4wLCj+ks2GftUct+fGUxXMdBUv5sdr0qFPLPB0b8vq516slCfRwaktAxK
# 1S40MCvFbbAXXpAZnU20FaAoDwqq/jwzwd8Wo2J83r7O3onQbDO9TyDStgaBNlHz
# MMQgl95nHBYMelLEHkUnVVVTUsgC0Huj09duNfMaJ9ogxhPNThgq3i8w3DAGZ61A
# MeF0C1M+mU5eucj1Ijod5O2MMPeJQ3/vKBtqGZg4eTtUHt/BPjN74SsJsyHqAdXV
# S5c+ItyKWg3Eforhox9k3WgtWTpgV4gkSiS4+A09roSdOI4vrRw+p+fL4WrxSK5n
# MYIalDCCGpACAQEwcTBaMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSswKQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1Mg
# RU9DIENBIDAxAhMzAAH55+nNq9cb495xAAAAAfnnMA0GCWCGSAFlAwQCAQUAoF4w
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwLwYJ
# KoZIhvcNAQkEMSIEIOLRjHb0rRMxibjzBFT7H0IVd3c2guMwCByUyBrWTbGIMA0G
# CSqGSIb3DQEBAQUABIIBgFK7tzHXhA3cl3vdUrf9+AnqADUW5ilP0OG3TJKWyjEz
# oQkqJw0e+MiyH4LwxzEPcpVz1tni5WAXaIija2e1IdwGqk2+8M46DWMsH70bgroL
# yq3flW7r/P5eM4rIIYreuAK7VKDtV/s/INaxabgSehUzKb7P2JdNxpNgS+QKDQFk
# 7ni1oGRAJgKzA846WPswt+MX16unGWlw9FJGHZYhaVEKfEpjVm2DOjm/ayST5VK0
# f8UXJ2RU6Tz091lu///B5Hd1JtTw1RBODoZ3t1zVL8s35ZnmI3Y+/pkRxcK909aW
# MXxPLJZB8HxA2wZr/U0Emk8Wp3vxO5pvHIZUezcp/3X4KBRPF3xiQ4qb+56qcOwI
# WeDtFMTz/nal8/RS6UomXV5RGi80IVaX1pTnYd1H45KlEBzcs0GSknJk8+WNYBP7
# E6gF0Wb0y6vdacd6LVCHv1JfG14MIbw2wYdx5asq9od8RuF0yqniMVROWKcB1XxV
# ZX41WLqngjNvi+DS+nBqPqGCGBQwghgQBgorBgEEAYI3AwMBMYIYADCCF/wGCSqG
# SIb3DQEHAqCCF+0wghfpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFiBgsqhkiG9w0B
# CRABBKCCAVEEggFNMIIBSQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
# BCAYOgfubD2DT1GS4XyIsI0pE4QOUcBIycNqzlB6RAPKrgIGZ6wV7CKwGBMyMDI1
# MDMwNjE4MTIxNy45ODRaMASAAgH0oIHhpIHeMIHbMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTUwMC0wNUUwLUQ5
# NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWUgU3RhbXBpbmcg
# QXV0aG9yaXR5oIIPITCCB4IwggVqoAMCAQICEzMAAAAF5c8P/2YuyYcAAAAAAAUw
# DQYJKoZIhvcNAQEMBQAwdzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjFIMEYGA1UEAxM/TWljcm9zb2Z0IElkZW50aXR5IFZlcmlm
# aWNhdGlvbiBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDIwMB4XDTIwMTEx
# OTIwMzIzMVoXDTM1MTExOTIwNDIzMVowYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1Ymxp
# YyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCefOdSY/3gxZ8FfWO1BiKjHB7X55cz0RMFvWVGR3eRwV1wb3+y
# q0OXDEqhUhxqoNv6iYWKjkMcLhEFxvJAeNcLAyT+XdM5i2CgGPGcb95WJLiw7HzL
# iBKrxmDj1EQB/mG5eEiRBEp7dDGzxKCnTYocDOcRr9KxqHydajmEkzXHOeRGwU+7
# qt8Md5l4bVZrXAhK+WSk5CihNQsWbzT1nRliVDwunuLkX1hyIWXIArCfrKM3+RHh
# +Sq5RZ8aYyik2r8HxT+l2hmRllBvE2Wok6IEaAJanHr24qoqFM9WLeBUSudz+qL5
# 1HwDYyIDPSQ3SeHtKog0ZubDk4hELQSxnfVYXdTGncaBnB60QrEuazvcob9n4yR6
# 5pUNBCF5qeA4QwYnilBkfnmeAjRN3LVuLr0g0FXkqfYdUmj1fFFhH8k8YBozrEaX
# nsSL3kdTD01X+4LfIWOuFzTzuoslBrBILfHNj8RfOxPgjuwNvE6YzauXi4orp4Sm
# 6tF245DaFOSYbWFK5ZgG6cUY2/bUq3g3bQAqZt65KcaewEJ3ZyNEobv35Nf6xN6F
# rA6jF9447+NHvCjeWLCQZ3M8lgeCcnnhTFtyQX3XgCoc6IRXvFOcPVrr3D9RPHCM
# S6Ckg8wggTrtIVnY8yjbvGOUsAdZbeXUIQAWMs0d3cRDv09SvwVRd61evQIDAQAB
# o4ICGzCCAhcwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1Ud
# DgQWBBRraSg6NS9IY0DPe9ivSek+2T3bITBUBgNVHSAETTBLMEkGBFUdIAAwQTA/
# BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2Nz
# L1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUyH7S
# aoUqG8oZmAQHJ89QEE9oqKIwgYQGA1UdHwR9MHsweaB3oHWGc2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMElkZW50aXR5JTIw
# VmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIw
# MjAyMC5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMIGBBggrBgEFBQcwAoZ1aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJZGVu
# dGl0eSUyMFZlcmlmaWNhdGlvbiUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhv
# cml0eSUyMDIwMjAuY3J0MA0GCSqGSIb3DQEBDAUAA4ICAQBfiHbHfm21WhV150x4
# aPpO4dhEmSUVpbixNDmv6TvuIHv1xIs174bNGO/ilWMm+Jx5boAXrJxagRhHQtiF
# prSjMktTliL4sKZyt2i+SXncM23gRezzsoOiBhv14YSd1Klnlkzvgs29XNjT+c8h
# IfPRe9rvVCMPiH7zPZcw5nNjthDQ+zD563I1nUJ6y59TbXWsuyUsqw7wXZoGzZwi
# jWT5oc6GvD3HDokJY401uhnj3ubBhbkR83RbfMvmzdp3he2bvIUztSOuFzRqrLfE
# vsPkVHYnvH1wtYyrt5vShiKheGpXa2AWpsod4OJyT4/y0dggWi8g/tgbhmQlZqDU
# f3UqUQsZaLdIu/XSjgoZqDjamzCPJtOLi2hBwL+KsCh0Nbwc21f5xvPSwym0Ukr4
# o5sCcMUcSy6TEP7uMV8RX0eH/4JLEpGyae6Ki8JYg5v4fsNGif1OXHJ2IWG+7zyj
# TDfkmQ1snFOTgyEX8qBpefQbF0fx6URrYiarjmBprwP6ZObwtZXJ23jK3Fg/9uqM
# 3j0P01nzVygTppBabzxPAh/hHhhls6kwo3QLJ6No803jUsZcd4JQxiYHHc+Q/wAM
# cPUnYKv/q2O444LO1+n6j01z5mggCSlRwD9faBIySAcA9S8h22hIAcRQqIGEjolC
# K9F6nK9ZyX4lhthsGHumaABdWzCCB5cwggV/oAMCAQICEzMAAABIVXdyHnSSt/cA
# AAAAAEgwDQYJKoZIhvcNAQEMBQAwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBS
# U0EgVGltZXN0YW1waW5nIENBIDIwMjAwHhcNMjQxMTI2MTg0ODUyWhcNMjUxMTE5
# MTg0ODUyWjCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEl
# MCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMe
# blNoaWVsZCBUU1MgRVNOOkE1MDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3Nv
# ZnQgUHVibGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMt+gPdn75JVMhgkWcWc+tWUy9oliU9OuicM
# d7RW6IcA2cIpMiryomTjB5n5x/X68gntx2X7+DDcBpGABBP+INTq8s3pB8WDVgA7
# pxHu+ijbLhAMk+C4aMqka043EaP185q8CQNMfiBpMme4r2aG8jNSojtMQNXsmgrp
# LLSRixVxZunaYXhEngWWKoSbvRg1LAuOcqfmpghkmhBgqD1lZjNhpuCv1yUeyOVm
# 0V6mxNifaGuKby9p4713KZ+TumZetBfY7zlRCXyToArYHwopBW402cFrfsQBZ/HG
# qU73tY6+TNug1lhYdYU6VLdqSW9Jr7vjY9JUjISCtoKCSogxmRW7MX7lCe7JV6Rd
# pn+HP7e6ObKvGyddRdtdiZCLp6dPtyiZYalN9GjZZm360TO+GXjpiZD0gZER+f5l
# EFavwIcD7HarW6qD0ZN81S+RDgfEtJ67h6oMUqP1WIiFC75if8gaK1aO5+Z8Eqna
# eKALgUVptF7i9KGsDvEm2ts4WYneMAhG2+7Z25+IjtW4ZAI83ZtdGOJp9sFd68S6
# EDf33wQLPi7CcZ9IUXW74tLvINktvw3PFee6I3hs/9fDcCMoEIav+WeZImILCgwR
# GFcLItvwpSEA7NcXToRk3TGfC53YD3g5NDujrqhduKLbVnorGOdIZXVeLMk0Jr4/
# XIUQGpUpAgMBAAGjggHLMIIBxzAdBgNVHQ4EFgQUpr139LrrfUoZ97y6Zho7Nzwc
# 90cwHwYDVR0jBBgwFoAUa2koOjUvSGNAz3vYr0npPtk92yEwbAYDVR0fBGUwYzBh
# oF+gXYZbaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9z
# b2Z0JTIwUHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAyMDIwLmNy
# bDB5BggrBgEFBQcBAQRtMGswaQYIKwYBBQUHMAKGXWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwUHVibGljJTIwUlNBJTIw
# VGltZXN0YW1waW5nJTIwQ0ElMjAyMDIwLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBmBgNVHSAEXzBdMFEG
# DCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wCAYGZ4EMAQQCMA0GCSqG
# SIb3DQEBDAUAA4ICAQBNrYvgHjRMA0wxiAI1dPL5y4pOMPM1nd0An5Lg9sAp/vwU
# HBDv2FiKGpn+oiDoZa3+NDkYCwFKkFgo1k4y1QwCs1B8iVnjbLa3KUA//EEZDrDC
# a7S4GZfODpbdOiZNnnpuH3SWLtk7gFuKIKDYICSm+1O+uBi7sVu+9OpMi/8u9dBo
# InH6zG8k+xsgDJZRJ8hhN0BaVWjrewnwCQfmnOmJ++QvJeYvGraNPLBp4P+kprMQ
# nBcBvLz67TigIZUJkNsP6wM4nvneFuXpfJY5eYKldW+PbA+hcl0j5PoM+1z0Za0z
# FINQpm1UlXZRWAAJrPHyA4OJ2PqHdobA6vxS38Ww79fzndDUJil8dZ9bckSQtzcW
# yUp/YqXbMfXgQGgt5SlPKSGfw1lR5eEey64qM/HyZQAtb8uCVSNlfInfIFDU+I56
# +nFOi3xp9dzquWr0UnaSC0zqKPa5bt/1q3nIhx3AUz1VSbRoKCJe+O9GRB5JQggC
# bjQtfaq97aR0+A179m3zJvnMNywmMeFk+1eJbdOcFRguoKwucPp9WHpflC8Vu2Mu
# UEgy3deW8BCe5UTOGjK3eKzDD3Dy36gYKDho2H3gh0q9Q1LV9/EL5D5euxPfAOVK
# Wo1It+ijGGwK7mBcq3Ol+HHz7iX2tUcnGBkT2fAYqIBvA1fEoUHdtWCbCh0ltTGC
# B0YwggdCAgEBMHgwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZXN0
# YW1waW5nIENBIDIwMjACEzMAAABIVXdyHnSSt/cAAAAAAEgwDQYJYIZIAWUDBAIB
# BQCgggSfMBEGCyqGSIb3DQEJEAIPMQIFADAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI1MDMwNjE4MTIxN1owLwYJKoZIhvcNAQkE
# MSIEIHIwrBvbgsh4Pwn9nhNAjbYfKRacJ9LWIFtgJi0SxT5KMIG5BgsqhkiG9w0B
# CRACLzGBqTCBpjCBozCBoAQg6ioBV5tPCNafQ/SAvBnTdh+NfdC8O0dkSXfybyLz
# HUEwfDBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZXN0YW1w
# aW5nIENBIDIwMjACEzMAAABIVXdyHnSSt/cAAAAAAEgwggNhBgsqhkiG9w0BCRAC
# EjGCA1AwggNMoYIDSDCCA0QwggIsAgEBMIIBCaGB4aSB3jCB2zELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkE1MDAt
# MDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lIFN0
# YW1waW5nIEF1dGhvcml0eaIjCgEBMAcGBSsOAwIaAxUA5hJ9QZRXOOnEOHn3+omI
# NFlowyegZzBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZXN0
# YW1waW5nIENBIDIwMjAwDQYJKoZIhvcNAQELBQACBQDrdD3iMCIYDzIwMjUwMzA2
# MTUyOTM4WhgPMjAyNTAzMDcxNTI5MzhaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIF
# AOt0PeICAQAwCgIBAAICIFYCAf8wBwIBAAICEugwCgIFAOt1j2ICAQAwNgYKKwYB
# BAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGG
# oDANBgkqhkiG9w0BAQsFAAOCAQEACUop5sspLF3kSIvR1Y92BRd2PMBBtFb+Yajz
# kBd9T0TDwAu/OIsou/qrmO6le/8Rlk/4TPVC+kLdu+bg4+iLX/HGDnO0eJEn8TA/
# cSJfQgwOUkwO/dVdHa317Kl6ERuKKuLKu0E/C8F2YZciTksiy+9fKEqDGa5hm3o5
# zOk2UYX7iQupBP5rJJHo5S1fQCgwxO/osfLph/jlUqj+7TzgfEksCstYXEN362X4
# mgpy2UR1ehskc7Ms/cUnky8uWp1t+jIcDJPEERWgqNdYEJlAxvP79uDiZXYCkAK0
# 9eR7XMMHjzKrKrTyOtRyneI04lBdmr+hcU+okBvZTawgLa5F4zANBgkqhkiG9w0B
# AQEFAASCAgBhLIDn3W6W1x+irmeQCIxqoVrb9uLh5qcGOF7P7Pxn9Cf+dnW34+mv
# HrVDNk9mcNoZMDHvzN1bFEmAIVAciB55wgB7Z69cKjjbwdTrnrsb2pfPWWvHgSce
# nLDpQYeBiLzcajVJ6ZCnQnQqBOedqonNpqCv9TIln53lKkKzJmeIwJnHn7vvKm3A
# 9NskeMsgI+vy0ChoXG4v3/ZTerdUUgUkW9gymwcwxTCBRpDZSkzmKcHtQ3vdxVpk
# r9PzUmOLeL6eq2nLLsD5PiMuswbgEqr6rK5771qGTZ2Dn4UJ8zL/X1FA8nEW9lhr
# w1LcwgwchDNrpETXydaZSg6qjliTxAjgvYTCKbZDViWZTsIUwBQXSikB7Psd+eU4
# 6DHjIx+qnLCAHyemQuqeL26Cz/VbEBvAml13bKoMj5L7vQuNy+WxtFtfmFfCFdVo
# LVCaWd/J3McxLVaPTiT1RVLZgqbTywGN4i5gaHLaF04nuO6cxqRWoi4yr+cgmIKT
# t12FoRyE/M90oRAKkSLoDogV+dFiahRyJs7RjtTSV5VrnuZXgpTcM4xEpukA0Yu8
# lYKtAQk0GyyuLLyv2glxO2hrVsHJ0PSU8GcWpc4dHvmVwg0gj8WxyH/fdTsp0+LI
# BdZzHMFL5kEBVlt2UOG0PU41/g8dt9zkomyKbGPIWyhbqC5yZjiD7g==
# SIG # End signature block
