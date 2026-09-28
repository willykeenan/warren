# Test-only helper. All mutations require the exact fixture executable and home.
param(
    [Parameter(Mandatory = $true)][ValidateSet('Preflight', 'Task', 'Kill', 'Cleanup', 'CleanupProcesses')][string]$Mode,
    [string]$TaskName,
    [string]$FixtureExe,
    [string]$FixtureHome,
    [int]$ProcessId
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Emit($Value) { $Value | ConvertTo-Json -Depth 8 -Compress }
if ($Mode -eq 'Preflight') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = @($identity.Groups | ForEach-Object { $_.Value })
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $service = Get-Service -Name Schedule
    Emit @{
        sid = $identity.User.Value
        interactive = ($groups -contains 'S-1-5-4') -and ($session -ne 0)
        sessionId = $session
        scheduleRunning = ($service.Status -eq 'Running')
        schtasksAvailable = [bool](Get-Command schtasks.exe -ErrorAction SilentlyContinue)
        os = [Environment]::OSVersion.VersionString
        tokenGroups = $groups
        tempFilesystem = ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($env:TEMP))).DriveFormat
    }
    exit 0
}
if (!$FixtureExe -or !$FixtureHome) { throw 'Exact fixture paths are required' }
if ($Mode -eq 'CleanupProcesses') {
    $terminated = @()
    foreach ($candidate in @(Get-Process -Name warren -ErrorAction SilentlyContinue)) {
        # Inspect names only to enumerate; terminate solely after exact path binding.
        if ([string]::Equals($candidate.Path, $FixtureExe, [StringComparison]::OrdinalIgnoreCase)) {
            $terminated += $candidate.Id
            $candidate.Kill()
            if (!$candidate.WaitForExit(10000)) { throw 'Fixture process survived cleanup' }
        }
    }
    Emit @{ terminatedPids = $terminated }
    exit 0
}
if ($Mode -eq 'Kill') {
    $process = Get-Process -Id $ProcessId -ErrorAction Stop
    if (![string]::Equals($process.Path, $FixtureExe, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to terminate a process outside the fixture executable'
    }
    $started = $process.StartTime.ToUniversalTime().ToString('o')
    $process.Kill()
    if (!$process.WaitForExit(10000)) { throw 'Fixture process did not exit' }
    Emit @{ pid = $ProcessId; startedAt = $started; terminated = $true }
    exit 0
}
if ($TaskName -notmatch '^warren-[0-9a-f]{16}$') { throw 'Invalid exact task name' }
$scheduler = New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
$folder = $scheduler.GetFolder('\')
$task = $null
try { $task = $folder.GetTask($TaskName) }
catch {
    $errorObject = $_.Exception
    while ($errorObject.InnerException) { $errorObject = $errorObject.InnerException }
    if ($errorObject.HResult -ne -2147024894) { throw }
}
if ($null -eq $task) { Emit @{ exists = $false }; exit 0 }
[xml]$xml = $task.Xml
$command = [string]$xml.Task.Actions.Exec.Command
$taskHome = [string]$xml.Task.Actions.Exec.WorkingDirectory
if (![string]::Equals($command, $FixtureExe, [StringComparison]::OrdinalIgnoreCase) -or
    ![string]::Equals($taskHome, $FixtureHome, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to inspect or mutate a task outside the exact fixture paths'
}
if ($Mode -eq 'Cleanup') {
    $task.Enabled = $false
    if ($task.GetInstances(0).Count -gt 0) { $task.Stop(0) }
    $folder.DeleteTask($TaskName, 0)
    Emit @{ deleted = $true; name = $TaskName }
    exit 0
}
Emit @{
    exists = $true
    xml = $task.Xml
    command = $command
    arguments = [string]$xml.Task.Actions.Exec.Arguments
    home = $taskHome
    sid = [string]$xml.Task.Principals.Principal.UserId
    logonType = [string]$xml.Task.Principals.Principal.LogonType
    triggerSid = [string]$xml.Task.Triggers.LogonTrigger.UserId
    restartInterval = [string]$xml.Task.Settings.RestartOnFailure.Interval
    state = [int]$task.State
    lastResult = [int64]$task.LastTaskResult
    instances = [int]$task.GetInstances(0).Count
}
