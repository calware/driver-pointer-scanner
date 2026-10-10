param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]] $Path,
    [string] $Output,
    [switch] $Recursive,
    [switch] $SkipFixtureCheck
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$originalDirectory = (Get-Location).Path
$python = (Get-Command python -ErrorAction Stop).Source
$inputs = @($Path | ForEach-Object { [System.IO.Path]::GetFullPath($_, $originalDirectory) })
$destination = if ($Output) { [System.IO.Path]::GetFullPath($Output, $originalDirectory) } else { $null }

Push-Location -LiteralPath $repo
try {
    if (-not $SkipFixtureCheck) {
        Write-Host 'Running scanner regression tests...'
        & $python -m unittest discover -q
        if ($LASTEXITCODE -ne 0) { throw 'Scanner tests failed; target scan was not started.' }

        Write-Host 'Scanning all 10 bundled driver fixtures...'
        $fixtureOutput = Join-Path $repo 'reports\fixtures-thorough-latest.json'
        $common = @('--engine', 'both', '--emulate-init', '--census',
                    '--budget', '30000', '--depth', '8', '--flow-budget', '100000',
                    '--offline-validate', '--offline-init-budget', '100000',
                    '--offline-flow-budget', '100000', '--offline-path-budget', '50000',
                    '--offline-max-sites', '64', '--offline-instruction-limit', '100000')
        & $python 'scanner.py' 'fixtures' @common '--output' $fixtureOutput
        if ($LASTEXITCODE -ne 0) { throw 'Fixture scan failed; target scan was not started.' }
        $fixtureRows = @((Get-Content -LiteralPath $fixtureOutput -Raw | ConvertFrom-Json).results)
        if ($fixtureRows.Count -ne 10) { throw "Expected 10 fixture images; found $($fixtureRows.Count)." }
        foreach ($row in $fixtureRows) {
            $name = [System.IO.Path]::GetFileName($row.file)
            $hits = @($row.offline_validation.sites | Where-Object {
                @($_.attempts | Where-Object { $_.status -eq 'TARGET_ENTERED' }).Count -gt 0
            }).Count
            $expected = if ($name -like 'internal-*') { 0 } else { 1 }
            if ($hits -ne $expected) {
                throw "Fixture $name produced $hits target-entry witnesses; expected $expected."
            }
        }
        Write-Host 'Fixture self-check passed: eight expected witnesses, two negative controls.'
    } else {
        $common = @('--engine', 'both', '--emulate-init', '--census',
                    '--budget', '30000', '--depth', '8', '--flow-budget', '100000',
                    '--offline-validate', '--offline-init-budget', '100000',
                    '--offline-flow-budget', '100000', '--offline-path-budget', '50000',
                    '--offline-max-sites', '64', '--offline-instruction-limit', '100000')
    }

    $arguments = @('scanner.py') + $inputs + $common
    if ($Recursive) { $arguments += '--recursive' }
    if ($destination) { $arguments += @('--output', $destination) }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Target scan failed with exit code $LASTEXITCODE." }
    if ($destination) {
        Write-Host "Full target report: $destination"
        Write-Host "Fixture report: $(Join-Path $repo 'reports\fixtures-thorough-latest.json')"
    }
} finally {
    Pop-Location
}
