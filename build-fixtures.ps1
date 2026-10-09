param([string]$KitVersion = '10.0.26100.0')
$ErrorActionPreference = 'Stop'
$kit = 'C:\Program Files (x86)\Windows Kits\10'
$clang = (Get-Command clang.exe).Source
$linker = Join-Path (Split-Path $clang) 'lld-link.exe'
$out = Join-Path $PSScriptRoot 'fixtures'
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($variant in @('positive', 'readonly', 'unrelated', 'helper', 'internal')) {
    foreach ($opt in @('Od', 'O2')) {
        $stem = Join-Path $out "$variant-$opt"
        $defines = @()
        if ($variant -eq 'readonly') { $defines += '/DREADONLY_CALLBACK' }
        if ($variant -eq 'unrelated') { $defines += '/DUNRELATED_CALLBACK' }
        if ($variant -eq 'helper') { $defines += '/DHELPER_CALLBACK' }
        if ($variant -eq 'internal') { $defines += '/DINTERNAL_ONLY' }
        & $clang '--driver-mode=cl' '/nologo' '/c' "/$opt" '/GS-' '/Zl' '/kernel' '/D_AMD64_' '/DAMD64' '/D_WIN64' '/D_WIN32_WINNT=0x0601' '-Wno-ignored-pragma-intrinsic' '-Wno-pragma-pack' '-Wno-visibility' '-Wno-sizeof-array-div' @defines "/I$kit\Include\$KitVersion\km" "/I$kit\Include\$KitVersion\shared" (Join-Path $PSScriptRoot 'fixture\driver.c') "/Fo$stem.obj"
        if ($LASTEXITCODE) { throw "Compile failed: $variant-$opt" }
        & $linker '/driver' '/subsystem:native,6.01' '/entry:DriverEntry' '/machine:x64' '/nodefaultlib' '/dynamicbase' '/nxcompat' '/opt:noicf' "/out:$stem.sys" "$stem.obj" "$kit\Lib\$KitVersion\km\x64\ntoskrnl.lib"
        if ($LASTEXITCODE) { throw "Link failed: $variant-$opt" }
    }
}
