# tools/extract_app.ps1 —— 从模拟器（雷电 9 / adb）完整提取番茄小说的分析样本
#
# 背景：真机上的 App 已删除，模拟器里这份是唯一的活体签名 oracle。
#       任何重装 / 升级 / 清数据都会断掉复现链，所以样本必须能一键重建 + 校验。
#
# 提取内容：
#   1. base.apk（全量 dex / resources / lib）
#   2. 签名链相关 so：libmetasec_ml.so / libsscronet.so / libttcrypto.so ...
#   3. app 私有目录（shared_prefs / databases）—— 设备指纹、cookie、账号态
#   4. /data/local/tmp/frida16 —— 重建 oracle 的另一半
#   5. manifest.json：逐文件 md5 / sha256 / size / 来源设备
#
# 实现要点（踩过的坑）：
#   - adb 是 shell 用户，pull /data/data 直接失败 → 先用 su 打包到 /sdcard 再 pull
#   - Windows 的 Split-Path 会把 /data/app/.../base.apk 的分隔符吃掉 → 用字符串裁剪
#
# 用法：
#   .\tools\extract_app.ps1                 # 全量
#   .\tools\extract_app.ps1 -SkipData       # 只要 APK + so
#   .\tools\extract_app.ps1 -Force          # 重拉覆盖
param(
  [string]$Pkg = 'com.dragon.read',
  [string]$Adb = '',
  [string]$Out = '',
  [switch]$SkipData,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
if (-not $Adb) {
  $cand = @("$PSScriptRoot\platform-tools\adb.exe", "$PSScriptRoot\..\tools\platform-tools\adb.exe")
  $Adb = ($cand | Where-Object { Test-Path $_ } | Select-Object -First 1)
  if (-not $Adb) { $Adb = 'adb' }
}
$root = Split-Path $PSScriptRoot -Parent
if (-not $Out) { $Out = Join-Path $root "samples\emulator-$Pkg" }
$Out = [System.IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force -Path $Out, "$Out\lib", "$Out\data" | Out-Null

function Sh([string]$c) { (& $Adb shell $c) -join "`n" }
function SuSh([string]$c) { (& $Adb shell "su -c '$c'") -join "`n" }

$manifest = [System.Collections.Generic.List[object]]::new()
function AddManifest([string]$p, [string]$from) {
  $fi = Get-Item $p
  $manifest.Add([pscustomobject]@{
    file   = (Resolve-Path -Relative $p)
    size   = $fi.Length
    md5    = (Get-FileHash $p -Algorithm MD5).Hash
    sha256 = (Get-FileHash $p -Algorithm SHA256).Hash
    from   = $from
  })
}

# ---------------------------------------------------------------- 0. 基本信息
$apkPath = ((Sh "pm path $Pkg") -replace '^package:', '').Trim()
if (-not $apkPath) { throw "$Pkg 未安装" }
$appDir = $apkPath -replace '/base\.apk$', ''
$ver = (Sh "dumpsys package $Pkg | grep -m1 versionName") -replace '\s+', ''
$sn = (& $Adb get-serialno).Trim()
Write-Host "[*] serial=$sn  apk=$apkPath  $ver"

# ---------------------------------------------------------------- 1. APK
$apkOut = Join-Path $Out 'base.apk'
if ((Test-Path $apkOut) -and -not $Force) {
  Write-Host "  [skip] base.apk (已存在，-Force 重拉)"
} else {
  & $Adb pull $apkPath $apkOut 2>&1 | Out-Null
  Write-Host "  [pull] base.apk"
}
AddManifest $apkOut $apkPath

# ---------------------------------------------------------------- 2. so
$abis = (Sh "ls $appDir/lib") -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$keep = 'libmetasec_ml\.so|libsscronet\.so|libttcrypto\.so|libttboringssl\.so|libdragon_crypt\.so|libdragoncore\.so|libEncryptor\.so|libc\+\+_shared\.so|libdexvmp\.so|libpreload\.so'
foreach ($abi in $abis) {
  $dir = Join-Path $Out "lib\$abi"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $files = (Sh "ls $appDir/lib/$abi") -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $files | Set-Content -Encoding utf8 (Join-Path $dir '_index.txt')
  $want = $files | Where-Object { $_ -match $keep }
  Write-Host "[*] lib/$abi : 共 $($files.Count) 个，取 $($want.Count) 个"
  foreach ($f in $want) {
    $dst = Join-Path $dir $f
    if ((Test-Path $dst) -and -not $Force) { AddManifest $dst "$appDir/lib/$abi/$f"; continue }
    & $Adb pull "$appDir/lib/$abi/$f" $dst 2>&1 | Out-Null
    if (Test-Path $dst) { AddManifest $dst "$appDir/lib/$abi/$f" } else { Write-Host "  [fail] $f" }
  }
}

# ---------------------------------------------------------------- 3. 私有数据（su 打包 → pull → 本地解包）
if (-not $SkipData) {
  $tar = "/sdcard/$($Pkg -replace '\.', '_')_data.tar"
  Write-Host "[*] packing private data (shared_prefs/databases) ..."
  SuSh "cd /data/data && tar cf $tar $Pkg/shared_prefs $Pkg/databases 2>/dev/null; chmod 644 $tar; ls -l $tar" | Out-Null
  $tarLocal = Join-Path $Out 'data\app_data.tar'
  & $Adb pull $tar $tarLocal 2>&1 | Out-Null
  if (Test-Path $tarLocal) {
    tar -xf $tarLocal -C (Join-Path $Out 'data') 2>&1 | Out-Null
    AddManifest $tarLocal $tar
    $n = (Get-ChildItem (Join-Path $Out 'data') -Recurse -File -ErrorAction SilentlyContinue).Count
    Write-Host "  [ok] 解包 $n 个文件"
  } else { Write-Host "  [fail] 私有数据打包失败" }
  # 关键态明文摘要（设备 id / cookie / 登录态）
  $pick = @('com.ss.android.deviceregister.utils.Cdid.xml', 'cookieStore.xml',
            'com_ss_android_token_sp_host.xml', 'device_register_oaid_refine.xml',
            'first_time_install.xml', 'applog_stats.xml')
  $dumpFile = Join-Path $Out 'data\device_state.txt'
  "== $Pkg device state @ $(Get-Date -Format s) ==" | Set-Content -Encoding utf8 $dumpFile
  foreach ($p in $pick) {
    "`n---- $p ----" | Add-Content -Encoding utf8 $dumpFile
    SuSh "cat /data/data/$Pkg/shared_prefs/$p 2>/dev/null" | Add-Content -Encoding utf8 $dumpFile
  }
}

# ---------------------------------------------------------------- 4. frida-server
$fsLocal = Join-Path $Out 'frida16'
if (-not (Test-Path $fsLocal) -or $Force) {
  & $Adb pull /data/local/tmp/frida16 $fsLocal 2>&1 | Out-Null
}
if (Test-Path $fsLocal) { AddManifest $fsLocal '/data/local/tmp/frida16' }

# ---------------------------------------------------------------- 5. manifest
$meta = [pscustomobject]@{
  pulled_at = (Get-Date).ToString('s')
  serial    = $sn
  model     = (Sh 'getprop ro.product.model').Trim()
  android   = (Sh 'getprop ro.build.version.release').Trim()
  abilist   = (Sh 'getprop ro.product.cpu.abilist').Trim()
  pkg       = $Pkg
  version   = $ver
  apk_path  = $apkPath
  abis      = $abis
  files     = $manifest
}
$meta | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $Out 'manifest.json')
Write-Host "[done] $Out  记录 $($manifest.Count) 个文件"