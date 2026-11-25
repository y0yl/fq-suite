# tools/provision_signer.ps1 —— 把「签名机」部署到任意一台 adb 可达的 Android 设备
#
# 目的：脱离雷电模拟器。改造 APK 是纯 Java（SignServer）+ 原包 arm64 原生库，
#       所以任何 **arm64-v8a** 的 Android 都能当签名机：真机、云手机、arm64 容器都行。
#       注意：x86_64 的 AVD/模拟器**跑不了**（APK 只有 arm64-v8a 一套 so，且没有 libhoudini）。
#
# 流程：校验设备 → 装包 → 灌设备态(shated_prefs/databases) → 首启过隐私 → 起签名服务
#       → adb forward → 调 fq_sign_tcp.py --selftest 自检
#
# 用法：
#   .\tools\provision_signer.ps1                              # 用默认 serial，全新部署
#   .\tools\provision_signer.ps1 -Serial 127.0.0.1:5555        # 指定云手机
#   .\tools\provision_signer.ps1 -NoFresh                      # 保留已有数据，只更新 APK
#   .\tools\provision_signer.ps1 -SkipState                    # 不灌设备态（会生成新设备身份）
param(
  [string]$Serial = '',
  [string]$Apk = '',
  [string]$StateTar = '',
  [string]$Adb = '',
  [int]$Port = 27043,
  [switch]$NoFresh,
  [switch]$SkipState,
  [switch]$AutoConsent
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $Adb) { $Adb = Join-Path $PSScriptRoot 'platform-tools\adb.exe' }
if (-not (Test-Path $Adb)) { $Adb = 'adb' }
if (-not $Apk) { $Apk = Join-Path $root 'work\patched_signed.apk' }
if (-not $StateTar) { $StateTar = Join-Path $root 'work\fq_pre2.tar' }
if (-not (Test-Path $Apk)) { throw "找不到改造包: $Apk（先跑 tools\build_signer_apk.ps1）" }

function A([string[]]$args_) {
  if ($Serial) { & $Adb -s $Serial @args_ } else { & $Adb @args_ }
}
function Sh([string]$c) { (A @('shell', $c)) -join "`n" }
function SuSh([string]$c) { (A @('shell', "su -c '$c'")) -join "`n" }

# ---------------------------------------------------------------- 0. 设备体检
$devs = (A @('devices')) -split "`n" | Where-Object { $_ -match '\sdevice$' }
if (-not $devs) { throw '没有可用设备（adb devices 为空）' }
$sn = if ($Serial) { $Serial } else { ($devs[0] -split '\s+')[0] }
if (-not $Serial) { $Serial = $sn }        # 后续所有 adb 调用都显式 -s，多设备时不会串台
$model = (Sh 'getprop ro.product.model').Trim()
$rel = (Sh 'getprop ro.build.version.release').Trim()
$abi = (Sh 'getprop ro.product.cpu.abilist').Trim()
Write-Host "[*] serial=$sn model=$model android=$rel"
Write-Host "[*] abilist=$abi"
if ($abi -notmatch 'arm64-v8a') {
  throw "这台设备没有 arm64-v8a（$abi）。改造包只带 arm64 so，x86_64 AVD 跑不了。"
}
$rooted = (Sh 'id') -match 'uid=0'
if (-not $rooted) {
  $t = SuSh 'id'
  if ($t -notmatch 'uid=0') { Write-Warning 'su 不可用：灌设备态会失败，只能全新安装（设备身份会变）' }
}

# ---------------------------------------------------------------- 1. 装包
if (-not $NoFresh) {
  Write-Host '[*] uninstall 旧包（保留原包请用 -NoFresh）'
  A @('uninstall', 'com.dragon.read') | Out-Null
}
Write-Host "[*] install $Apk"
$out = (A @('install', '-r', '-g', $Apk)) -join "`n"
if ($out -notmatch 'Success') { throw "安装失败: $out" }
$uid = (Sh "stat -c '%u' /data/data/com.dragon.read").Trim()
Write-Host "[*] installed, uid=$uid"

# ---------------------------------------------------------------- 2. 灌设备态
if (-not $SkipState -and (Test-Path $StateTar)) {
  Write-Host "[*] 灌设备态 $StateTar"
  A @('push', $StateTar, '/sdcard/fq_state.tar') | Out-Null
  SuSh "cd /data/data && tar xf /sdcard/fq_state.tar && chown -R $uid`:$uid com.dragon.read/shared_prefs com.dragon.read/databases && restorecon -R com.dragon.read" | Out-Null
} else {
  Write-Warning '跳过设备态：这台设备会有全新的 cdid/iid（服务端眼里是新设备）'
}

# ---------------------------------------------------------------- 3. 首启 + 隐私弹窗
Write-Host '[*] 首启 App（等它把 metasec 回调注册上）'
A @('shell', 'monkey', '-p', 'com.dragon.read', '-c', 'android.intent.category.LAUNCHER', '1') | Out-Null
Start-Sleep -Seconds 8
if ($AutoConsent) {
  for ($i = 0; $i -lt 3; $i++) {
    A @('shell', 'uiautomator', 'dump', '/sdcard/ui.xml') | Out-Null
    $raw = (Sh 'cat /sdcard/ui.xml')
    $m = [regex]::Match($raw, '<node[^>]*text="同意并继续"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"')
    if (-not $m.Success) { $m = [regex]::Match($raw, '<node[^>]*text="同意"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"') }
    if ($m.Success) {
      $x = ([int]$m.Groups[1].Value + [int]$m.Groups[3].Value) / 2
      $y = ([int]$m.Groups[2].Value + [int]$m.Groups[4].Value) / 2
      Write-Host "    点『同意』($x,$y)"
      A @('shell', 'input', 'tap', "$x", "$y") | Out-Null
      Start-Sleep -Seconds 6
    } else { break }
  }
}
$focus = (Sh 'dumpsys activity activities | grep -m1 mResumedActivity')
Write-Host "    当前焦点: $($focus.Trim())"

# ---------------------------------------------------------------- 4. 起服务 + forward
Write-Host '[*] 起签名服务'
A @('shell', 'am', 'start-foreground-service', '-n',
    'com.dragon.read/com.dragon.sign.SignServer') | Out-Null
A @('forward', "tcp:$Port", "tcp:$Port") | Out-Null
Start-Sleep -Seconds 3
$log = (A @('logcat', '-d', '-s', 'DragonSign:*')) -join "`n"
if ($log -notmatch 'listening on') { Write-Warning "没看到 listening 日志，贴一段：`n$log" }

# ---------------------------------------------------------------- 5. 自检
Write-Host '[*] 自检（535 签/s + 一条真实请求）'
$py = Join-Path $root 'fq_sign_tcp.py'
& python $py --selftest 2>&1 | Select-Object -Last 10

Write-Host @"

[完成] $sn ($model / android $rel)
  签名端口 : adb -s $sn forward tcp:$Port tcp:$Port
  采集示例 : python fq_fast_aio.py --books-file books.txt --rate 85 --workers 220
  保活建议 : adb -s $sn shell dumpsys deviceidle whitelist +com.dragon.read
             adb -s $sn shell am broadcast -a com.dragon.sign.START -n com.dragon.read/com.dragon.sign.SignServer`$Starter
"@