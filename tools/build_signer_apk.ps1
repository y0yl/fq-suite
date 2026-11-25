# tools/build_signer_apk.ps1 —— 一键构建「内置签名服务」版番茄 APK
#
# 做什么：
#   1. apktool 解包（-s：保留原始 dex，不反编译 smali —— 避免踩 VMP / 签名校验）
#   2. 编译 com.dragon.sign.SignServer（javac 打 android.jar）
#   3. d8 生成 classes26.dex（原包有 classes..classes25，追加一个即可）
#   4. 往 AndroidManifest.xml 注入 <service> + 两个 <receiver>（开机自启 / adb 广播拉起）
#   5. apktool 重打包 -> zipalign -> apksigner 签名
#
# 产物：work\patched_signed.apk
# 安装：adb uninstall com.dragon.read; adb install -r -g work\patched_signed.apk
# 启动：adb shell am start-foreground-service -n com.dragon.read/com.dragon.sign.SignServer
#       adb forward tcp:27043 tcp:27043
#
# 用法：
#   .\tools\build_signer_apk.ps1                      # 用 samples\emulator-com.dragon.read\base.apk
#   .\tools\build_signer_apk.ps1 -Apk <path> -SkipDecode   # 复用已解包的 work\apk_s
param(
  [string]$Apk = '',
  [string]$Work = '',
  [string]$Keystore = '',
  [string]$StorePass = 'dragon123',
  [string]$KeyAlias = 'dragon',
  [switch]$SkipDecode,
  [switch]$SkipSign
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $Apk) { $Apk = Join-Path $root 'samples\emulator-com.dragon.read\base.apk' }
if (-not $Work) { $Work = Join-Path $root 'work' }
if (-not $Keystore) { $Keystore = Join-Path $Work 'sign.keystore' }
$dec = Join-Path $Work 'apk_s'
$src = Join-Path $root 'work\apkpatch\src'
$cls = Join-Path $Work 'apkpatch\classes'
$apktoolJar = 'D:\RE\tools\apktool\apktool_3.0.3.jar'
$jdk = 'D:\RE\tools\jdk17\jdk-17.0.21.1+2\bin'
$bt = 'D:\Android\Sdk\build-tools\34.0.0'
$aj = 'D:\Android\Sdk\platforms\android-34\android.jar'

foreach ($p in @($apktoolJar, "$jdk\javac.exe", "$jdk\keytool.exe", "$bt\d8.bat",
                 "$bt\zipalign.exe", "$bt\apksigner.bat", $aj)) {
  if (-not (Test-Path $p)) { throw "缺少工具: $p" }
}
New-Item -ItemType Directory -Force -Path $Work, $cls | Out-Null

# ---------------------------------------------------------------- 1. 解包
if (-not $SkipDecode) {
  Write-Host "[1/6] apktool d -s ..."
  & java -jar $apktoolJar d -s -f -o $dec $Apk 2>&1 | Select-Object -Last 3
}

# ---------------------------------------------------------------- 2. javac
Write-Host "[2/6] javac (UTF-8 / source 8 / android.jar)"
& "$jdk\javac.exe" -nowarn -encoding UTF-8 -source 8 -target 8 -bootclasspath $aj -cp $aj `
  -d $cls (Get-ChildItem $src -Recurse -Filter *.java | ForEach-Object { $_.FullName }) 2>&1 |
  Where-Object { $_ -notmatch '^注意|^Note' } | Select-Object -Last 5

# ---------------------------------------------------------------- 3. d8
Write-Host "[3/6] d8 -> classes.dex"
& "$bt\d8.bat" --min-api 21 --lib $aj --output (Join-Path $Work 'apkpatch') `
  (Get-ChildItem $cls -Recurse -Filter *.class | ForEach-Object { $_.FullName }) 2>&1 |
  Select-Object -Last 5
$dex = Join-Path $Work 'apkpatch\classes.dex'
if (-not (Test-Path $dex)) { throw 'd8 未产出 classes.dex' }

# ---------------------------------------------------------------- 4. manifest
Write-Host "[4/6] 注入 manifest（service + boot/starter receiver）"
$mf = Join-Path $dec 'AndroidManifest.xml'
$raw = Get-Content $mf -Raw
if ($raw -notmatch 'com\.dragon\.sign\.SignServer') {
  $inject = @'
    <service android:name="com.dragon.sign.SignServer" android:exported="true" android:foregroundServiceType="dataSync"/>
    <receiver android:name="com.dragon.sign.SignServer$Boot" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.BOOT_COMPLETED"/>
        </intent-filter>
    </receiver>
    <receiver android:name="com.dragon.sign.SignServer$Starter" android:exported="true">
        <intent-filter>
            <action android:name="com.dragon.sign.START"/>
        </intent-filter>
    </receiver>
'@
  $raw = $raw -replace '(?s)\s*</application>', ("`r`n" + $inject + "`r`n</application>")
  Set-Content -Path $mf -Value $raw -Encoding utf8 -NoNewline
  Write-Host '    注入完成'
} else {
  Write-Host '    已存在，跳过'
}
Copy-Item $dex (Join-Path $dec 'classes26.dex') -Force

# ---------------------------------------------------------------- 5. 重打包
Write-Host "[5/6] apktool b + zipalign"
$unsigned = Join-Path $Work 'patched_unsigned.apk'
& java -jar $apktoolJar b -f -o $unsigned $dec 2>&1 | Select-Object -Last 3
$aligned = Join-Path $Work 'patched_aligned.apk'
& "$bt\zipalign.exe" -f -p 4 $unsigned $aligned
if ($LASTEXITCODE -ne 0) { throw 'zipalign 失败' }

# ---------------------------------------------------------------- 6. 签名
if (-not $SkipSign) {
  Write-Host "[6/6] apksigner"
  if (-not (Test-Path $Keystore)) {
    & "$jdk\keytool.exe" -genkeypair -keystore $Keystore -alias $KeyAlias -keyalg RSA `
      -keysize 2048 -validity 10000 -storepass $StorePass -keypass $StorePass `
      -dname 'CN=DragonLab,O=Lab,C=CN' 2>&1 | Select-Object -Last 2
  }
  $out = Join-Path $Work 'patched_signed.apk'
  & "$bt\apksigner.bat" sign --ks $Keystore --ks-pass "pass:$StorePass" --key-pass "pass:$StorePass" `
    --min-sdk-version 21 --v1-signing-enabled true --v2-signing-enabled true `
    --out $out $aligned 2>&1 | Select-Object -Last 3
  & "$bt\apksigner.bat" verify --print-certs $out 2>&1 | Select-Object -First 2
  Write-Host "[done] $out"
} else {
  Write-Host "[done] $aligned （未签名）"
}