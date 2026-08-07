システム全体にわたる PowerShell 関連のアクティビティ、特に `.ps1` ファイルの実行履歴を広範なログから収集し、表形式で綺麗にまとめてハントしたい場合は、以下のクエリが利用できます。

このクエリのデメリットは、システム背景で動く無関係なノイズ（バックグラウンド処理）を大量に拾ってしまう点です。その解決策として、`NT AUTHORITY\SYSTEM` アカウントによって実行されたインスタンスを除外します。PsExec 等によって起動された SYSTEM シェル上の攻撃者の挙動を見落とすリスクはありますが、ノイズを劇的に減らし、悪意あるアクティビティを検出できる確率が大幅に向上するため、トレードオフとしては十分見合う価値があります。漏れてしまったイベントも、他のクエリを組み合わせれば容易に補足可能です。単一のクエリですべてを検知しようとする必要はありません。

```sql
index=* ".ps1" (sourcetype=*sysmon* OR sourcetype=*powershell* OR sourcetype=*security* OR sourcetype=*wineventlog* OR sourcetype=*edr* OR sourcetype=*defender* OR sourcetype=*carbon* OR sourcetype=*crowdstrike*) NOT (User="NT AUTHORITY\\SYSTEM" OR Image="C:\\Windows\\Temp\\__PSScriptPolicy*") | eval log_source=case(match(sourcetype,"(?i)sysmon"),"Sysmon", match(sourcetype,"(?i)powershell"),"PowerShell Operational", match(sourcetype,"(?i)security"),"Windows Security", match(sourcetype,"(?i)defender"),"Windows Defender", match(sourcetype,"(?i)carbon|crowdstrike"),"EDR", 1=1,sourcetype) | eval activity_type=case(EventCode=1,"Process Created", EventCode=11,"File Created", EventCode=15,"File Stream Created", EventCode=7,"Image Loaded", EventCode=4688,"Process Created", EventCode=4103,"PowerShell Module", EventCode=4104,"Script Block Executed", EventCode=4105,"Script Started", EventCode=4106,"Script Stopped", 1=1,"Other") | eval script_info=coalesce(TargetFilename,Path,ScriptName,Image) | table _time, Computer, log_source, activity_type, EventCode, script_info, CommandLine, ProcessId, User, ScriptBlockText, ParentImage, ParentCommandLine | sort -_time
```

もう一つの効果的な調査手法として、PowerShell の実行インスタンス全体をシンプルに精査する方法があります。思考プロセスとして、外部コマンドやスクリプトを実行する際、攻撃者は Execution Policy（実行ポリシー）を `Bypass` や `AllSigned` 等に変更する必要があるため、ポリシーが `Restricted`（制限あり）に設定されたままのイベントは基本的に考慮外として除外できます。

また、`.psm1`（モジュールファイル）は Windows の標準処理で多用されますが、攻撃者の使うツールの多くは `.ps1` ファイル形式です。このアプローチは完璧ではありませんが、調査を展開するための起点（ピボット）として活用できます：

```sql
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="*powershell.exe*"
NOT (TargetFilename="*.psm1" OR CommandLine="*Restricted*") | table _time, Image, Company, CommandLine, User | sort -_time
```