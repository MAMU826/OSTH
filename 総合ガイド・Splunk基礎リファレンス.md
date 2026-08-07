このリポジトリは、OffSec OSTH および OSIR 認定資格の学習を進める中で作成したものです。この README では、シンプルな使用例から高度なユースケースまで、Splunk を活用するさまざまな方法を案内するとともに、重要なフィールドやフィルタ演算子のリファレンスを可能な限り多く提供します。

前半のセクションでは、Splunk の使い方、ワークフロー、およびデータの取得・表示方法について解説します。後半のセクションでは、ソートとフィルタリングの手法を扱い、`stats`、`WHERE` 演算子、`sort`、`|`（パイプ）演算子などのコマンドの使い方を説明します。全体として、Splunk を使用する際の手軽なリファレンスとして役立つことを願っています。また、新しいアイデアが浮かんだり、新たなクエリを作成した際には、このリポジトリ/README を更新していく予定です。


## 基本的な検索構造
```spl
index=* source="*" EventCode=1 "powershell"
```

これは、イベント内のいずれかの場所に "powershell" を含むすべてのインデックスから、プロセス生成イベント（SysmonのEventCode 1）を検索します。`EventCode` 引数や `source` を削除して、"powershell" を含むすべてのイベントを検索することもできます。

個人的なおすすめとして、ソース（`source`）を明示的に指定しない方法があります。Windows のイベントコードは一意ではないため、同じイベントコードを持つソースが大量にない限り、指定する必要がないことが多いためです。ソースを細かく指定する状態から、ワイルドカードを使用した柔軟な検索へ移行できます。

## ワイルドカードとテキストマッチング
```spl
index=* "*net.exe*"                    # net.exe を含む「あらゆる」イベントを検索
index=* "192.168"                      # このIPパターンを含む「あらゆる」イベントを検索
index=* "powershell" (NOT "*net.exe*")   # powershell を検索するが net.exe は除外
index=* "HOST123" "*cmd.exe*"          # 特定のホスト上の cmd.exe を検索
```
`(NOT)` を使用すると、`(NOT SOMETHING_A) (NOT SOMETHING_B)` のように複数の除外条件を繋げることができます。完全に洗練されたクエリを書く必要はなく、機能すれば十分です。特に、手早く結果を絞り込みたい場合に効果的です。

同様に `AND` や `OR` なども使用できます。Splunk は処理速度に注意していれば、プレーンテキストを使った直感的なフィルタリングを非常に柔軟に行うことができます。

## フィールド指定検索
```spl
index=* Image="*\\powershell.exe"      # ワイルドカードを使用したフィールドの完全一致
index=* Image=*.exe                    # すべての実行ファイル
index=* User="NT AUTHORITY\\SYSTEM"    # 特定のユーザー
index=* User!=Administrator            # Administrator 以外のユーザー
index=* (Image="*cmd.exe" OR Image="*powershell.exe")  # 複数の選択肢
```

## | table を使った主要な Sysmon フィールド表示

### 基本的なプロセス情報
```spl
index=* source=* EventCode=1
| table _time, Computer, User, Image, CommandLine
```

### 親プロセスのコンテキストを含める場合
```spl
index=* source="*Sysmon*" EventCode=1
| table _time, Computer, User, ParentImage, ParentCommandLine, Image, CommandLine
```

### ネットワーク接続
```spl
index=* source="*" EventCode=3
| table _time, Computer, Image, User, DestinationIp, DestinationPort, DestinationHostname
```

### ファイル作成
```spl
index=* source="*" EventCode=11
| table _time, Computer, Image, TargetFilename, CreationUtcTime
```

### レジストリ変更
```spl
index=* source="*" EventCode=13
| table _time, Computer, Image, TargetObject, Details, EventType
```

## 主要な Sysmon イベントコード一覧
- **EventCode=1** - プロセス生成（Process Creation）
- **EventCode=3** - ネットワーク接続（Network Connection）
- **EventCode=7** - イメージロード/DLL（Image Loaded）
- **EventCode=8** - リモートスレッド作成（CreateRemoteThread）
- **EventCode=11** - ファイル作成（File Created）
- **EventCode=13** - レジストリ値の設定（Registry Value Set）
- **EventCode=15** - ファイルストリーム作成/ADS（File Stream Created）
- **EventCode=22** - DNSクエリ（DNS Query）

## 便利なフィルタリングパターン

### ノイズの除外
```spl
index=* source="*Sysmon*" EventCode=1 
    NOT Image="*\\Windows\\System32\\*"
    NOT User="NT AUTHORITY\\SYSTEM"
```

### 疑わしいパスに絞り込み
```spl
index=* source="*Sysmon*" EventCode=1
    (Image="*\\Temp\\*" OR Image="*\\AppData\\*" OR Image="*\\Public\\*" OR Image="*\\Tasks\\*")
```

### コマンドライン文字列の検知
```spl
index=* source="*Sysmon*" EventCode=1
    CommandLine="*-enc*"              # エンコードされたコマンド
    CommandLine="*bypass*"            # バイパスフラグ
    CommandLine="*http://*"           # コマンド内のURL
```

## 検索の結合（Combining Searches）

### ネットワーク活動を伴うプロセス
```spl
index=* source="*" EventCode=1 Image="*\\rundll32.exe"
| join ProcessGuid 
    [search index=* source="*Sysmon*" EventCode=3]
| table _time, Computer, Image, CommandLine, DestinationIp, DestinationPort
```

### 親子関係の追跡
```spl
index=* source="*" EventCode=1 
    ParentImage="*\\explorer.exe" 
    Image!="*\\Windows\\*"
| table _time, Computer, ParentImage, Image, CommandLine
```

## 時間によるフィルタリング
```spl
index=* earliest=-24h                  # 過去24時間
index=* earliest=-15m                  # 過去15分
index=* earliest="10/01/2024:00:00:00" latest="10/02/2024:00:00:00"  # 特定の期間指定
```

## 迅速なスレットハンティングの例

### PowerShell によるダウンロードを検知
```spl
index=* "IEX" "DownloadString"
| table _time, Computer, User, CommandLine
```

### 疑わしいサービスの検知
```spl
index=* source="WinEventLog:System" EventCode=7045 
    (Service_Name="*temp*" OR Service_Name="*update*")
| table _time, Computer, Service_Name, Service_File_Name
```

### エンコードされたコマンドの検知
```spl
index=* (CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*base64*")
| table _time, Computer, User, Image, CommandLine
```

## プロのアドバイス (Pro Tips)
1. **広く検索を開始し、徐々に絞り込む**: まずは `index=* "keyword"` から始め、後からフィルタを追加する。
2. **NOT を使ってノイズを削減する**: `NOT Image="*\\trusted.exe*"` などで信頼できるプロセスを除外する。
3. **ワイルドカードを積極的に活用する**: `*` は任意の文字列にマッチします。
4. **大文字・小文字の区別に注意する**: 必要に応じて正規表現の `(?i)` を使い、大文字小文字を無視した検索を行う。
5. **存在するフィールドを確認する**: 検索を実行した後、左側パネルにある「Interesting Fields（注目フィールド）」を確認する。
6. **IoC（侵害指標）を広範囲にハントする**: 例えば攻撃者のIPアドレスを特定した場合、`index=* "*192.168.10.10*"` で検索し、そのIPに関連する他の大まかなアクティビティを拾い出す。

## 覚えておくべき必須フィールド
- **_time** - 発生日時
- **Computer/host** - 発生したマシン
- **User** - 実行したユーザー
- **Image** - 実行されたプログラム
- **CommandLine** - 実行時のコマンドライン引数
- **ParentImage** - 起動元の親プロセス
- **TargetFilename** - 作成・変更されたファイル名
- **DestinationIp** - 接続先のIPアドレス
- **ProcessId/ProcessGuid** - プロセスの一意識別子

環境や調査のコンテキストに合わせて、これらのクエリを自由にカスタマイズしてください。


# Splunk フィルタリングとフォーマット


## パイプ演算子（`|`）- Splunk を効果的に使いこなすための基本構造

パイプ `|` 演算子は、Splunk クエリにおける強力な武器です。クエリ全体をゼロから書き直すことなく、ノイズを減らし、不要な詳細を削ぎ落とすための非常にシンプルで簡単な方法を提供します。ハンティング中に素早く対応できるよう、このパイプを活用して「即座に使えるテンプレートクエリ」を作成しておくことを強く推奨します。

```splunk
index=* | head 10 | table User, Computer
```
**処理の流れ:** 
1. windows インデックス（または指定インデックス）からすべてのイベントを取得
2. 最初の 10 件のイベントのみを抽出（`head 10`）
3. `User` と `Computer` フィールドのみを表示（`table`）

**重要な概念:** 各パイプは、LEGOブロックを組み立てるように、処理結果を次のコマンドへと受け渡します。

---

## WHERE を使った基本的なフィルタリング

`where` コマンドは、指定した条件に基づいて結果をフィルタリングします。特定のユーザーによって生成されたプロセスや特定のホスト上のイベントなど、探しているものの目星が大まかについている場合に非常に役立ちます。`where` ステートメントはいくらでも追加できるため、広い範囲から収集した検索結果を絞り込む際に非常に便利です。

### 基本的な例:

**完全一致によるフィルタリング:**
```splunk
index=* | where User="Administrator"
```

**数値の比較によるフィルタリング:**
```splunk
index=* | where bytes_sent > 1000000
```

**NOT を使用したフィルタリング（結果の除外）:**
```splunk
index=* | where NOT User="SYSTEM"
```

**複数条件によるフィルタリング:**
```splunk
index=* | where EventCode=4624 AND User!="SYSTEM"
```

### 関数を使用した高度な WHERE:

**`match()` を使用したパターンマッチング（正規表現）:**
```splunk
index=* | where match(Process, "powershell")
```
これは "powershell" を含むすべてのプロセスを検索します。

**大文字・小文字を区別しないマッチング:**
```splunk
index=* | where match(Process, "(?i)powershell")
```
`(?i)` を付けることで大文字・小文字を無視します（PowerShell, powershell, POWERSHELL などすべてにマッチ）。

**複数の企業名・ベンダーの除外:**
```splunk
index=* | where NOT match(Company, "(?i)(Microsoft|Google|Adobe)")
```
Company フィールドに Microsoft、Google、または Adobe が含まれるイベントを除外します（大文字小文字無視）。

---

## AS によるフィールド名の変更

`as` 演算子は、フィールド名をより読みやすい名前に変更します。主に `stats` コマンドと組み合わせて使用されます。

### 基本的な例:

**基本的な名前変更:**
```splunk
index=* | stats count as TotalEvents
```

**stats 集計処理内での名前変更:**
```splunk
index=* 
| stats count(User) as UniqueUsers, 
        avg(Duration) as AverageDuration
```

**`values()` と `as` の組み合わせ:**
```splunk
index=* EventCode=4624
| stats values(User) as LoggedInUsers, 
        values(Computer) as Computers 
        by SourceIP
```
SourceIP ごとにグループ化し、IP ごとのユニークな User と Computer のリストを表示します。

---

## 結果のソート（並び替え）

`sort` コマンドは検索結果を並び替えます。降順（値が大きい順/新しい順）には `-` を、昇順（値が小さい順/古い順）には `+` を使用します。

### 例:

**単一フィールドによるソート（昇順）:**
```splunk
index=* | table User, EventCode | sort User
```

**単一フィールドによるソート（降順）:**
```splunk
index=* | table User, EventCode | sort -EventCode
```

**複数フィールドによるソート:**
```splunk
index=* | table User, _time, EventCode | sort User, -_time
```
User のアルファベット順（昇順）でソートした後、同じ User 内で時間（最新順）にソートします。

---

## よく使うデータ操作コマンド

### 1. **table** - 特定イベントの指定フィールドを個別の列として表示
```splunk
index=* | table User, Computer, EventCode, _time
```
指定した4つのフィールドのみを列形式で表示します。

### 2. **fields** - フィールドの含め出し・除外
```splunk
index=* | fields User, Computer | fields - _raw
```
User と Computer フィールドを保持し、`_raw` フィールドを除外します。

### 3. **dedup** - 重複エントリーの削除
```splunk
index=windows | dedup User
```
重複する User ごとに、最初の1件のみを保持します。

### 4. **eval** - 新しいフィールドの作成または既存フィールドの修正
```splunk
index=windows 
| eval UserType=if(User="Administrator", "Admin", "Standard")
```
User フィールドの値に基づいて、`UserType` という新しいフィールドを作成します。

### 5. **stats** - データの集計
```splunk
index=windows 
| stats count by User
```
User ごとのイベント数をカウントします。

**主要な stats 関数:**
- `count` - イベント数をカウント
- `values()` - 一意な値の一覧を取得
- `min()` - 最小値を取得
- `max()` - 最大値を取得
- `avg()` - 平均値を計算
- `sum()` - 合計を計算

### 6. **coalesce** - ヌル（Null）でない最初の値を使用
```splunk
index=windows 
| eval Username=coalesce(User, AccountName, "Unknown")
```
User が存在すればそれを使い、なければ AccountName、どちらも無ければ "Unknown" を代入します。

---

## 高度なソート/フィルタリングを使用しているクエリの解体・解説

このクエリは、環境内への初期侵入（Initial Access）に使用されたペイロードを浮き彫りにするか、横展開（Lateral Movement）を特定することを目的としています。指定した信頼できる企業名に一致しない、ネットワーク接続を発生させたファイルを表示します。ユニークな値のみを表示するようにグループ化されているため、出力結果は通常 2〜3 ページ程度に収まり、大量のデータに埋もれることなく攻撃者の広範なアクティビティを効率的に特定できます。

```splunk
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
| where NOT match(Company, "(?i)(Microsoft|Google|VMware)")
| eval ProcessGuid=coalesce(ProcessGuid, ProcessGuid)
| stats values(Image) as Process, 
        values(CommandLine) as CommandLine,
        values(Company) as Company,
        values(User) as User,
        values(DestinationIp) as DestIP,
        values(DestinationPort) as DestPort,
        values(DestinationHostname) as DestHost,
        values(SourceIp) as SourceIP,
        values(SourcePort) as SourcePort,
        min(_time) as ProcessStart,
        values(EventCode) as EventCodes 
        by ProcessGuid
| where EventCodes="1" AND EventCodes="3"
| table ProcessStart, Process, User, CommandLine, SourceIP, DestIP, DestPort, DestHost, Company
| sort -ProcessStart
```

### 各ステップの解説:

**ステップ 1: 初期検索**
```splunk
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
```
- すべてのインデックスを検索
- Sysmon ログを指定
- EventCode 1（プロセス生成）または EventCode 3（ネットワーク接続）を取得

**ステップ 2: 既知の信頼できる企業を除外**
```splunk
| where NOT match(Company, "(?i)(Microsoft|Google|VMware)")
```
- Microsoft、Google、VMware 製のプロセスを除外
- 大文字小文字を区別しない
- ノイズを削減（自組織の環境に合わせて除外対象の企業を追加することで、画面上の不要なログをさらに削ることができます）

**ステップ 3: ProcessGuid の存在を保証**
```splunk
| eval ProcessGuid=coalesce(ProcessGuid, ProcessGuid)
```
- `ProcessGuid` フィールドが存在することを確認（Null値の処理）

**ステップ 4: プロセスごとにイベントをグループ化**
```splunk
| stats values(Image) as Process, 
        values(CommandLine) as CommandLine,
        ...
        by ProcessGuid
```
- プロセスの一意の識別子である `ProcessGuid` ごとにすべてのイベントを統合
- `values()` により、各フィールドのユニークな値を収集
- 可読性を高めるため `as` でフィールド名を変更
- `min(_time)` で最も古いタイムスタンプ（プロセスが起動した時間）を取得

**ステップ 5: 両方のイベントコードを持つプロセスを抽出**
```splunk
| where EventCodes="1" AND EventCodes="3"
```
- 以下の**両方**を実行したプロセスのみを表示するようにフィルタリング：
  - EventCode 1（プロセスが生成された）
  - EventCode 3（ネットワーク接続を行った）
- これにより、「起動し、かつ外部通信を行った」プロセスのみを抽出できます。

**ステップ 6: 出力フォーマットの整列**
```splunk
| table ProcessStart, Process, User, CommandLine, SourceIP, DestIP, DestPort, DestHost, Company
```
- 関連するフィールドのみを指定した順序で表示

**ステップ 7: 時間順にソート**
```splunk
| sort -ProcessStart
```
- 最新のプロセスから順に表示（降順）

### このクエリの実際の挙動:
このクエリは、以下の条件に該当する潜在的に疑わしいプロセスをハントします：
1. 実行された（EventCode 1）
2. ネットワーク接続を行った（EventCode 3）
3. 信頼できるベンダー（Microsoft, Google, VMware）製ではない
4. ネットワークの詳細とともに時系列順で結果を表示

---

## 段階的なクエリ構築の例

シンプルなクエリから始めて、徐々に高度なクエリへとステップアップしていきましょう。

### レベル 1:
```splunk
# すべてのログイン失敗イベントを検索
index=windows EventCode=4625 | table User, Computer, _time

# ユーザーごとのイベント数をカウント
index=windows | stats count by User | sort -count

# "cmd" を含むプロセスを検索
index=windows | where match(Process, "cmd") | table Process, User
```

### レベル 2:
```splunk
# 複数のコンピュータからログインしたユーザーを特定
index=windows EventCode=4624
| stats values(Computer) as Computers, 
        dc(Computer) as ComputerCount 
        by User
| where ComputerCount > 1

# プロセスとそのネットワーク接続を紐付け
index=sysmon (EventCode=1 OR EventCode=3)
| stats values(Image) as Process, 
        values(DestinationIp) as Destinations 
        by ProcessGuid
| where isnotnull(Destinations)
```

上記のレベル 2 の例は、クエリ作成・表形式出力・フィルタリングを組み合わせることで、大量のイベントログから真に必要な情報を抽出する良いステップアップ例です。具体的には以下を行っています：

- 複数の端末にアクセスしているユーザーの特定（通常、1人のユーザーが同時に3台以上の端末にアクセスすることは稀であるため）
- EventCode 4624 = Windows ログイン成功
- `values(Computer)` = 該当ユーザーがアクセスしたすべてのユニークな端末名をリスト化（出力をコンパクトにします）
- `dc(Computer)` = **d**istinct **c**ount（ユニークカウント） - アクセス端末数をカウント
- `by User` = ユーザー名ごとにグループ化
- 2台以上の端末にログインしたユーザーのみを表示

---

レベル 2 クエリの後半部分は、生成されたプロセスとそこから発生したネットワーク接続を示します。例えば、攻撃者が C2 サーバーに通信する Meterpreter のリバースシェルを実行した場合、このイベントを特定できます：
- プロセス生成とネットワーク接続の相関関係を表示
- EventCode 1 = プロセス開始、EventCode 3 = ネットワーク接続発生
- `ProcessGuid` = プロセスとネットワーク活動を結びつける一意のID
- `values(Image)` = プログラム名 / パス
- `values(DestinationIp)` = このプロセスが接続したすべての通信先IP
- `isnotnull(Destinations)` = 実際にネットワーク接続を発生させたプロセスのみを表示


### レベル 3:
```splunk
# 外部通信を行っているレア（出現頻度が低い）なプロセスを検索
index=sysmon EventCode=3 
| where NOT match(DestinationIp, "^(10\.|172\.|192\.168\.)")
| stats count by Image
| where count < 5
| sort count
```

`stats` コマンドはデータに対する計算とグループ化を行います（Excel のピボットテーブルのような機能です）。`count`、`values()`、`sum()`、`avg()` などの関数を使用して、イベント数のカウント、ユニーク値のリスト化、平均値の計算、特定フィールドによる集計が可能です。

`count` 関数は、単にイベント数や発生回数をカウントする最も基本的な stats 関数です。単独（`stats count`）で使用すると全イベント数を数え、`by`（`stats count by User`）と併用すると、指定フィールドのユニーク値ごとにカウントします。

レベル 3 のクエリに関して言えば、`stats count by Image` コマンドはユニークなプロセス（Image）ごとに外部ネットワーク接続を行った回数をカウントし、プログラムごとの通信頻度テーブルを作成します。`where count < 5` でフィルタリングすることで、数回しか外部接続を行っていない「レアな」プロセスを特定できます。通常の正規プログラムは通信を行う場合多数の接続を発生させますが、ビーコンやリバースシェルのペイロードは C2 サーバーに数回しか接続しない場合があるため、このようなレアな通信は不審とみなすことができます。

※上記のような検索は誤検知（False Positive）を含む可能性がありますが、ここでの目的は Splunk の概念を理解し、期待する情報を適切にフィルタリング・抽出・特定できるようになることです。

---

## クイックリファレンス

| コマンド | 目的 | 例 |
|---------|---------|---------|
| `\|` | データを次のコマンドへパイプ | `index=windows \| head 10` |
| `where` | 結果のフィルタリング | `\| where User="admin"` |
| `where NOT` | 条件に合う結果を除外 | `\| where NOT User="SYSTEM"` |
| `match()` | パターンマッチング（正規表現） | `\| where match(field, "pattern")` |
| `as` | フィールド名の変更 | `\| stats count as Total` |
| `sort` | 結果のソート | `\| sort -count, sort +_time, sort -_time` |
| `table` | 指定フィールドの表示 | `\| table User, Time, CommandLine, Image` |
| `stats` | データの集計 | `\| stats count by User` |
| `values()` | ユニーク値のリスト化 | `\| stats values(IP) by User` |
| `eval` | フィールドの作成・修正 | `\| eval newfield=field1+field2` |
| `coalesce()` | 最初の非Null値を取得 | `\| eval x=coalesce(a,b,c)` |

---
## 独自のクエリを作成するためのアドバイス

1. **シンプルに始める:** 基本的な検索から始め、パイプを1つずつ追加して結果の変化を確認する。これにより、意図しない挙動が発生した際の原因特定が容易になります。
2. **各ステップをテストする:** パイプを追加するたびにクエリを実行してデータの変化を確認し、その後にフィルタを追加する。最初から完璧なクエリを作ろうとせず、まずは広く検索してからパイプを追加して削ぎ落としていく感覚を掴みましょう。
3. **一般的なパターンを覚える:** 一度全体のプロセスに慣れてしまえば、ほとんどのクエリはいくつかのフィールドを変更するだけで再利用（使い回し）できるようになります。

以下のセクションのクエリは、OSTH/OSIR 特有のものであり、ラボ演習や試験問題の解答に役立つ内容となっています。


# OSTH / OSIR ラボ・ハンティングクエリ集

その前に、試験全般に適用できる一般的なアドバイスをいくつか紹介します。まず第一に、**脅威インテリジェンスレポート（Threat Intelligence Report）を徹底的に活用すること**です。試験当日に最初に実行すべきクエリは、以下に示すIoC検索クエリです。提供されたハッシュ値だけでなく、レポートに記載されている攻撃手法（Techniques）も可能な限りハントする必要があります。

例えば、脅威レポートに「特定の攻撃グループが初期侵入にフィッシングを好んで使用する」と記載されている場合、このリポジトリで示されているクエリやテクニックを使用して、侵害期間中に実行されたすべてのマクロ有効化ファイルを検索したり、Word や Excel などの親プロセスから起動した `powershell.exe` や `cmd.exe` を探します。また、データ窃取に WinRAR を使用することが知られている場合は、WinRAR や `.rar` ファイルに関連するイベントをハントします。

重要なのは、自身の知識やこのリポジトリのパターンを使って手当たり次第にハントを開始する前に、**まず脅威レポートに記載されている内容を広く検索するクエリを実行すること**です。それらを適切なクエリで掘り下げていけば、調査の起点となるピボットポイント（展開軸）が自然と見つかる可能性が高くなります。

また、レポートを参照せずに調査を進めていて行き詰まったりアイデアが尽きた場合にも、脅威インテリジェンスレポートは頭をリフレッシュし、新しい視点を得るための非常に優れたアプローチとなります。

何を行うにしても、単なるハッシュ値だけでなく、記載されているすべての TTP（Tactics, Techniques, and Procedures）を含め、脅威インテリジェンスレポート全体を網羅的に参照・ハントしたか確認してください。

## IoC（侵害指標）によるハント
```spl
index="*" ("malicious.exe" OR
    "192.168.1.100" OR 
    "evil.com" OR 
    "45.142.212.100" OR 
    "badactor@email.com" OR 
    "C:\\Temp\\payload.ps1" OR 
    "HKLM\\Software\\Evil" OR 
    "mutex_12345" OR 
    "pipe\\evil_pipe" OR 
    "service_backdoor" OR 
    "scheduled_task_evil" OR 
    "SHA256_hash_here" OR
    "MD5_hash_here")
| table _time, host, source, User, Image, CommandLine, Message
```

## ファイルダウンロードの検知

### Webダウンロードコマンド
```spl
index="*" ("IWR" OR "Invoke-WebRequest" OR "wget" OR "curl" OR "DownloadString" OR "DownloadFile")
| table _time, host, User, CommandLine, ParentImage
```

### Zone.Identifier (Mark of the Web / MOTW)
```spl
# ダウンロードされたすべてのファイル
index="*" EventCode=15 TargetFilename="*:Zone.Identifier"
| table _time, host, User, TargetFilename, Image

# 危険な特定のファイル拡張子
index="*" EventCode=15 (TargetFilename="*.exe:Zone.Identifier" OR 
    TargetFilename="*.ps1:Zone.Identifier" OR 
    TargetFilename="*.zip:Zone.Identifier" OR
    TargetFilename="*.dll:Zone.Identifier" OR
    TargetFilename="*.scr:Zone.Identifier")
| table _time, host, User, TargetFilename, Image

# Chromeでダウンロード中のファイル
index="*" "*.crdownload" 
| table _time, host, User, TargetFilename
```

## ネットワーク接続

### 通信先トップ（送信先IPの上位表示）
```spl
index="*" EventCode=3 
| stats count by DestinationIp 
| sort -count 
| head 20
```

### 特定の IP アドレスの調査
```spl
index="*" DestinationIp="192.168.100.100" 
| table _time, User, Image, ProcessId, host, DestinationPort
```

### 特定ユーザーの通信履歴を追跡
```sql
index="*" DestinationIp="192.168.100.100" User="domain\\user" 
| table _time, Image, ProcessId, CommandLine, DestinationPort
```

### 特定のホストからの通信
```spl
index="*" (SourceHostname="WK3.domain.com" OR host="WK3")
| stats count by DestinationIp 
| sort -count 
| head 20
```

## ファイル操作

### ファイル生成（最初の発生例）
```spl
index="*" EventCode=11 TargetFilename="*some.exe"
| sort _time 
| head 1
| table _time, host, User, Image, TargetFilename
```

### 特定ファイルの追跡
```spl
index="*" EventCode=11 TargetFilename="C:\\Temp\\malicious.exe"
| table _time, host, User, Image, CreationUtcTime
```

## プロセス実行

### バイナリの初回実行
```spl
index="*" EventCode=1 Image="*\\some.exe"
| sort _time 
| head 1
| table _time, ComputerName, User, CommandLine, ParentImage, ProcessId
```

### バイナリのハッシュ値取得
```spl
index="*" EventCode=1 Image="*\\suspicious.exe"
| table _time, ComputerName, User, Image, SHA256, CommandLine
```

## 認証イベント

### ログイン成功（マシンアカウントを除外）
```spl
index="*" EventCode=4624 host="DB1" 
| regex Account_Name!=".*\$" 
| table _time, Account_Name, Logon_Type, Source_Network_Address, Workstation_Name
```

### ログイン失敗
```spl
index="*" EventCode=4625 
| regex Account_Name!=".*\$"
| stats count by Account_Name, Source_Network_Address 
| sort -count
```

### 特定ユーザーのアクティビティ追跡
```spl
index="*" (User="user" OR Account_Name="user")
| table _time, EventCode, ComputerName, Image, CommandLine, ProcessId
| sort _time
```

## ユーザー管理

### ユーザーアカウント作成
```spl
index="*" EventCode=4720
| table _time, Account_Name, Target_User_Name, host
```

### グループへのユーザー追加
```spl
index="*" (EventCode=4732 OR EventCode=4728)
| table _time, Account_Name, Target_User_Name, Group_Name
```

## リモート実行の検知

### WinRM / PSRemoting
```spl
index="*" "TaskCategory=Execute a Remote Command"
| table _time, host, User, CommandLine, Message

# または WSMan イベントを検索
index="*" (EventCode=91 OR EventCode=168 OR "WSMan" OR "WinRM")
| table _time, host, User, Message
```

### リモートからのプロセス生成
```spl
index="*" EventCode=1 (ParentImage="*\\wsmprovhost.exe" OR ParentImage="*\\winrshost.exe")
| table _time, host, User, Image, CommandLine, ParentImage
```

## PowerShell アクティビティ

### すべての PowerShell イベント
```spl
(index="*" source="*PowerShell*") OR 
(index="*" EventCode=1 Image="*powershell.exe") OR
(index="*" EventCode=4104)
| table _time, host, User, ScriptBlockText, CommandLine, Message
```

### エンコードされたコマンド
```spl
index="*" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR ScriptBlockText="*FromBase64String*")
| table _time, host, User, CommandLine, ScriptBlockText
```

## プロセスの系統（親子関係）
```spl
index="*" Image="*\\suspicious.exe"
| table _time, ComputerName, User, ProcessId, ParentProcessId, ParentImage, CommandLine
| sort _time
```

## さらに役立つクイックヒント:
1. **常に最初の発生例を確認する** - `| sort _time | head 1` を使用して最初の発生時間を特定し、その前後を詳細に絞り込んでハントするための時間範囲（タイムレンジ）を作成します。
2. **マシンアカウントを除外する** - `regex Account_Name!=".*\$"` を使用します。マシンアカウントはノイズになることが多く、有用な情報を増やさないケースが多いためです。
3. **横展開（Lateral Movement）を追跡する** - Logon_Type 3（ネットワーク経由）および 10（リモートインタラクティブ）に着目します。また、コマンドライン内で攻撃者のIPが使用されている場合など、他イベントとIPを相関させることでデータ持ち出し（Exfiltration）や追加ツールのダウンロードの形跡を特定できます。
4. **プロセスの系統を確認する** - 攻撃者が環境内でどのようにコマンド実行権限を取得したか（侵入経路）を特定するために、常に `ParentImage` と `ParentProcessId` を確認対象に含めてください。
5. **IoC を保存しておく** - 脅威レポートで提供された侵害指標（IoC）を使って、セクション最初の IoC ハントクエリを活用しましょう。