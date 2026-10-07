# Foundation の秘密管理と実行委任設計

Foundation は、principal が持つ秘密と接続を暗号文で保持し、許可された principal の実行環境へ仕事を届ける。秘密を復号するのは、その秘密について明示的に承認された利用者のクライアントまたは実行環境である。Foundation が提供する Agent も同じ仕組みに参加する。

運営側の Agent に許可すれば、利用者の端末がすべて停止していても処理を続けられる。利用者側の実行環境だけに許可すれば、Foundation の管理サーバーへ秘密を開示せずに利用できる。両者を切り替えるモードは設けず、復号先と実行権限で表現する。

対象は secret、外部サービスへの connection、OAuth app の秘密、およびそれらを使う実行・承認・共有・復旧である。以下の API、データ構造、CLI は実装先の契約であり、現在の提供機能を表すものではない。設計基準日は 2026 年 10 月 7 日とする。

## 設計上の決定

1. 人、AI、アプリ、組織を別の principal 型に分けない。実行する Agent も通常の principal である。
2. 管理サーバーは利用者の秘密を復号する鍵を持たない。運営側での復号は、許可された Agent の実行環境が担当する。
3. 認証、権限、鍵の所持を区別する。ログインや API 認証に成功しただけでは復号も委任の署名もできない。
4. 依頼者、実行主体、実行環境、結果の受取先を実行ごとに固定する。実行機が不在でも未承認の相手へ切り替えない。
5. API トークン、OAuth、ロールによる一時資格情報を、実行環境が解決する connection として扱う。
6. 権限変更と鍵の配布は同じ承認で扱う。DB の権限を書き換えただけでは復号先を追加できない。
7. 任意コードへ渡した秘密を、そのコードから隠せるとは扱わない。限定した操作の委任と、秘密を渡す実行を区別する。
8. 旧実装の変換は独立した移行処理で完了させ、通常の実行経路は一つにする。

## 主体と実行環境

| 概念 | 責務 | 秘密との関係 |
| --- | --- | --- |
| principal | 所有、依頼、委任、実行の主体 | 承認された鍵を通じて秘密を扱う |
| credential | principal として Foundation に認証する手段 | 単独では復号能力を与えない |
| key | 暗号化先または署名の検証先 | 用途、世代、principal、承認元を固定する |
| resource | principal が保持するもの | secret、connection、app は機密部分を暗号化する |
| environment | 仕事を受け取る実行先 | 実行主体、運営者、鍵、実行可能な操作を公開する |
| run | 依頼から結果までの一回の実行 | 依頼者と実行主体を別々に記録する |
| grant | ある主体に許可した操作と範囲 | 署名された権限証明として実行先でも検証する |

`agent` relation は引き続き principal 間の委任関係を表す。常駐プロセスの種類や特権を表すものにはしない。CLI、ブラウザ、VPS の常駐プロセス、Foundation Agent は、同じ契約を実装するクライアントまたは実行プロセスである。

実行環境は既存の environment を拡張して表現する。別の runner resource や agent principal 型は追加しない。

```ts
type Environment = {
  id: Id;
  ownerId: Id;
  executorId: Id;
  operatorId: Id;
  driver: 'local' | 'attached' | 'managed';
  keyBindingId: Id;
  capabilities: Array<'http' | 'command' | 'oauth' | 'role'>;
  manifestDigest: string;
  state: 'starting' | 'ready' | 'stopping' | 'stopped' | 'failed';
  lastSeenAt: Time | null;
};
```

`driver` は起動・停止・接続の方法だけを変える。権限の判定や暗号化方式には使わない。`operatorId` は実行環境とそのソフトウェアを管理できる相手を示し、利用者への信頼範囲の説明に使う。自称の operator 情報を物理的な隔離の証明とは扱わない。

environment の署名付き manifest は `executorId`、`operatorId`、公開鍵、capabilities、実行ポリシーのハッシュを含む。名前や接続先だけを差し替えて別の環境として実行させることはできない。

### Foundation Agent

Foundation Agent は運営者が管理する実行サービスであり、利用者の秘密を扱うインスタンスには所有単位ごとの executor principal と鍵を割り当てる。全利用者の秘密を開ける共有の復号鍵は使わない。

利用者は通常の environment と同じ画面で Foundation Agent を選ぶ。選択した接続の暗号化先に、その environment の承認済み鍵が加わる。運営側 Agent を利用者本人としてログインさせたり、利用者の principal 秘密鍵を渡したりする必要はない。

ここでの Agent は秘密を扱う実行プロセスを含む。LLM にトークンの文字列を渡すことを意味しない。AI が操作を依頼し、実行プロセスが認証情報を注入する。

### 一つの接続を複数の場所で使う例

利用者が Cloudflare の connection を所有し、「さくら VPS」と「Foundation Agent」を復号先に選ぶ。収集を依頼する AI には、承認済みの収集 function の実行権限だけを与える。

AI は connection の token を受け取らず、選んだ environment に署名付きの実行依頼を送る。さくら VPS を指定した依頼はそこで実行し、Foundation Agent を指定した依頼は運営側で実行する。両方とも同じ connection、policy、run の形式を使う。

利用者の端末と VPS が停止していても、Foundation Agent 宛てに承認してある仕事は継続できる。VPS 宛ての未完了の仕事まで、勝手に Foundation Agent へ移すことはしない。実行先を変更する場合は、未送信・結果不明の区別を確認したうえで新しい intent を作る。

## 管理と実行の境界

```text
利用者のクライアント
  鍵の生成、共有の承認、実行依頼への署名
          │ 暗号文、署名された依頼・権限
          ▼
Foundation 管理サーバー
  保管、索引、配送、キュー、状態、課金、監査メタデータ
          │ 同じ暗号文と証明を配送
          ▼
承認された実行環境
  権限検証、復号、OAuth 取得・更新、入力展開、API・コマンド実行
          │ 必要な認証情報を付与
          ▼
外部サービス
```

結果は実行環境で受取先向けに暗号化し、管理サーバーを通じて返す。管理サーバーは実行できたか、誰がいつ依頼したかを管理するが、秘密や結果本文の平文を必要としない。

管理サーバーに残す暗号化用 Vault は、Foundation 自身の課金連携、メール送信、外向き通知の署名鍵などを保護するためのものである。利用者の connection、実行入力、OAuth app の client secret を復号する経路にはしない。

Foundation Agent のホストと管理サーバーを分離することは権限分離には有効だが、同じ運営者が両方を管理する場合、運営者に対して秘密を隠す保証にはならない。

## 保護する範囲

この設計における「運営側に秘密を読ませない」は、利用者が管理する承認済みクライアント・実行環境だけに秘密を配布した場合の性質である。Foundation 全体に固定の `zeroKnowledge` フラグは設けない。

| 状況 | 保証することと限界 |
| --- | --- |
| 管理サーバーの DB やバックアップの漏えい | 利用者だけが鍵を持つ機密本文を復号できない。管理メタデータは漏れる |
| 管理サーバーによる鍵や仕事の差し替え | ピン留めした鍵、署名された権限・依頼、内容のハッシュで検出する |
| 許可済みの Foundation Agent | その接続の秘密を扱える。運営者への非開示は保証しない |
| 許可済みの端末・実行機の侵害 | その環境が開ける秘密は保護できない |
| 悪意ある管理サーバーによる配送妨害 | 可用性は保証しない。権限取り消しの通知を隠す攻撃にも限界がある |
| Web UI や配布クライアントの改ざん | 復号するコードを信頼する必要がある。サーバー配信 JS だけで悪意ある運営者への完全な耐性は主張しない |

強い運営者非開示を必要とする利用では、利用者が検証・固定した CLI または実行プロセスで鍵の承認と復号を行う。ブラウザだけを使う場合には、Web 配信元、拡張機能、XSS なども信頼境界に含まれる。

接続名、所有者、共有先、実行先、利用日時、状態、サイズ、必要な scope といったメタデータはサーバーに見える。暗号文を利用する方式は、メタデータ秘匿、アクセスパターン秘匿、過去に開示した秘密の回収、全履歴の完全な改ざん防止を意味しない。

## 鍵と認証

### 鍵の種類

principal は暗号化用と署名用に独立した鍵を持てる。暗号化鍵は既存の P-256 ECDH を利用し、署名鍵には別に生成した P-256 ES256 鍵を用いる。用途の異なる鍵を兼用しない。

鍵は UUID の `keyId` と公開鍵の fingerprint で識別する。principal ID を JWE の鍵 ID と兼用しない。鍵を交換しても principal や resource の ID は変えない。

```ts
type KeyBinding = {
  id: Id;
  principalId: Id;
  lineageId: Id;
  generation: number;
  encryptionKeyId: Id;
  encryptionPublicKey: Jwk;
  signingKeyId: Id;
  signingPublicKey: Jwk;
  previousBindingDigest: string | null;
  authorizedBy: SignedStatement[];
};
```

初回の binding は本人のクライアントで生成し、その fingerprint を信頼の起点として保存する。後続の鍵、実行環境、共有先は、既に信頼している鍵からの署名、または利用者が確認した別経路の fingerprint により承認する。初回の自己署名だけで相手の正当性が証明されるとは扱わない。

一つの principal は複数の binding を持てる。`generation` と前の binding は同じ `lineageId` 内の鍵交換を表す。binding の追加は権限の自動追加ではなく、その鍵で署名できる操作と復号できる resource を別途承認する。公開鍵の fingerprint は RFC 7638 の JWK thumbprint と SHA-256 で求める。[JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)

同じ鍵 bundle を複数の credential から解除できるようにした場合、それらは同じ暗号上の能力を持つ。独立して失効させたい実行機には独立した binding を使う。別の信頼範囲で行動する Agent には別 principal を割り当て、利用者の権限の起点となる署名鍵を配らない。

### 認証用 credential との分離

メール、passkey、API credential はサーバー上の principal を認証する。復号鍵や委任用署名鍵を取得できるかは独立した条件である。

API トークン、セッショントークン、メール認証コード、サーバーが生成・受信する値を、秘密鍵の wrapping key にしない。認証情報を再発行しても暗号文を開けるようにはならない。

人のクライアントでは、対応する passkey の PRF 出力、既に承認した端末への鍵転送、または利用者が保持する高エントロピーの復旧鍵で鍵 bundle を保護する。PRF の対応状況は実行時に確認し、未対応の credential は認証用として利用できるが鍵の解除には使わない。[WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension)

PRF の出力と復旧鍵はクライアント内でのみ扱い、認証結果を送る JSON、ログ、telemetry に含めない。新しい bundle の wrapping key は、用途を区別した HKDF-SHA-256 とランダム salt で導出する。salt、用途、bundle の版、principal ID を暗号文に結び付け、認証用データとの兼用を避ける。[HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)

API を使う実行プロセスではローカルで鍵を生成する。API トークンを通信に使う場合も秘密鍵は別の保管先に置き、権限の署名や復号にはその鍵を必要とする。新しい端末の鍵 bundle は、その端末が事前に生成した公開鍵へ暗号化して渡す。

新規端末の追加は、既存端末が fingerprint と用途を確認し、鍵の binding と必要な権限を署名する。管理サーバーの「この鍵がこの principal の鍵である」という返答だけでは受け入れない。組織や人が管理する AI も、同じ委任の証明で追加する。

### 実行機の鍵

実行機の秘密鍵は実行機内で生成・保持する。実行機の初期化を管理サーバーが手配しても、利用者の principal 秘密鍵を作って環境変数で渡すことはしない。

常駐実行プロセスの鍵、API credential、ローカルの OAuth 更新記録を、子コマンドへ継承しない。子コマンドに渡すのは承認された入力だけとする。運営側では所有単位の隔離、別プロセスの秘密保管、短命な実行コンテナを基本とし、制御用鍵を job filesystem にマウントしない。

local 実行では利用者の OS も信頼対象である。任意コードを安全に隔離できない環境は、外部 principal からの任意 command を受け付ける capability を公開しない。

## 権限と鍵の配布

### 三つの条件

秘密を使う run は、次のすべてを満たす必要がある。

1. 依頼者がその操作を依頼できる。通常の `use`、`execute`、function の委任範囲を検証する。
2. 指定された environment の鍵が、その秘密について承認された復号先である。
3. その environment が、承認済みの操作範囲と受取先に従って実行する。

権限があるが鍵の配布が終わっていない状態は `key_required` とする。鍵を持つというだけで管理 API へのアクセスを許可しない。暗号文と鍵を取得済みの相手が、システム外で復号することまでは防げない。

利用者が自分の `reveal` と reader の鍵を使って local 実行する場合、その承認済み reader binding を local environment でも使える。実行依頼はその本人が署名する。これは他の environment へ鍵を配る操作ではなく、既に開ける内容を手元で使う操作である。遠隔実行先へ reader の秘密鍵を転送する代替経路にはしない。

### 操作の意味

| 操作 | 意味 |
| --- | --- |
| `read` | 名前、状態、共有先などのメタデータを見る |
| `reveal` | 機密本文を自分のクライアントで開く。secret、connection、app に同じ意味で適用する |
| `use` | 許可された実行環境で、承認された操作に秘密を利用する |
| `execute` | environment や function に対して許可された仕事を依頼する |
| `share` | 自分が委任できる範囲で権限や復号先の変更を承認する |
| `update` | 許可された本文や設定を更新する。復号先の拡大を含まない |
| `transfer` | 所有者と権限の起点を、受取側の確認と鍵の準備を伴って変更する |

権限表現は既存の owner、member、agent、grant を基礎とする。ただし機密情報や実行権限に影響する変更には、署名された証明を伴わせる。DB の grants と relations は、その証明から構築する索引でもあり、別の権限原本にはしない。

### 署名付きの権限

所有者の承認済み署名鍵を resource の権限の起点にする。委任する場合は、その親の許可を参照する署名付き statement を作る。実行環境は自分が保持する信頼の起点まで証明をたどり、管理サーバーの判定とは別に検証する。

statement は発行者、対象、許可する action、対象 environment、操作制約、委任の可否と範囲、発効・期限、世代、親の digest を含む。子の委任では対象を広げず、action を増やさず、期限を延ばさない。`share` がない主体は新しい委任を発行できない。証明の循環を拒否し、証明チェーンの初期上限を 16 段とする。

```ts
type GrantStatement = {
  id: Id;
  issuerId: Id;
  issuerKeyId: Id;
  subjectId: Id;
  subjectBindingIds: Id[];
  target: { kind: 'principal' | 'resource'; id: Id };
  actions: Action[];
  environmentIds: Id[];
  constraintDigests: string[];
  parentDigests: string[];
  delegation: { actions: Action[]; maxDepth: number };
  revision: number;
  notBefore: Time;
  expiresAt: Time | null;
};
```

grant は空の制約を「何でも許可」と解釈しない。対象操作に必要な制約が不足すれば承認を求める。所有の根拠や owner・member による管理の委任も署名でたどり、最初の resource 作成時に権限の起点を固定する。サーバーが提示する別の自己署名鍵を、新しい所有者の証明として採用しない。

親子の制約は積集合として適用する。独立した複数の grant の緩い部分だけを組み合わせて、一つの許可を作らない。要求した操作全体を満たす証明チェーンと、必要な全 resource の許可をそれぞれ検証する。

永続的な所有・保管の許可には期限なしを使える。自動実行を委任する grant の期限は承認時に決め、期限なしを選んだ場合は、失効が配送されないと期間で停止させられないことを示す。個々の run には必ず期限を持たせ、既定を登録から 24 時間とする。長時間継続する仕事は、別に承認した継続処理の委任を使う。

resource ごとの access policy は、適用する権限証明と具体的な復号先を結び付ける。

```ts
type AccessPolicy = {
  resourceId: Id;
  ownerId: Id;
  revision: number;
  previousDigest: string | null;
  authorityBindingId: Id;
  grantDigests: string[];
  readers: Array<{ principalId: Id; keyBindingId: Id }>;
  executors: Array<{
    environmentId: Id;
    executorId: Id;
    keyBindingId: Id;
    constraintDigest: string;
  }>;
};
```

policy と暗号文の recipient は一致させる。環境の鍵が変わった場合は、以前の承認に含まれる鍵更新の委任で検証できるか、改めて承認する。サーバーに登録されている最新の公開鍵へ無条件に再暗号化しない。

更新時には、権限証明、policy revision、resource version、全 recipient の変更を一つのトランザクションで確定する。署名と包み直しに必要な鍵がなければ承認待ちにし、管理サーバーで代行しない。

### owner と member の変更

owner や member が増えることで既存 resource の閲覧対象が広がる場合、現在の共有計画と同じように、対象 resource と鍵の配布を計画する。秘密を開ける承認済みクライアントが、新しい対象の鍵を確認して包み直す。機密 resource を含む関係変更は、計画対象すべての処理が揃ってから確定する。

関係の追加だけで executor の集合を広げない。member として機密本文を閲覧できることと、その人が管理する全 environment に秘密を配ることは区別する。

関係や grant の取り消しは、オンラインでの新しい取得・実行を止める。保持済みの鍵や平文を消したことにはならない。将来の本文を保護するための再暗号化と、外部トークンを無効にする処理は別に行う。

### 秘密を見せずに操作を依頼する範囲

機密開示を含まない `use` の委任では、所有者が承認した function の内容のハッシュと引数制約に従って操作を許す。function の参照先、認証情報を差し込む位置、結果として返す項目を署名対象に含める。function を更新したら、その新しい内容への承認を必要とする。

任意の HTTP 宛先や任意の command に秘密を渡すことは、依頼者が秘密を持ち出せる実行である。その場合は依頼者の `reveal`、所有者が内容を確認した一回限りの実行承認、または「依頼者が作るコードへ秘密を渡す」範囲を明示した継続的な委任を必要とする。制約を指定しない `use` だけで任意 command を組み立てられるとはしない。

継続的な任意コードへの委任には、依頼者の binding、対象秘密、実行環境、ネットワーク・sandbox・結果の制約、期限を含める。この委任は実質的な機密開示を含む。`reveal` API の権限を別に保持していても、任意コードを通じた取得を防げるとは説明しない。これにより、利用者が選んだ Agent の自律的な操作を、毎回の人手承認なしでも許可できる。

初期の実行制約は `function`、`approved-intent`、`caller-program` の三種類とする。それぞれ承認済み function digest、一回限りの intent digest、上記の機密開示を含むコード実行範囲を表す。`caller-program` は明示した承認がある場合だけ生成する。単なる環境の追加を、その依頼者への任意コードの許可として扱わない。

宛先の allowlist や出力のマスキングは補助である。任意プログラムに入力した秘密について、文字列を変形した持ち出しまで防げるとは説明しない。利用者が自由に書いたコードを使う場合、そのコードを信頼対象として扱う。

## 機密本文の形式

secret、connection、app に共通の `SealedPayload` を使う。名前・種類・所有者・公開可能な状態は resource のメタデータに置き、機密本文だけを暗号化する。

暗号化には、既存実装と同じ `ECDH-ES+A256KW` と `A256GCM` による JWE General JSON Serialization を使う。各 payload revision で新しい content encryption key と IV を生成し、recipient ごとに鍵を包む。暗号アルゴリズム自体を独自実装しない。[JWE](https://www.rfc-editor.org/rfc/rfc7516.html)

```ts
type SealedPayload = {
  protocol: 1;
  resourceId: Id;
  ownerId: Id;
  kind: 'secret' | 'connection' | 'app';
  materialRevision: number;
  policyDigest: string;
  previousDigest: string | null;
  envelope: JweGeneral;
  proof: Jws;
};
```

AAD には protocol、Foundation origin、resource ID、owner ID、kind、material revision、policy digest を含める。別の resource、所有者、Foundation origin への流用を防ぐ。`kid` は具体的な encryption key ID とする。

`proof` は本文の外側の全メタデータと envelope 全体の digest を署名する。JWE の recipient header だけを改変して、承認済みの鍵に見せかけることを防ぐ。AES-GCM の検証だけを、書き手の権限の証明として使わない。

署名には JWS を使い、署名対象と digest の生成には RFC 8785 の JSON 正規化を用いる。重複した JSON property、想定外の algorithm、未知の critical header、無効な鍵、受取先の重複を拒否する。[JWS](https://www.rfc-editor.org/rfc/rfc7515.html)、[JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)

サーバーは署名、権限証明、revision、recipient の一致、構造とサイズを検証する。暗号文の中身が意図した資格情報かは検証できないため、書き込むクライアントの自己復号検証と、利用する実行環境の内容検証を必要とする。

初期上限は、機密本文 1 MiB、recipient 100 件とする。上限超過は明示的なエラーとし、共通のサーバー鍵や無制限なグループ鍵へ置き換えない。

### 本文の種類

| kind | 暗号化する本文 | 非機密の索引として持てる情報 |
| --- | --- | --- |
| secret | 任意の bytes と必要な content type | サイズ、共有先、更新日時 |
| token connection | credential fields、承認済み method snapshot | method、account の表示、output 名、状態 |
| OAuth connection | access token、refresh token、有効期限、provider 固有状態、method と app の binding | 確認した account、scope、期限、状態 |
| role connection | ロールの利用設定、参照する workload identity、必要な機密値 | role の表示、実行可能な環境、状態 |
| app | client secret などの機密 fields | client ID、client type、redirect の仕様、対応 method |

OAuth の client secret は app に置き、connection に無制限に複製しない。connection の実行可能性は、参照する app と workload identity まで含めて確認する。管理サーバーが持つ account や scope の表示用索引は、実行環境が署名した状態を反映する。

## 実行プロトコル

### 実行先の決定

run は必ず environment を指定する。CLI の `exec` は現在の端末の local environment を選ぶ。遠隔の `run` は明示した environment、または利用者が事前に選択した既定の environment を使う。既定値がなければ選択を求める。

environment が秘密の復号先でない場合、実行を登録する前に共有・承認の必要性を示す。指定先が停止している場合は、その実行先を待つ。別の運営者や鍵への変更は新しい承認として扱う。

Foundation Agent は、利用者が選べる常時稼働の既定実行先になれる。接続・app・実行権限が揃っていれば、依頼者の端末が停止しても開始・継続できる。所有者のログインセッションを保持して動かすのではなく、事前の委任を使う。

### 依頼と結果

```ts
type RunIntent = {
  runId: Id;
  ownerId: Id;
  actorId: Id;
  actorKeyId: Id;
  environmentId: Id;
  environmentManifestDigest: string;
  kind: 'http' | 'command' | 'function';
  sources: Array<{
    resourceId: Id;
    policyDigest: string;
    material:
      | { kind: 'pinned'; revision: number; digest: string }
      | { kind: 'renewable'; connectionGeneration: number; authorizationDigest: string };
  }>;
  functionDigest: string | null;
  grantDigests: string[];
  specDigest: string;
  resultRecipients: Array<{ principalId: Id; keyBindingId: Id }>;
  createdAt: Time;
  notAfter: Time;
  nonce: string;
};
```

依頼者は intent と実行内容の digest を署名する。実行内容は実行環境と承認済みの閲覧者へ暗号化する。引数、stdin、HTTP body に機密情報がある場合も管理サーバーへ平文で置かない。secret や connection の値は埋め込まず resource ID と output の参照で指定する。

run の入力・結果にも共通の JWE 処理を使い、AAD に用途、Foundation origin、run ID、intent digest、受取先の digest を含める。承認入力には request ID、操作 index、操作 digest を結び付ける。resource の暗号文を、run の結果や別の承認入力として流用できる形式にはしない。

通常の secret は依頼時の material revision に固定する。OAuth の access token は実行時に更新され得るため、認可済み account、client、method、policy を固定し、その条件内の最新の署名済み material を使う。任意の新しい資格情報を「最新版」として差し替えられる契約にはしない。

`authorizationDigest` は承認した account、client、scope 上限、method と依存する app の binding を指す。role による更新可能な一時資格情報も同じ考え方で扱う。通常の secret の固定 revision が取得できない場合は `material_changed` とし、新しい内容への実行意図を確認する。実行を続けるためだけに、過去の token の利用可能なコピーをサーバーへ残し続けない。

実行環境が返す結果の署名は、run ID、intent digest、attempt ID、実行環境の鍵、状態、結果暗号文の digest を含む。結果の受取先は intent の集合と一致させる。サーバーの指定で結果を別の鍵へ送り直さない。

### 処理の順序

1. クライアントが必要な権限・鍵・capability と実行先の manifest を確認する。
2. サーバーが依頼者の認証、署名、権限、上限、暗号文のサイズを検証し、intent と実行内容を保存する。
3. 指定 environment が外向き接続で仕事を取得する。サーバーから端末への任意の着信接続は要求しない。
4. 実行環境が署名、鍵の系譜、policy、期限、nonce、function digest、実行内容の digest、受取先を検証する。
5. サーバー上の現在の失効・権限状態も確認する。実行環境が記録済みの revision より古い証明は受け入れない。
6. 実行環境が必要な秘密だけを復号し、接続の更新、入力の展開、外部 API 呼び出しまたは command 実行を行う。
7. 必要な生成物を実行環境で暗号化して保存し、暗号化した結果と署名済み receipt を返す。

サーバーの再起動で依頼者の短命な session が切れても、独立した期限付き委任が有効なら run を実行できる。実行承認の取り消しや actor key の失効は開始時と外部操作直前に確認する。

### 実行状態と重複

run の状態は `queued`、`running`、`succeeded`、`failed`、`cancelled`、`uncertain` とする。`queued` の理由として `environment_offline`、`capacity` を返す。鍵や権限が不足した依頼は、原則としてキューへ入れる前に解決する。

lease は初期値 60 秒、heartbeat は 15 秒とし、仕事の取得には単調増加する fencing number と attempt ID を割り当てる。実行機は run ID と attempt の消費記録を耐久保存する。二重配達には保存済みの receipt を返す。

attempt の内部進行は `claimed`、`prepared`、`dispatched`、`settled` とする。外部送信または子プロセス開始の前に `dispatched` を耐久記録し、サーバーへ確定させる。run ID 単位でも送信済みを記録し、attempt ID や fence だけを変えた配達で再実行しない。同一 environment を複数プロセスで動かす場合、その環境が管理する一つの耐久 journal と排他制御を共有する。

外部へまだ送信していないことを確認できる仕事だけを再配達する。外部へ送信した後に結果が不明になった操作は `uncertain` とし、lease の期限切れだけで別の実行機へ再実行させない。外部サービスと共有する idempotency key がある場合は、その保証範囲で再開できる。

取消しは、未開始なら `cancelled` とする。開始後は実行先へ停止を要求するが、完了済みの外部操作を取り消したとは表示しない。停止確認が取れない場合には `uncertain` とし、外部状態の確認を促す。

### ネットワークと入力の扱い

HTTP 実行は HTTPS、承認した origin、method、パス・引数の制約を検証する。認証情報を付けたリダイレクトは自動追従しない。DNS の解決結果を接続時にも固定し、通常の外部 API 実行では private、loopback、link-local、クラウド metadata endpoint を拒否する。

OAuth のローカル callback 用 loopback listener は、外向き HTTP 実行とは別の用途として許可する。自前実行機で社内 API を使う場合は、その実行機の所有者が別途明示したネットワーク許可を必要とする。URL を渡すだけでネットワークの境界を緩めない。

command では既存の予約変数名の検証、private な一時ファイル、入力サイズと実行時間の制限を継承する。既知の秘密の出力マスキングは実行側で行い、マスキング前のログをサーバーへ転送しない。エラーの公開情報は code と安全な短文に限定し、provider の応答詳細は結果と同じ受取先へ暗号化する。

### 結果を使った秘密の作成

HTTP の `save` や command の生成物から secret を作る場合も、実行環境が保存先の承認済み policy へ暗号化する。保存する ID、名前、所有者、policy、上書き対象の version を intent に含める。実行側へ必要な `create` または限定した `update` を委任する。

結果を書き込む権限を、保存先の共有先を変える権限として扱わない。自分を recipient に加えたり、依頼者が指定していない resource を上書きしたりできない。

## 接続の取得と更新

### 接続方法と実行可能性

method は資格情報の取得・更新・利用方法を定義する。app は OAuth client の登録情報を表す。connection は、実際に承認した account、scope、method、app と取得済みの資格情報を結び付ける。

method の snapshot には、issuer、token endpoint、identity endpoint、API の許可 origin、client authentication、PKCE、対応する callback、outputs、adapter とその版を含める。実行環境は承認済み digest の snapshot を使う。サーバーの catalog を更新しただけでは、既存トークンの送信先を変えられない。

Foundation 公式 app も Foundation の principal が所有する通常の app として扱う。catalog はその公開情報と承認済み binding を参照する。`appId = foundation` という特別な復号経路は持たせない。運営側の confidential client secret は、運営側が承認した runtime の鍵へ暗号化して登録し、管理 API の設定値から取り出して配る方式にはしない。

| 方法 | 資格情報を取得・更新する場所 | 条件 |
| --- | --- | --- |
| 手入力 API トークン | 入力したクライアント、利用する実行環境 | 入力後、送信前に暗号化する |
| Foundation 公式 public client | 利用者側または運営側の承認済み実行環境 | 提供元が端末向け client と callback をサポートする |
| 利用者所有の confidential client | client secret の復号を許可した実行環境 | app と connection の両方の権限・鍵が必要 |
| Foundation 所有の confidential client | Foundation が app の利用を認める運営側実行環境 | 共通 client secret を利用者の端末や配布 CLI に埋め込まない |
| ロールによる一時資格情報 | 対応する workload identity を持つ実行環境 | 提供元の trust policy でもその identity が許可されている |

public client とは OAuth の client authentication の区分であり、サービス固有の「誰でもそのアプリを利用できる」という公開範囲とは別である。Foundation 公式 public client なら、利用者ごとのアプリ登録は不要にできる。現行の confidential client の client ID をそのまま使えるとは仮定せず、必要な登録変更・新規登録と provider の審査を確認する。

端末向け OAuth は外部ブラウザで承認を行い、PKCE を用いてクライアントが token endpoint と交換する。Cloudflare では CLI 等の client に Authorization Code、PKCE S256、token endpoint authentication `none` が定義されている。これは、すべての provider の同じ対応を意味しない。[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html)、[Cloudflare の client 登録](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/#choose-a-flow)

ブラウザからの直接交換には provider の CORS などの条件もある。利用できない場合は承認済み CLI・実行環境で交換する。管理サーバーを平文の token proxy にして解決しない。

DPoP など資格情報が特定の鍵・インスタンスへ拘束される方式は、その拘束を扱える adapter と実行環境がある場合だけ対応を公開する。access token だけを別環境へ配って利用可能と表示しない。対応を実装しない段階では接続可能としない。

### 接続の作成

1. 利用者が method、app、利用 account、scope、実行環境を選ぶ。
2. クライアントが必要な依存先まで確認し、選んだ環境が取得・更新・利用を完結できるか検証する。
3. 所有者が共有先と実行制約を承認し、署名済み access policy を作る。
4. 手入力トークンはクライアントで暗号化する。OAuth は選択した実行環境で認可 transaction を開始する。
5. 取得した資格情報から account と実際の scope を確認し、実行環境が状態に署名する。
6. policy の recipient へ本文を暗号化し、connection を `ready` として保存する。

依頼者が別の principal に接続を求める場合も、この処理を approval request の中で行う。入力欄が `secret` である値を、汎用の承認 API の body に平文で送らない。承認するクライアントで暗号化するか、指定した実行環境に向けた暗号化入力として扱う。

既存 secret から connection を作る場合、その変換と新しい共有先を承認する。参照元の `use` だけで、別の所有者・recipient 向けに秘密を複製できる経路にはしない。

### OAuth の認可 transaction

実行環境がランダムな state と PKCE verifier を作り、選択済み issuer、client ID、redirect URI、scope、connection ID、policy digest、実行環境の鍵に結び付ける。初期の有効期限は 10 分とし、一回だけ消費する。

verifier と app の秘密は実行環境内、またはその環境だけを recipient とした transaction の暗号文に置く。管理サーバーは認可 URL、進行状態、暗号文を取り次ぐ。

callback は端末の loopback、クライアントに紐付いた redirect URI、承認済みの実行環境の callback を優先する。管理サーバー上の relay を使う場合、認可コードだけを対応する transaction に中継し、そこで token endpoint に交換しない。relay が認可コードを観測できることを前提に、PKCE verifier を渡さず、ログ・Referer・任意 return URL への漏えいを防ぐ。

実行環境で state、認可応答の issuer または issuer を識別できる専用 redirect、client ID、redirect URI、transaction の一回性を検証する。PKCE は S256 を使い、public client で無効化しない。provider ごとの例外は接続前に catalog の capability として明示し、失敗時の自動 downgrade は行わない。

承認した account、client、scope が変わる場合は、その結果を既存の利用者へ配る前に所有者の再承認を必要とする。確認用の資格情報は取得した環境と承認者にだけ暗号化して保持する。取り消した認可は可能なら同じ環境で revoke する。

PKCE、issuer の確認、redirect の一致、refresh token の保護は OAuth Security BCP に従う。PKCE があること自体を、サーバーからトークンを隠す保証とは扱わない。[OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)

### OAuth 更新の委任

承認された実行環境は、connection の利用に必要な token 更新も行える。そのために `update` のうち `connection-refresh` に限定した委任を与える。変更できるのは token、期限、provider が返した継続状態とその索引だけであり、owner、recipient、method、client、承認範囲を変更できない。

初期設計では、一つの OAuth connection の access token と refresh token を同じ暗号化本文に保管する。したがって、その本文を開ける実行環境には refresh token も開示される。配布先を信頼対象とする設計であり、更新担当という論理上の役割だけで refresh token を隠せるとは扱わない。

複数環境が同じ connection を使う場合、更新は connection 単位で直列化する。異なる信頼範囲に access token だけを配りたい要件は、別 connection または更新元への限定した操作委任で扱い、初期設計の本文へ隠れた権限区分を追加しない。

### 更新の競合と応答喪失

refresh token rotation では、同じ古い token を二つの実行機が使うと接続を失う可能性がある。単なる暗号文の最終書き込み勝ちでは扱わない。公開クライアントの refresh token は provider 側でも replay を検出できる保護が必要である。[RFC 9700 の refresh token 保護](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14)

1. runtime が現在の material revision を指定して `connection-refresh` operation を取得する。サーバーは同じ connection に未解決の operation が一つだけになるよう制約する。
2. runtime がローカルの耐久 journal に operation ID、fence、旧 revision を記録する。
3. サーバー上で `in_flight` を確定してから token endpoint を呼ぶ。
4. 応答を受けたら、新しい資格情報をローカルで暗号化して耐久保存し、その後に新しい SealedPayload を作る。
5. 同じ operation ID と expected revision で、暗号文と索引を原子的に commit する。再送時には同じ commit 結果を返す。

`prepared` のまま送信していなければ operation を解放できる。`in_flight` 後の lease 切れは `uncertain` とし、別の環境が同じ refresh token を自動再使用しない。元の runtime が journal から結果を再送するか、provider の確認可能な回復手順を使う。どちらもできなければ再接続を要求する。

更新 operation が `uncertain` の間は新しい資格情報の利用を停止し、`connection_uncertain` を返す。connection の表示用状態が `ready` であることだけを、実行可能性の判定には使わない。journal に基づく確定または再接続で不明状態を解決してから利用を再開する。

応答受信とローカル耐久保存の間に停止する窓は完全には消せない。provider による冪等性の保証がない限り、通信失敗を理由に refresh を再送しない。

更新済みの token は、connection の同じ recipient 集合へ暗号化する。旧 policy を持つ実行機からの commit は拒否し、最新 policy への再承認済み処理を要求する。再接続で認可 grant 自体を置き換えた場合は connection generation を上げ、古い operation の遅れた応答を採用しない。

### 共有変更と更新の排他

通常の共有変更は、新しい refresh の開始を止め、進行中 operation の確定を待ってから、最新の本文を新しい policy へ暗号化する。policy 変更と refresh commit を同じ connection の version と排他境界で直列化し、古い本文で新しい token を上書きしない。

緊急の失効では新規利用の停止を先に行えるが、既に送信した refresh を未実行だったことにはしない。新しい token の保存・provider での解除・再認可のいずれかで状態を解決してから、recipient の変更を完了する。未解決の応答を持つ runtime からの暗号化済み回復記録は隔離して保持し、現在の資格情報として自動採用しない。

管理サーバーには、暗号文内の token が本当に同じ account や scope を表すかを証明する能力はない。これらを確認して署名する runtime も信頼対象である。サーバーは公開された authorization digest と更新範囲を検証し、受け取る runtime も復号後に対応関係を検証する。

Foundation Agent が承認済みで必要な app にアクセスできれば、この更新も利用者不在で実行できる。provider 側の失効、追加認証、再同意が必要な状態まで自動で解決できるわけではない。

### ロールの接続

AWS 等の role connection は、実行環境の workload identity と外部 trust policy を使って一時資格情報を得る。管理サーバーのクラウド credential を全 environment に転送しない。

Foundation が運営する identity にだけ許可したロールは、そのまま自前環境で利用可能にはならない。自前環境を使う場合は provider 側でその identity を承認する。外部 trust policy の変更は、この設計の適用だけでは自動実行しない。

## 承認と継続処理

approval request は操作の提案を運ぶものであり、提案者に権限を与えるものではない。承認者は、依頼者、所有者、実行環境とその運営者、共有先、外部サービス、scope、操作内容を確認する。

承認の署名は request ID と操作の digest、実行先、鍵、期限、必要な権限に結び付ける。パラメータや実行先が変わったら同じ承認を再利用しない。メールリンクや request session は対象を開くために使い、鍵の解除や強い委任を代替しない。

定期処理やイベント起動も、事前に承認した function digest、引数の制約、起動条件、実行先、期限を持つ委任の範囲で動かす。ユーザーの session を偽装して起動しない。スケジュール tick や外部イベントはトリガーであって権限の起点ではない。

Webhook の内容が操作に影響する場合は、実行環境で提供元の署名や event ID を検証する。管理サーバーから来たという理由だけで、provider が送信した事実を認定しない。承認済みのトリガー ID と消費済み event ID により重複起動を抑制する。

本変更では定期処理の新しい製品機能や任意 provider の Webhook adapter を一括追加しない。既存または今後の起動機能が、この実行契約を使う境界を定める。

## API と CLI

### 共通 API

以下の endpoint は新しい実行モデルの契約とする。機密本文を受け取る endpoint は、共通の SealedPayload または対象 runtime への暗号文を受け取る。

| endpoint | 契約 |
| --- | --- |
| `POST /api/principals/:id/key-bindings` | 証明付きの公開鍵 binding を登録する |
| `GET /api/principals/:id/key-bindings` | 公開鍵、証明、世代、失効状態を返す |
| `POST /api/principals/:id/resources` | メタデータと、必要なら初期 policy・暗号文を原子的に作成する |
| `GET /api/resources/:id/sealed` | 権限に応じて署名付き暗号文と policy を返す |
| `PUT /api/resources/:id/sealed` | expected version と更新証明で機密本文を更新する |
| `POST /api/resources/:id/access-plan` | 権限・recipient の変更による影響と必要な再暗号化を返す |
| `PUT /api/resources/:id/access` | 署名済み policy と暗号文を原子的に適用する |
| `POST /api/environments/:id/attach` | environment の署名・鍵所持を確認して稼働セッションを開始する |
| `POST /api/environments/:id/heartbeat` | セッションに紐付く状態と処理中の lease を更新する |
| `POST /api/environments/:id/claims` | 自分宛ての仕事を取得する |
| `POST /api/principals/:id/runs` | 署名済み intent と暗号化した実行内容を登録する |
| `GET /api/runs/:id` | 公開可能な状態、receipt、受取人向けの結果暗号文を返す |
| `POST /api/runs/:id/receipts` | 実行環境の署名で進行・完了結果を記録する |
| `POST /api/runs/:id/cancel` | 権限を検証し、取消し要求とその証明を配送する |
| `POST /api/principals/:id/connections` | 接続計画と認可 transaction を作る。token の平文は受け取らない |
| `POST /api/connections/:id/operations` | refresh、revoke 等の排他的な operation を開始する |
| `POST /api/connections/:id/operations/:operation/start` | operation を `in_flight` にして外部送信前の境界を確定する |
| `POST /api/connections/:id/operations/:operation/commit` | operation に結び付く暗号文・状態・receipt を確定する |
| `POST /api/connections/:id/operations/:operation/abort` | 外部送信前の operation を終了する |

実行環境の attach と heartbeat は、サーバーの challenge、environment ID、有効期限に対する署名で鍵の所持を確認する。API トークンの盗難だけで別環境がその名前を使って仕事を消費できることを防ぐ。

`claims` は外向き HTTPS の long polling を初期実装とする。一回の待機は最大 25 秒とし、接続方式を変えても job と署名の形式は変えない。rate limit と上限は principal と environment ごとに設定する。

接続 operation には `prepared`、`in_flight`、`committed`、`uncertain`、`aborted` を持たせる。送信開始の確定と abort の API は同じ operation resource 上の状態遷移として提供する。平文を返す汎用 `connection outputs` API は設けず、output の解決は runtime 内で行う。

`GET sealed` の許可は `reveal`、または呼び出している environment が対象 policy の executor であり、有効な operation に必要であることによる。メタデータの `read` だけで任意の本文を配布しない。

すべての更新は expected version による競合検出を行う。同じ ID・同じ署名内容の再送は同じ結果を返し、同じ ID で内容が違う再送は `409 conflict` とする。ランタイムが暗号文内で見つけた参照と intent に列挙した参照が一致することも検証する。

### CLI の利用形

```sh
foundation init --name my-pc
foundation agent start
foundation keep cloudflare-token --stdin --for ENVIRONMENT_ID
foundation connect cloudflare --environment ENVIRONMENT_ID
foundation exec --inputs @inputs.json -- command
foundation run --environment ENVIRONMENT_ID --request @request.json
foundation run --environment ENVIRONMENT_ID --function FUNCTION_ID --arguments @arguments.json
foundation wait RUN_ID
foundation read SECRET_ID
```

`init` は認証と独立した暗号化・署名鍵を手元で生成する。`agent start` は、この端末を承認した environment として待ち受ける。local `exec` は同じ実行ライブラリを一時的に使うため、常駐 agent の起動を必須にしない。

`keep` の `--for` は承認する environment を指定し、複数回指定できる。省略時は所有者側の保管だけを行う。運営側の実行機を自動追加しない。共有先の追加・削除は Web UI または共通 access API を使う。

`exec` は手元で入力を解決する。自分に `reveal` があり鍵を持つ secret は、そのまま手元の command に渡せる。別の主体から委任された secret は、その委任で認められた function、個別 command、または明示された `caller-program` の範囲で使う。

`--allow-use` は最終契約から外し、実行環境の選択に統一する。旧 CLI は移行時に更新を要求し、旧 flag を隠れて Foundation Agent の選択として解釈する互換層は残さない。

### MCP と他のクライアント

Foundation のリモート MCP サーバーも管理 API と同じ権限で動く。利用者側だけが復号できる入力や結果を、MCP サーバーが中継のために復号する例外は作らない。

利用者側の bridge が暗号化・署名・結果の復号を行うか、利用者が明示した Foundation Agent が実行し、承認された結果だけを AI へ返す。結果を Foundation 側で平文表示・配送する必要がある場合は、その表示・配送担当を結果の受取先として明示する。これは接続の秘密をその担当へ渡すこととは別の許可である。

署名鍵や復号鍵を持たないクライアントは、メタデータの参照と承認の依頼を行える。認証に成功したという理由だけで署名をサーバーが代行しない。

運営側 bridge に継続実行を委任した場合、bridge は自分の principal と署名鍵で、受けた委任の範囲だけを依頼する。元の利用者がその時点で署名したことにはせず、依頼の入口と実際の署名主体を監査に残す。利用者側だけの接続へ運営側 bridge を使うには、その接続で承認された実行制約と依頼権限が必要であり、復号先への追加とは別に確認する。

## 利用者に見せる状態

接続の詳細には「操作を依頼できる相手」「内容を表示できる相手」「秘密を扱う実行環境」を分けて表示する。実行環境には運営者を併記する。

| 場面 | 表示する内容 |
| --- | --- |
| 実行先の選択 | `自分の PC`、`さくら VPS`、`Foundation Agent` と各運営者 |
| Foundation Agent を復号先へ追加 | `Foundation が管理する実行環境に、この接続の秘密を扱うことを許可します。` |
| 実行機の停止 | `選択した実行環境の接続を待っています。` |
| 鍵の配布前 | `鍵を持つ端末で、この実行環境への共有を承認してください。` |
| API 認証はできるが鍵がない | `認証済みです。秘密を開くには鍵の解除が必要です。` |
| 更新結果が不明 | `接続の更新結果を確認できません。再接続が必要な場合があります。` |
| 外部操作の結果が不明 | `処理結果を確認できません。再実行する前に接続先を確認してください。` |

接続状態と実行機の稼働状態は別々に表示する。connection が `ready` でも environment が停止中なら、接続が壊れたとは表示しない。

`connection.state` は `authorizing`、`ready`、`review`、`reconnect`、`disconnecting`、`disconnected` とする。refresh operation の競合や進行は connection operation の状態で示し、通常の更新ごとに connection 全体を不明瞭な「接続中」へ戻さない。

「ゼロ知識」という切替スイッチは設けない。現在の復号先とその運営者から信頼範囲を説明する。Foundation が扱った履歴のある資格情報について、共有先から外しただけで「Foundation が一度も知らない秘密」に変わったとは表示しない。

## 失効と復旧

### 実行権限の取り消し

取り消しは署名付きの policy 更新として記録し、新しい取得・開始を止める。実行中の処理には停止を要求する。実行機は起動時と外部操作直前にオンラインで現在の状態を確認し、確認できなければ新しい外部操作を始めない。

署名鍵を失った場合でも、アカウント認証に基づく緊急停止は行える。これは権限を狭める停止状態であり、新しい実行や復号先を承認する能力ではない。再開・権限追加・鍵交換には正当な署名または事前に定めた復旧権限を必要とする。

サーバーが正常に失効を配布することと、悪意あるサーバーが通知を隠す場合の保証は区別する。署名と既知 revision の保存で巻き戻しを検出し、期限付き委任で残存期間を制限するが、未知の最新失効を暗号だけで知ることはできない。即時失効と完全なオフライン実行を同時に保証しない。

権限を受け取った相手が資格情報をコピーして直接 provider に使う行為は、Foundation の権限だけでは止められない。外部サービスでの token revoke・rotation を別の操作として提示する。

### 鍵の交換と紛失

鍵交換は旧鍵または承認済み復旧権限の署名で新 binding を作り、新しい recipient へ本文を再暗号化する。新環境の利用開始と、旧鍵の新規利用停止を同じ変更計画に含める。

失った鍵が既存の暗号文を保持している可能性がある場合、新しい content encryption key へ再暗号化する。外部 credential の値を変更しなければ、その値を既に読んだ相手の利用は止まらない。

復旧用 bundle は、暗号化鍵と権限の継続に必要な署名鍵・信頼の checkpoint を含め、利用者が保持するランダムな復旧鍵へ暗号化する。複数の承認済み端末や明示した復旧担当への配布も同じ仕組みで扱う。運営側を復旧担当に選んだ場合、その対象について運営者を信頼することを明示する。

鍵と復旧手段をすべて失った場合、メールでアカウントへのアクセスを回復できても、過去の機密本文は復号できない。新しい接続の作成・外部サービスでの再認可が必要になる。

### 接続解除と削除

接続解除は、まず新しい利用を止め、許可済みの実行環境に provider への revoke を依頼する。実行機が不在なら `disconnecting` のまま待つか、利用者に provider での手動解除を案内する。ローカルの暗号文を消しただけで外部 token が失効したとは扱わない。

削除は、外部解除、実行中 operation、保持すべき receipt を確認してから進める。アカウント削除のために必要な鍵を、外部解除より先に破棄しない。provider 側の解除を確認できない場合は、その未完了を明示する。

### export と所有権移転

export は暗号文、policy、公開鍵 binding、署名付き履歴をそのまま出力する。connection の中身を管理サーバーで復号して export 用に暗号化し直さない。秘密鍵の持ち出しは別のクライアント側操作にする。

transfer と account merge は、元と先の権限証明、暗号文を開けるクライアント、新しい recipient の準備を必要とする。resource ID を維持する場合も、owner を含む AAD と proof を作り直す。未処理の run、認可 transaction、refresh operation を片付けてから一括確定する。鍵がないことを理由に管理サーバーで代替復号しない。

## 保存構造

既存の principals、credentials、resources、relations、grants、runs、approval_requests、audit_log を基礎にする。以下を新しい原本と索引として追加・整理する。

| 保存先 | 主な内容 | 整合性の条件 |
| --- | --- | --- |
| `principal_key_bindings` | 公開鍵、用途、世代、承認証明、失効 | key ID と fingerprint の対応を固定する |
| `authority_statements` | 署名付きの関係・委任・取り消し | digest を一意とし、親の範囲を超えない |
| `resource_access` | resource の現在の policy と署名 | resource ごとに revision を単調増加させる |
| `resources.sealed` | 共通 SealedPayload | policy と recipient、所有者、revision が一致する |
| `environment_sessions` | 実行機の鍵所持証明、heartbeat、接続状態 | environment と binding に紐付ける |
| `run_attempts` | intent digest、fence、進行、暗号化結果、receipt | run と attempt の一意性、再送の冪等性を持つ |
| `connection_operations` | refresh・revoke の状態、旧 revision、fence、receipt | connection に未解決の operation は一つとする |
| `credentials.private_wrap` | クライアントだけが開ける鍵 bundle | API 認証用 bearer token を wrapping key に使わない |

`resources.version` は更新の競合検出、`policy.revision` は権限の変更、`materialRevision` は機密本文の更新を表す。token 更新だけで新しい共有承認を求めない一方、policy の変更を token 更新に紛れ込ませない。

暗号文・metadata・policy・権限の索引の更新は同じ DB transaction で行う。ネットワーク越しの provider 呼び出しは DB transaction の外で行い、connection operation により順序と回復を管理する。

Foundation 自身の運営情報を除き、機密 resource の `private_data` にサーバー復号可能な別コピーを持たせない。run の本文・承認入力・結果にも同じ原則を適用する。一般の公開 object や非機密の resource 全体を暗号化し直すことは、この変更の対象外とする。

audit_log には actor、executor、environment、operator、resource ID、policy revision、intent と receipt の digest、状態、時刻を記録する。token、secret の値、HTTP body、command の機密引数は記録しない。サーバーによる履歴の削除を署名だけで防げるとはせず、必要な receipt と最新 checkpoint はクライアント側にも保持する。

## 実装の構成

| 層 | 配置する処理 |
| --- | --- |
| `shared` | schema、暗号文と署名の形式、鍵 binding、権限証明、入力・結果の契約 |
| `runtime` | policy 検証、秘密の解決、OAuth と role adapter、HTTP、command、refresh journal |
| `server` | 認証、署名・権限の検証、索引、暗号文保管、配送、lease、状態、課金 |
| `cli` | ローカル鍵、署名・暗号化、local runtime、遠隔実行のクライアント |
| `web` | 鍵解除、共有・実行の承認、暗号化、接続先選択、状態と信頼範囲の表示 |

`runtime` は local、attached、managed で同じ実装を使い、key store、transport、command sandbox、耐久 journal の adapter だけを差し替える。DB やサーバーの Vault を直接参照しない。

現行コードとの主な対応は次のとおりとする。

| 現行の箇所 | 新しい責務 |
| --- | --- |
| [shared/encryption.ts](shared/encryption.ts) | key ID と文脈を固定した共通暗号化、独立した署名・鍵 bundle の保護 |
| [server/authorization.ts](server/authorization.ts) | 既存の principal モデルを保ち、署名付きの権限原本と整合する判定を行う |
| [server/key-sharing.ts](server/key-sharing.ts) | 全機密 resource の共有計画と原子的な変更の検証を行う |
| [server/inputs.ts](server/inputs.ts) | 平文の解決・変換・保存は runtime へ移し、サーバーは参照と配送を扱う |
| [server/services.ts](server/services.ts) | 接続計画・公開状態・暗号文・operation の管理を行う |
| [server/oauth.ts](server/oauth.ts) | provider との交換・更新・確認・解除を runtime へ移す |
| [server/http-execution.ts](server/http-execution.ts) | 入力の展開と外部 HTTP を runtime へ移す |
| [server/runs.ts](server/runs.ts) | 署名済み intent、指定実行先、attempt、receipt を調整する |
| [server/environments.ts](server/environments.ts) | lifecycle と接続を管理し、利用者の秘密鍵を生成・注入しない |
| [server/runner.ts](server/runner.ts) | managed environment の起動・停止を担当する adapter とする |
| [server/runner-agent.ts](server/runner-agent.ts) | 共通 runtime の managed 起動経路へ統合する |
| [server/requests.ts](server/requests.ts) | 署名された承認と暗号化入力の進行を管理する |
| [server/accounts.ts](server/accounts.ts) | 暗号文の export、署名・鍵配布を伴う transfer・merge を扱う |
| [web/app/keys.ts](web/app/keys.ts) | 認証用 bearer と独立した鍵解除・鍵転送・署名を扱う |
| [server/mcp.ts](server/mcp.ts) | 管理 API と同じ秘密の境界を維持する |

既存の `jose`、`oauth4webapi`、入力検証、HTTP transport の防御を活用する。OAuth の protocol 処理を手書きに戻さず、adapter ごとの違いと実行場所を分離する。

## 現行データからの移行

### 現状の分類

移行元を次のように区別する。

| 対象 | 現行の状態 | 移行時の処理 |
| --- | --- | --- |
| `allowUse` を持つ secret | Foundation の server identity を recipient に含められる | 承認した実行環境への配布に置き換える |
| サーバーを recipient に含まない secret | クライアント側の鍵で保管される | 鍵の来歴を確認し、新 policy・署名・AAD へ変換する |
| token・OAuth connection と app | Vault で保管し、サーバーが復号・利用する | 承認済み recipient 向けの SealedPayload へ変換する |
| API credential の鍵 wrap | API token を材料に principal の秘密鍵を包む経路がある | クライアントだけが開ける新 bundle と新鍵へ移す |
| managed environment | サーバーが鍵を生成し環境変数へ渡す経路がある | 新 runtime が生成した独立鍵で登録し直す |
| 未完了の認可・run | サーバー側の平文処理を前提とする | 完了・取消し・結果確認を行ってから切り替える |

API token は認証時にサーバーへ送られるため、その token で包んだ principal 秘密鍵を「サーバーが知らない鍵」とは評価しない。`allowUse = false` だけで来歴を判定しない。

### 切り替えの手順

1. **事前点検**。resource、鍵、credential の wrap、recipient、未完了 operation を分類する。平文を一覧・ログに出さない。復元可能な DB と暗号文のバックアップを取得する。
2. **利用者側の準備**。新しい鍵 bundle と信頼の起点を承認済み端末で作り、復旧手段を確認する。Foundation Agent を利用する場合も、この段階で environment と鍵を明示して承認する。
3. **移行計画の承認**。誰がどの秘密を復号できるようになるかを一覧で示し、所有者が署名する。旧 server identity への許可を、別の実行機への無断の許可として扱わない。
4. **更新停止**。対象の新規書き込み・認可・実行を停止し、進行中処理を完了または確認する。外部操作の結果が不明なものは個別に解決する。
5. **独立した変換**。クライアントだけが開けるものはそのクライアントで変換する。サーバー保管のものは、限定した移行ツールで一度だけ復号し、承認された recipient へ直ちに暗号化する。
6. **整合性確認**。件数、ID、所有者、権限、復号先、署名、参照、復号確認を照合する。開けない項目があれば切り替えを止め、削除や空値への置換をしない。
7. **本番切り替え**。新 API・CLI・UI・runtime を同じ契約で有効にし、代表的な local と managed の実行を確認する。旧形式を読む通常経路は起動しない。
8. **後処理**。移行専用の権限と鍵を回収し、旧データ・バックアップは明示した保存期限と削除手順に従って扱う。強い非開示を必要とする資格情報は、利用者の承認を得て provider 側で更新・再認可する。

所有者が承認できない、利用者側の鍵がない、未解決の OAuth 更新がある場合は、その対象の移行は完了できない。無停止・無承認で全データを新しい信頼モデルへ変更できるとは約束しない。全対象の準備が整うまで切り替えを延期するか、対象ごとの停止期間を明示する。

### 履歴とロールバック

旧システムで運営側が扱えた token を再暗号化しても、過去の知識は消えない。現在の復号先と、過去に運営側で扱った記録を区別する。運営側へ一度も渡していない新しい資格情報にしたい場合、利用者側での token rotation または再認可が必要である。

新しいトークンへ変更した後に旧バックアップへ戻すと、無効な refresh token を復活させる可能性がある。旧スナップショットへ戻してよいのは、新方式での外部副作用や token 更新が始まる前までとする。それ以降は停止して新方式の状態を保ったまま修復し、必要に応じて再認可する。

旧形式の変換コードは一回限りの migration に閉じ込める。変更履歴や監査記録は維持するが、通常の型・画面・API に「旧方式なら」という分岐を残さない。

任意 command を `use` のみで実行できていた委任は、操作制約の確認が必要である。移行時に `reveal` を自動追加しない。必要な function、個別 command の承認、または機密開示を含む `caller-program` の委任へ整理する。従来の自律的な操作を続ける場合も、その範囲を一度確認すれば、以後すべての command で人の再承認を要求する必要はない。

## 検証と実装順序

### 振る舞いの検証

テストは以下の現在形の契約を確認する。特定のファイル配置や削除した識別子の不在を固定するテストにはしない。

| 領域 | 確認する振る舞い |
| --- | --- |
| 暗号化 | 承認した鍵で、resource・所有者・世代が一致する本文を開く |
| 鍵の追加 | 確認済みの binding と権限に基づいて新しい端末へ共有する |
| 認証 | API 認証と鍵の解除状態を独立して扱う |
| 主体 | 人・AI・アプリが同じ関係と権限で依頼・委任する |
| 実行先 | 指定した environment で実行し、停止中はその environment の接続を待つ |
| Foundation Agent | 許可された接続を、利用者端末が停止している間も利用する |
| 改ざん | 署名・digest・recipient・scope の不一致を安全なエラーとして扱う |
| `use` | 承認した function と引数範囲で秘密を使う |
| 任意 command | 個別の承認、明示した継続委任、または機密開示権限に従って入力を渡す |
| OAuth | 選択した環境で認可・交換・更新し、取得した account と scope を確認する |
| OAuth 競合 | 同じ connection の token 更新を一つずつ確定する |
| 共有と更新 | 共有先の変更時にも、確定した最新の token を維持する |
| 応答喪失 | 更新や外部操作の不明な結果を `uncertain` として回復手順へ進める |
| 再配達 | 同じ intent と attempt の再送に、保存済みの結果を返す |
| 取り消し | 新しい利用を停止し、外部解除の完了と未完了を区別する |
| 共有 | owner・member・recipient の変更を必要な鍵配布と一緒に確定する |
| 保存 | 実行結果から承認した所有者・共有先の secret を作成する |
| export | 鍵と policy に対応する暗号文を持ち出し、利用者側で復元する |
| 移行 | ID・内容・所有者・承認範囲を保ち、利用可能な新形式へ変換する |
| UI | 運営者、復号先、停止中、鍵待ち、再接続、結果不明を利用者向けの言葉で示す |

偽の provider、複数 runtime、切断可能な transport、任意箇所で停止する journal を使い、認可コードの再使用、鍵のすり替え、DB CAS 競合、token 応答前後の停止を再現する。暗号処理は known-answer test と異なる実行環境間の相互運用も確認する。

暗号形式、署名の権限チェーン、鍵の bootstrap、任意コードとの隔離は、実装段階で独立したセキュリティレビューの対象にする。振る舞いのテストが通ることだけを、これらの安全性の証明とは扱わない。

UI を実装した段階では、画面を実際に開き、承認に必要な情報が見えることと、開発会話・設計意図・移行作業の報告が通常の表示へ混ざらないことを確認する。

### 実装の区切り

1. **鍵と権限の契約**。KeyBinding、署名付き statement、AccessPolicy、SealedPayload と相互運用テストを確定する。
2. **保管と共有**。新しい保存構造、共有計画、鍵 bundle、失効、export・transfer を実装する。
3. **共通 runtime**。local の HTTP・command と attached 接続を実装し、同じテストを managed runtime に適用する。
4. **run の配送**。署名済み intent、暗号化結果、lease、receipt、取消し、uncertain の回復を実装する。
5. **接続**。token、OAuth、role を runtime に移し、認可・更新・解除と複数実行機の競合を検証する。
6. **利用者の操作**。Web・CLI・MCP・approval を同じ契約へ揃え、Foundation Agent の選択と信頼範囲を確認する。
7. **移行とリリース**。実データの分類に対応する migration を検証し、署名済み移行計画と復旧条件を満たして切り替える。

実装中に内部で旧処理と新処理を比較しても、リリース後の通常コードには二つの実行モデルを持たせない。移行不能なデータや未確認の provider capability を理由に、平文経路へ自動で戻さない。

### リリース前に確定する接続ごとの条件

provider ごとに、public client 登録の可否、redirect、CORS、PKCE、必要な client authentication、refresh token の挙動、取得可能 scope、revoke、account 確認、sender constraint を記録して実際の登録と照合する。

Foundation の既存 OAuth app に必要な scope が登録されているか、選んだ環境で交換・更新できるかは、一般的な OAuth 対応とは別に検証する。接続方式の対応範囲が不足する場合は接続前に説明し、許可していない Foundation Agent を裏で使って補わない。

本番の鍵交換、外部 token rotation、OAuth app の登録変更、データ移行、デプロイは、それぞれ実行時の対象と承認を確認して行う。この設計の作成によって実行済みとは扱わない。
