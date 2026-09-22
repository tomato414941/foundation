// Printed by `foundation --help`. Written for an AI agent that has just been told to use an
// external service and needs the whole procedure in one read. What each adapter is, receives
// and delivers comes from the server's own adapter list; nothing about a service is written here.
function adapterLines(adapters) {
  if (!adapters) return ['   使える接続方法とその説明は foundation adapters で確認する (FOUNDATION_URL が必要)。'];
  const lines = [];
  for (const adapter of adapters.filter(item => item.available)) {
    const service = adapter.service?.name || 'サービスは依頼時に申告';
    lines.push('   ' + adapter.id + '  ' + service + ' / ' + adapter.access.name + (adapter.variables.length ? '  渡す変数: ' + adapter.variables.join(', ') : ''));
    lines.push('     foundation connect --adapter ' + adapter.id + ' --purpose "<用途>"' + (adapter.declared ? '   (下の説明のとおり申告を付ける)' : ''));
    if (adapter.ai) lines.push('     ' + adapter.ai);
  }
  const unavailable = adapters.filter(item => !item.available);
  if (unavailable.length) lines.push('   現在使えない接続方法: ' + unavailable.map(item => item.id).join(', '));
  return lines;
}

export function guide(adapters) {
  return ['Foundation: 外部サービスの認証情報を、利用者の承認を経てコマンドの環境変数に渡す仕組み。',
    '利用者にキーやトークンをチャットへ貼らせてはいけない。必ず Foundation を通す。', '',
    '言葉: 認証情報 = 利用者が Foundation に預けた 1 件。接続方法 (adapter) = その種類で、受け取り方・確かめ方・渡し方を決める。サービス = 認証情報で届く先 (AWS、Gmail など)。',
    '自分の立場: あなたは Foundation 上で 1 つの「アクセスキー」の持ち主として扱われる。利用者がキーを 1 回承認すると、以後は利用者が預けた認証情報を全部使える (gh や aws の CLI のログインと同じ)。',
    '  foundation whoami で自分のキーの名前を確認できる (未承認なら 401 not_approved)。',
    '', 
    '手順',
    '1. キーの承認 (初回だけ)。foundation whoami が 401 not_approved なら、まだ承認されていない。',
    '   foundation connect   (オプションなし。名前を変えるなら --name) を実行し、出力の verification_uri と confirmation_code を利用者に伝える。',
    '   コードは利用者が手で打つので必ず表示する。利用者は URL を開き、コードを入れて承認する。この依頼では認証情報の登録はしない。',
    '   数秒おきに foundation whoami を試し、通ったら 2 へ。連打しない。',
    '2. 必要な認証情報が foundation credentials にあれば、依頼を作らずに 4 へ。なければ登録を依頼する。接続方法は次から選ぶ:',
    ...adapterLines(adapters),
    '   foundation connect --adapter <接続方法> --purpose "<用途>" [--guide "<案内>"] [--valid <分>]   出力の verification_uri を利用者に伝える (コードはない)。',
    '   用途は利用者が読んで判断できる具体的な 1 文にする。',
    '   --guide に、利用者が認証情報を登録するときの手順を書く (2000 文字まで、改行可)。登録画面に「依頼元のAIからの案内」として出る。',
    '   --valid <分> で依頼の有効期間を決める (既定 30、最大 1440)。他社の画面での作業が長くなりそうなら延ばす。',
    '   Foundation 自身は他社の画面の手順書を持たない。どこを押すかは、その時点で自分で調べて書く。',
    '   登録が失敗したときの Foundation 側の理由 (foundation request の events の code):',
    '     invalid_values = 入力欄の形が違う (空、改行、長すぎる、形式違い)。 invalid_credential = 値の中身を接続方法が受け付けなかった。',
    '     reconnect_required = サービスがその認証情報を受け付けなかった (無効・失効・取り違え)。',
    '     already_connected = 同じ認証情報が登録済み。 confirmation_required / confirmation_locked = 承認の確認コードの誤り (5 回で失効)。',
    '3. 利用者の操作を待つ。数秒おきに foundation credentials を試し、目的の認証情報が現れたら 4 へ。連打しない。',
    '   利用者が「できない」「どうすればいい」と言ったら foundation request を実行し、自分の依頼と、そのページで起きた出来事 (events) を読む。',
    '   events は時系列の生の記録: page_opened / page_viewed / connect_started / connect_failed (code と Foundation の固定文) / connected / approved / denied / cancelled。入力値は記録されない。',
    '4. 確認: foundation credentials   (各認証情報の id、サービス、渡す変数 variables が分かる)',
    '5. 実行: foundation exec <credential-id> [<credential-id> ...] -- <コマンド> [引数...]',
    '   複数の認証情報を同時に渡せる (例: Expo と Apple で eas build)。同じ変数名を 2 つが使う場合は実行しない。',
    '   子プロセスにだけ、各認証情報の variables と FOUNDATION_CREDENTIAL_IDS が入る。ファイルで渡すもの (.p8 など) は実行中だけ存在し、終了時に消える。exec の外では認証情報に触れない。', '',
    '道具: ファイル置き場 (使ってもよいし、使わなくてもよい。Foundation のどの手順もこれを前提にしない)',
    '   foundation put <ファイル> [--type <Content-Type>] [--minutes <分>]   ファイルを置き、期限付きの読み取り URL (url) を得る。5MB まで、7 日で消える。',
    '   URL を知っていれば誰でもそのファイル 1 つを読める (書き換え・一覧はできない)。置いたファイルは変更できない。変えるなら別に置く。',
    '   URL は S3 の署名付き URL なので、S3 の URL を求める先 (例: CloudFormation の quickcreate?templateURL=) にも渡せる。',
    '   foundation files で一覧、foundation link <file-id> [--minutes <分>] で URL を出し直す (既定 60 分、最大 10080 分)。秘密の値は置かない。', '',
    '守ること',
    '- 認証情報の値を出力・ログ・ファイルに書かない。exec 経由でコマンドに渡すだけにする。',
    '- 依頼は必要最小限にする。作業に要らないサービスを求めない。',
    '- 依頼元の名前 (--name) と用途は正直に書く。利用者はそれを見て判断する。',
    '- 承認待ちの依頼は 1 件まで。内容を変えるときは foundation cancel してから作り直す。connect を連投しない。',
    '- 拒否された、または期限切れになった場合は、理由を推測せず利用者に確認する。',
    '- 受け取った認証情報は、その作業でだけ使う。', '',
    'その他のコマンド: foundation adapters | credentials | files | request | cancel | whoami | rename <名前> | leave (自分のキーを失効させる)',
    '環境変数: FOUNDATION_URL (必須)、FOUNDATION_AGENT (任意。この AI の名前。例: claude / codex)、FOUNDATION_RUNTIME_KEY_FILE (任意)',
    'キーの単位: 既定は「機械 × OS ユーザー」で 1 つ。FOUNDATION_AGENT を設定すると AI ごとに別のキーになるが、同じ OS ユーザーで動く他の AI はそのファイルを読めるので、これは帳簿上の区別であり守りではない。本当に分離したいなら OS ユーザーを分ける。',
  ].join('\n');
}
