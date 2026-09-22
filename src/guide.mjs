// Printed by `foundation --help`. Written for an AI agent that has just been
// told to use an external service and needs the whole procedure in one read.
const EXAMPLES = {
  expo: 'foundation connect --provider expo --purpose "<用途>"',
  openrouter: 'foundation connect --provider openrouter --purpose "<用途>"',
  supabase: 'foundation connect --provider supabase --purpose "<用途>"   (Supabase CLI は SUPABASE_ACCESS_TOKEN を読む)',
  aws: 'foundation connect --provider aws --purpose "<用途>"   (ロールの一時認証情報を AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN / AWS_REGION で渡す。exec --duration <秒> で期間を要求できる。上限は AWS が決める)',
  apple: 'foundation connect --provider apple --purpose "<用途>"   (App Store Connect API キー。EAS 用に .p8 を EXPO_ASC_API_KEY_PATH のファイルで、ID 類を EXPO_ASC_* / EXPO_APPLE_* で渡す)',
  cloudflare: 'foundation connect --provider cloudflare --purpose "R2のバケット一覧を確認する。変更やデータ転送は行わない"   (CLOUDFLARE_API_TOKEN。accounts の cloudflare_account_id が対象)',
  gmail: 'foundation connect --provider gmail --mode metadata --purpose "<用途>"   (mode: readonly | metadata)',
  apikey: 'foundation connect --service <サービス名> --site <https://キー作成ページ> --env <環境変数名> --purpose "<用途>"',
};

export function guide(providers) {
  const lines = [];
  const available = providers ? providers.filter(provider => provider.available) : null;
  const unavailable = providers ? providers.filter(provider => !provider.available) : [];
  lines.push('Foundation: 外部サービスの認証情報を、利用者の承認を経てコマンドの環境変数に渡す仕組み。',
    '利用者にキーやトークンをチャットへ貼らせてはいけない。必ず Foundation を通す。', '',
    '自分の立場: あなたは Foundation 上で 1 つの「アクセスキー」の持ち主として扱われる。利用者がキーを 1 回承認すると、以後は許可された接続を使える。',
    '  foundation whoami   で自分のキーの名前と許可された接続を確認できる (未承認なら 401 not_approved)。',
    '  まず whoami か accounts を試し、必要な接続が既にあれば依頼を作らずに 5 へ進む。', '');
  lines.push('手順');
  lines.push('1. 接続依頼を作る。用途は利用者が読んで判断できる具体的な 1 文にする。');
  const ids = available ? available.map(provider => provider.id) : Object.keys(EXAMPLES);
  for (const id of ids) if (EXAMPLES[id]) lines.push('   ' + EXAMPLES[id]);
  if (ids.includes('apikey')) lines.push('   例: foundation connect --service Anthropic --site https://console.anthropic.com/settings/keys --env ANTHROPIC_API_KEY --purpose "Claude API で要約を生成する"');
  if (ids.includes('cloudflare')) lines.push('   Cloudflare はユーザーAPIトークン。R2のS3互換API用Access Key/Secret Keyではない。バケット一覧は公式APIの /accounts/<cloudflare_account_id>/r2/buckets (ページ送りは result_info.cursor) を使う。',
    '   Foundationはトークン全体の権限を狭めない。登録したアカウントと依頼された用途にだけ使う。');
  lines.push('   --guide "<案内>" に、利用者がアカウントを登録するときの手順を書く (2000 文字まで、改行可)。登録画面に「依頼元のAIからの案内」として出る。許可の画面には出ないので、確認コードや許可の押し方は書かなくてよい。',
    '   --valid <分> で依頼の有効期間を決める (既定 30、最大 1440)。他社の画面での作業が長くなりそうなら延ばす。',
    '   Foundation 自身は手順書を持たない。他社の画面の操作 (どこを押すか) は、その時点で自分で調べて書く。Foundation が知っている事実は次の通り:',
    '     AWS: 定義ファイルのスタックが IAM ユーザー・ロール・アクセスキーを作り、完了すると「出力」に CopyToFoundation が 1 つ出る。利用者はその 1 行を貼る。',
    '          Permissions はスタック作成時に選ぶ (ReadOnlyAccess / PowerUserAccess / AdministratorAccess)。IAM を含む作業には AdministratorAccess が要る。同名のスタックは作れない。',
    '     Apple: チームキーの .p8 と Key ID / Issuer ID / Team ID / チーム種別。EAS の署名準備には Admin の役割。ファイル選択でも貼り付けでも登録できる。',
    '     Cloudflare: ユーザー API トークン (Global API Key と R2 の S3 互換キーは不可) と アカウント ID。',
    '     Supabase: アカウントのアクセストークン (sbp_...)。Expo: アクセストークン (個人用または Robot)。汎用: 1 行のキー (検証なし)。',
    '   登録が失敗するときの、Foundation 側の理由 (foundation request の events の code で分かる):',
    '     invalid_credential = 形式が違う (AWS なら出力の値が途中で切れている、Apple なら .p8 が全部貼れていない、Supabase なら sbp_ で始まらない)。',
    '     reconnect_required = 接続先がその認証情報を受け付けなかった (無効・失効・取り違え)。 role_denied = AWS のロールを引き受けられない (信頼ポリシー、またはアカウント違い)。',
    '     already_connected = 同じ認証情報が登録済み。 invalid_account = 追加項目 (アカウント ID、Key ID など) の形式が違う。 confirmation_required / confirmation_locked = 確認コードの誤り (5 回で失効)。',
    '2. 出力の verification_uri と confirmation_code を、そのまま利用者に伝える。',
    '   利用者はブラウザで URL を開き、必要ならサービス側でキーを作って登録し、コードを入力して許可する。',
    '   コードは利用者が手で打つので必ず表示する。',
    '3. 利用者が承認するのを待つ。数秒おきに foundation accounts を試し、通ったら 4 へ。連打しない。',
    '   利用者が「できない」「どうすればいい」と言ったら foundation request を実行し、自分の依頼の内容と、承認ページで起きた出来事 (events) を読む。',
    '   events は時系列の生の記録: page_opened / page_viewed / connect_started / connect_failed (code と Foundation の固定文) / connected / approved / denied / cancelled。',
    '   入力値は記録されない。出来事を見て、その利用者がいる段階に合った案内を会話で行う。',
    '4. 接続先を確認: foundation accounts   (account id と token_env が分かる。キーが未承認なら 401 not_approved になる)',
    '5. 実行: foundation exec [--duration <秒>] <account-id> [<account-id> ...] -- <コマンド> [引数...]',
    '   複数の接続を同時に渡せる (例: Expo と Apple で eas build)。同じ変数名を 2 つの接続が使う場合は実行しない。',
    '   ファイルで渡す認証情報 (.p8 など) はコマンドの実行中だけ存在する一時ファイルで、終了時に消える。コピーして残さない。',
    '   子プロセスにだけ FOUNDATION_ACCESS_TOKEN と、token_env が示す変数 (EXPO_TOKEN、OPENROUTER_API_KEY、',
    '   GOOGLE_OAUTH_ACCESS_TOKEN、または --env で申告した名前) が入る。exec の外では認証情報に触れない。', '');
  lines.push('守ること',
    '- 認証情報の値を出力・ログ・ファイルに書かない。exec 経由でコマンドに渡すだけにする。',
    '- 依頼は必要最小限にする。作業に要らないサービスや権限を求めない。',
    '- 用途と依頼元の名前 (--name) は正直に書く。利用者はそれを見て許可を判断する。',
    '- 承認待ちの依頼は 1 件まで。内容を変えるときは foundation cancel してから作り直す。connect を連投しない。',
    '- 拒否された、または 30 分で期限切れになった場合は、理由を推測せず利用者に確認する。',
    '- --service で申告したキーは Foundation では検証されない。認証エラーになったら貼り間違いの可能性を利用者に伝える。',
    '- 受け取った認証情報は、その作業でだけ使う。', '');
  lines.push('その他のコマンド: foundation providers | request (自分の依頼と承認ページの出来事を読む) | cancel (承認待ちの依頼を取り下げる) | accounts | whoami | rename <名前> (自分のキーの名前を変える) | leave (自分のキーを失効させる)',
    '環境変数: FOUNDATION_URL (必須)、FOUNDATION_AGENT (任意。この AI の名前。例: claude / codex)、FOUNDATION_RUNTIME_KEY_FILE (任意)',
    'キーの単位: 既定は「機械 × OS ユーザー」で 1 つ。FOUNDATION_AGENT を設定すると AI ごとに別のキーになるが、同じ OS ユーザーで動く他の AI はそのファイルを読めるので、これは帳簿上の区別であり守りではない。',
    '  本当に分離したいなら OS ユーザーを分ける。');
  if (providers) {
    lines.push('', '現在のサーバーで使えるサービス: ' + (available.length ? available.map(provider => provider.id + ' (' + provider.name + ')').join(', ') : 'なし'));
    if (unavailable.length) lines.push('現在使えないサービス: ' + unavailable.map(provider => provider.id).join(', '));
  }
  return lines.join('\n');
}
