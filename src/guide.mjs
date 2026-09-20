// Printed by `foundation --help`. Written for an AI agent that has just been
// told to use an external service and needs the whole procedure in one read.
const EXAMPLES = {
  expo: 'foundation connect --provider expo --purpose "<用途>"',
  openrouter: 'foundation connect --provider openrouter --purpose "<用途>"',
  gmail: 'foundation connect --provider gmail --mode metadata --purpose "<用途>"   (mode: readonly | metadata)',
  apikey: 'foundation connect --service <サービス名> --site <https://キー作成ページ> --env <環境変数名> --purpose "<用途>"',
};

export function guide(providers) {
  const lines = [];
  const available = providers ? providers.filter(provider => provider.available) : null;
  const unavailable = providers ? providers.filter(provider => !provider.available) : [];
  lines.push('Foundation: 外部サービスの認証情報を、利用者の承認を経てコマンドの環境変数に渡す仕組み。',
    '利用者にキーやトークンをチャットへ貼らせてはいけない。必ず Foundation を通す。', '');
  lines.push('手順');
  lines.push('1. 接続依頼を作る。用途は利用者が読んで判断できる具体的な 1 文にする。');
  const ids = available ? available.map(provider => provider.id) : Object.keys(EXAMPLES);
  for (const id of ids) if (EXAMPLES[id]) lines.push('   ' + EXAMPLES[id]);
  if (ids.includes('apikey')) lines.push('   例: foundation connect --service Anthropic --site https://console.anthropic.com/settings/keys --env ANTHROPIC_API_KEY --purpose "Claude API で要約を生成する"');
  lines.push('2. 出力の verification_uri と confirmation_code を、そのまま利用者に伝える。',
    '   利用者はブラウザで URL を開き、必要ならサービス側でキーを作って登録し、コードを入力して許可する。',
    '   コードは利用者が手で打つので必ず表示する。',
    '3. 承認を待つ: foundation wait --timeout 1800',
    '4. 接続先を確認: foundation accounts   (account id と token_env が分かる)',
    '5. 実行: foundation exec <account-id> -- <コマンド> [引数...]',
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
  lines.push('その他のコマンド: foundation providers | status | cancel | accounts',
    '環境変数: FOUNDATION_URL (必須)、FOUNDATION_RUNTIME_KEY_FILE (任意。既定は ~/.local/state/foundation/ 配下に自動生成)');
  if (providers) {
    lines.push('', '現在のサーバーで使えるサービス: ' + (available.length ? available.map(provider => provider.id + ' (' + provider.name + ')').join(', ') : 'なし'));
    if (unavailable.length) lines.push('現在使えないサービス: ' + unavailable.map(provider => provider.id).join(', '));
  }
  return lines.join('\n');
}
