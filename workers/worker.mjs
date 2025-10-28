export default {
    async fetch(req, env) {
      const url = new URL(req.url);
      if (url.pathname === '/login')          return login(env);
      if (url.pathname === '/oauth/callback') return callback(req, env);
      if (url.pathname === '/api/unwrap')     return unwrap(req, env);

      // --- 댓글 API 추가 ---
      if (url.pathname === '/api/comments/add'  && req.method === 'POST') return addComment(req, env);
      if (url.pathname === '/api/comments/list' && req.method === 'GET')  return listComments(req, env);

      if (req.method === 'OPTIONS')           return new Response(null, { headers: preflight(env, req) });
      return new Response('ok', { headers: cors(env, req) });
    }
  };
  
  const te = new TextEncoder();
  const b64ToU8 = (b64)=>Uint8Array.from(atob(b64), c=>c.charCodeAt(0));
  const u8ToB64 = (u8)=>btoa(String.fromCharCode(...u8));
  
  function preflight(env, req){
    return {
      'Access-Control-Allow-Origin': env.PAGES_ORIGIN,
      'Vary':'Origin',
      'Access-Control-Allow-Credentials':'true',
      'Access-Control-Allow-Methods':'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers':'content-type'
    };
  }
  function cors(env, req){
    return {
      'Access-Control-Allow-Origin': env.PAGES_ORIGIN,
      'Vary':'Origin',
      'Access-Control-Allow-Credentials':'true',
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none';"
    };
  }
  
  async function signHmac(secretB64, data){
    const key = await crypto.subtle.importKey('raw', b64ToU8(secretB64), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, te.encode(data));
    return u8ToB64(new Uint8Array(sig));
  }
  
  async function decryptGcm(keyRaw, iv, aadStr, ctPlusTag){
    const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
    const pt  = await crypto.subtle.decrypt(
      { name:'AES-GCM', iv, additionalData: aadStr? te.encode(aadStr): undefined },
      key,
      ctPlusTag
    );
    return new Uint8Array(pt);
  }
  
  async function login(env){
    const u = new URL('https://kauth.kakao.com/oauth/authorize');
    u.searchParams.set('response_type','code');
    u.searchParams.set('client_id', env.KAKAO_CLIENT_ID);
    u.searchParams.set('redirect_uri', env.KAKAO_REDIRECT_URI);
    u.searchParams.set('scope','profile_nickname');
    return Response.redirect(u.toString(), 302);
  }
  
  async function callback(req, env){
    const url  = new URL(req.url);
    const code = url.searchParams.get('code');
  
    const token = await fetch('https://kauth.kakao.com/oauth/token', {
      method:'POST',
      headers:{'content-type':'application/x-www-form-urlencoded'},
      body: new URLSearchParams({
        grant_type:'authorization_code',
        client_id: env.KAKAO_CLIENT_ID,
        client_secret: env.KAKAO_CLIENT_SECRET,
        redirect_uri: env.KAKAO_REDIRECT_URI,
        code
      })
    }).then(r=>r.json());
  
    const me = await fetch('https://kapi.kakao.com/v2/user/me', {
      headers:{ Authorization:`Bearer ${token.access_token}` }
    }).then(r=>r.json());
  
    const allowed = String(env.ALLOWED_USER_IDS||'').split(',').map(s=>s.trim()).filter(Boolean);
    if (!allowed.includes(String(me.id))) {
      return new Response('Forbidden', { status:403, headers: cors(env, req) });
    }
  
    const exp = Math.floor(Date.now()/1000) + 3600;
    const payload = btoa(JSON.stringify({ sub:String(me.id), exp }));
    const mac = await signHmac(env.SESSION_SECRET_BASE64, payload);
    const cookie = `SESS=${payload}.${mac}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=3600`;
  
    return new Response(null, { status:302, headers: { 'Set-Cookie': cookie, 'Location': env.PAGES_ORIGIN, ...cors(env, req) }});
  }
  
  async function unwrap(req, env){
    if (req.method === 'OPTIONS') return new Response(null, { headers: preflight(env, req) });
    if (req.method !== 'POST')   return new Response('Method Not Allowed', { status:405, headers: cors(env, req) });
  
    const cookie = req.headers.get('cookie')||'';
    const m = /SESS=([^;]+)/.exec(cookie);
    if (!m) return new Response('Unauthorized', { status:401, headers: cors(env, req) });
    const [payload, mac] = m[1].split('.');
    if (await signHmac(env.SESSION_SECRET_BASE64, payload) !== mac) return new Response('Unauthorized', { status:401, headers: cors(env, req) });
    const { exp } = JSON.parse(atob(payload));
    if (Date.now()/1000 > exp) return new Response('Expired', { status:401, headers: cors(env, req) });
  
    const { postId, wrappedKey, aad } = await req.json();
    if (!postId || !wrappedKey?.iv || !wrappedKey?.tag || !wrappedKey?.ct) {
      return new Response('Bad Request', { status:400, headers: cors(env, req) });
    }
  
    const master   = b64ToU8(env.MASTER_KEY_BASE64);
    const iv       = b64ToU8(wrappedKey.iv);
    const tag      = b64ToU8(wrappedKey.tag);
    const ct       = b64ToU8(wrappedKey.ct);
    const combined = new Uint8Array(ct.length + tag.length);
    combined.set(ct,0); combined.set(tag, ct.length);
  
    const K_post = await decryptGcm(master, iv, aad, combined);
    return new Response(JSON.stringify({ key: u8ToB64(K_post) }), { headers:{ 'content-type':'application/json', ...cors(env, req) }});
  }

  
// ===== 댓글: 공통 유틸 =====
function requireSessionOr401(req, env) {
  const cookie = req.headers.get('cookie')||'';
  const m = /SESS=([^;]+)/.exec(cookie);
  if (!m) return { err: new Response('Unauthorized', { status:401, headers: cors(env, req) }) };
  return { token: m[1] };
}

async function verifySession(token, env, req) {
  const [payload, mac] = token.split('.');
  const expect = await signHmac(env.SESSION_SECRET_BASE64, payload);
  if (expect !== mac) return { err: new Response('Unauthorized', { status:401, headers: cors(env, req) }) };
  const obj = JSON.parse(atob(payload));
  if (Date.now()/1000 > obj.exp) return { err: new Response('Expired', { status:401, headers: cors(env, req) }) };
  return { session: obj }; // { sub: kakaoUserId, exp: ... }
}

async function gh(env, path, init={}) {
  const headers = init.headers || {};
  headers['Authorization'] = `Bearer ${env.GH_TOKEN}`;
  headers['Accept'] = 'application/vnd.github+json';
  headers['User-Agent'] = 'kakao-comments-worker';
  return fetch(`https://api.github.com${path}`, { ...init, headers });
}

async function ensureIssueForPost(env, postId) {
  // 1) 라벨로 이슈 찾기 (state=all 포함)
  const label = `post:${postId}`;
  const list = await gh(env, `/repos/${env.GH_OWNER}/${env.GH_REPO}/issues?labels=${encodeURIComponent(label)}&state=all&per_page=1`)
    .then(r=>r.json());
  if (Array.isArray(list) && list.length) return list[0].number;

  // 2) 없으면 생성
  const created = await gh(env, `/repos/${env.GH_OWNER}/${env.GH_REPO}/issues`, {
    method: 'POST',
    body: JSON.stringify({
      title: `Comments for post:${postId}`,
      labels: [label]
    })
  }).then(r=>r.json());
  return created.number;
}

// ===== 댓글: 작성 =====
async function addComment(req, env) {
  const sess = requireSessionOr401(req, env);
  if (sess.err) return sess.err;
  const ver = await verifySession(sess.token, env, req);
  if (ver.err) return ver.err;

  const { postId, content } = await req.json();
  if (!postId || !content || content.trim().length === 0) {
    return new Response('Bad Request', { status:400, headers: cors(env, req) });
  }

  // 포스트별 이슈 번호 확보
  const issueNumber = await ensureIssueForPost(env, postId);

  // 유저 표시는 최소한으로 (카카오 user id만). 원하면 세션에 닉네임을 추가 저장하도록 확장 가능.
  const userId = ver.session.sub;
  const body = `**user:${userId}**\n\n${content}`;

  await gh(env, `/repos/${env.GH_OWNER}/${env.GH_REPO}/issues/${issueNumber}/comments`, {
    method: 'POST',
    body: JSON.stringify({ body })
  });

  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'content-type':'application/json', ...cors(env, req) }
  });
}

// ===== 댓글: 목록 =====
async function listComments(req, env) {
  const sess = requireSessionOr401(req, env);
  if (sess.err) return sess.err;
  const ver = await verifySession(sess.token, env, req);
  if (ver.err) return ver.err;

  const url = new URL(req.url);
  const postId = url.searchParams.get('postId');
  if (!postId) return new Response('Bad Request', { status:400, headers: cors(env, req) });

  const issueNumber = await ensureIssueForPost(env, postId);

  const comments = await gh(env, `/repos/${env.GH_OWNER}/${env.GH_REPO}/issues/${issueNumber}/comments?per_page=50`)
    .then(r=>r.json());

  // 필요한 필드만 추출해서 프론트로 전달
  const items = comments.map(c => ({
    id: c.id,
    user: (c.body.match(/^\*\*user:(\d+)\*\*/) || [,'unknown'])[1],
    content: c.body.replace(/^\*\*user:\d+\*\*\s*\n+/,''),
    created_at: c.created_at
  }));

  return new Response(JSON.stringify({ items }), {
    headers: { 'content-type':'application/json', ...cors(env, req) }
  });
}