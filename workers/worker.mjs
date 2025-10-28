export default {
    async fetch(req, env) {
      const url = new URL(req.url);
      if (url.pathname === '/login')          return login(env);
      if (url.pathname === '/oauth/callback') return callback(req, env);
      if (url.pathname === '/api/unwrap')     return unwrap(req, env);
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
  