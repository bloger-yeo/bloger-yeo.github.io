import { readdir, readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import { marked } from 'marked';

dotenv.config();
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_BASE64 || '', 'base64');
if (MASTER_KEY.length !== 32) { console.error('MASTER_KEY_BASE64 필요(32바이트 base64)'); process.exit(1); }

const POSTS_DIR = 'src/posts';
const OUT_DIR   = 'public/enc';

function parseFrontMatter(src) {
  if (!src.startsWith('---')) return { meta:{}, body: src };
  const end = src.indexOf('\n---', 3);
  if (end === -1) return { meta:{}, body: src };
  const yaml = src.slice(3, end).trim();
  const body = src.slice(end+4).trim();
  const meta = {};
  yaml.split(/\r?\n/).forEach(line=>{
    const m = /^(\w+)\s*:\s*(.*)$/.exec(line);
    if (m) meta[m[1]] = m[2];
  });
  return { meta, body };
}

function aesGcmEncrypt(key, plaintext, aadStr) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  if (aadStr) cipher.setAAD(Buffer.from(aadStr));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

async function encryptOne({ id, html, outDir }) {
  const aad   = `post:${id}`;
  const Kpost = crypto.randomBytes(32);
  const body  = aesGcmEncrypt(Kpost, Buffer.from(html), aad);
  const wrap  = aesGcmEncrypt(MASTER_KEY, Kpost, aad);

  const payload = {
    version: 1,
    postId: id,
    aad,
    iv: body.iv.toString('base64'),
    tag: body.tag.toString('base64'),
    ciphertext: body.ciphertext.toString('base64'),
    wrappedKey: {
      iv:  wrap.iv.toString('base64'),
      tag: wrap.tag.toString('base64'),
      ct:  wrap.ciphertext.toString('base64')
    }
  };
  await mkdir(outDir, { recursive:true });
  await writeFile(path.join(outDir, `${id}.json`), JSON.stringify(payload));
  return { id };
}

async function main(){
  const files = await readdir(POSTS_DIR);
  const posts = [];
  for (const fn of files) {
    if (!/\.(md|html)$/i.test(fn)) continue;
    const raw         = await readFile(path.join(POSTS_DIR, fn), 'utf-8');
    const { meta, body } = parseFrontMatter(raw);
    const id          = meta.id || path.basename(fn).replace(/\.(md|html)$/i,'');
    const html        = /\.md$/i.test(fn) ? marked.parse(body) : body;
    await encryptOne({ id, html, outDir: OUT_DIR });
    posts.push({ id, title: meta.title || id });
  }
  await writeFile('public/index.json', JSON.stringify(posts, null, 2));
  console.log(`Encrypted ${posts.length} posts.`);
}
main().catch(e=>{ console.error(e); process.exit(1); });
