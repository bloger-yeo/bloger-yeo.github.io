import fs from 'node:fs';
import dotenv from 'dotenv';
dotenv.config();
const { WORKER_ORIGIN, PAGES_ORIGIN } = process.env;
fs.writeFileSync('public/env.js', `window.ENV={WORKER_ORIGIN:"${WORKER_ORIGIN}",PAGES_ORIGIN:"${PAGES_ORIGIN}"};`);
console.log('generated public/env.js');
