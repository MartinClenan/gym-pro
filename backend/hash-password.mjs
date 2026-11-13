import { pbkdf2Sync, randomBytes } from 'node:crypto';

const PBKDF2_ITERATIONS = 310_000;
const username = (process.argv[2] || '').trim().toLowerCase();
const initials = (process.argv[3] || username.slice(0, 2)).trim().toUpperCase();

if (!/^[a-z0-9._-]{2,40}$/.test(username)) {
  console.error('Uso: node backend/hash-password.mjs usuario iniciales');
  process.exit(1);
}

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    if (!input.isTTY || typeof input.setRawMode !== 'function') {
      reject(new Error('Ejecutá este comando en una terminal interactiva.'));
      return;
    }
    let value = '';
    process.stdout.write(prompt);
    input.setEncoding('utf8');
    input.setRawMode(true);
    input.resume();
    const finish = (result, error) => {
      input.setRawMode(false);
      input.pause();
      input.removeListener('data', onData);
      process.stdout.write('\n');
      if (error) reject(error);
      else resolve(result);
    };
    const onData = (chunk) => {
      for (const char of chunk) {
        if (char === '\u0003') return finish('', new Error('Operación cancelada.'));
        if (char === '\r' || char === '\n') return finish(value);
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else value += char;
      }
    };
    input.on('data', onData);
  });
}

try {
  const password = await readHidden('Contraseña nueva (mínimo 12 caracteres): ');
  if (password.length < 12) throw new Error('La contraseña debe tener al menos 12 caracteres.');
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const record = {
    [username]: {
      salt: salt.toString('base64url'),
      hash: hash.toString('base64url'),
      rol: 'admin',
      iniciales: initials.slice(0, 4),
    },
  };
  process.stdout.write(JSON.stringify(record) + '\n');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
