const crypto = require('crypto');

function makeToken(mode, secret) {
  return crypto.createHmac('sha256', secret).update(mode).digest('hex').slice(0, 32);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const accessPassword = process.env.ACCESS_PASSWORD;
  const testPassword   = process.env.TEST_PASSWORD;
  const tokenSecret    = process.env.TOKEN_SECRET;

  if (!accessPassword || !testPassword || !tokenSecret) {
    return res.status(500).json({ error: 'Сервер не настроен' });
  }

  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Пароль не указан' });

  if (password === accessPassword) {
    return res.status(200).json({ mode: 'main', token: makeToken('main', tokenSecret) });
  }

  if (password === testPassword) {
    return res.status(200).json({ mode: 'test', token: makeToken('test', tokenSecret) });
  }

  return res.status(401).json({ error: 'Неверный пароль' });
};
