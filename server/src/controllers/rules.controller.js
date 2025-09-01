const RulesService = require('../services/rules.service');

async function validateRule(req, res) {
  const { rule } = req.body || {};
  if (typeof rule !== 'string' || !rule.trim()) {
    return res.status(400).json({ errors: ['rule alanı zorunlu ve string olmalıdır.'] });
  }
  const result = RulesService.validate(rule);
  return res.json(result);
}


async function formatRule(req, res) {
  const { rule } = req.body || {};
  if (typeof rule !== 'string' || !rule.trim()) {
    return res.status(400).json({ error: 'rule alanı zorunlu ve string olmalıdır.' });
  }
  const formatted = RulesService.canonicalFormat(rule);
  if (!formatted) return res.status(400).json({ error: 'Kural biçimi geçersiz.' });
  return res.json({ rule: formatted });
}


async function getNextSid(_req, res) {
  const { sid } = RulesService.allocateSid();
  res.json({ sid });
}


async function parseRulesFile(req, res) {
  if (!req.file || !req.file.buffer) {
    return res.status(400).json({ error: 'file alanı zorunlu (multipart/form-data, field name: file)' });
  }
  const text = req.file.buffer.toString('utf8');
  const rules = RulesService.parse(text);
  res.json({ rules });
}

module.exports = {
  validateRule,
  formatRule,
  getNextSid,
  parseRulesFile,
};


