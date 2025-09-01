const { ORDER, orderOptions } = require('../utils/canonicalOrder');
const { parseRuleString, parseFileToSpecs } = require('../utils/parse');
const { validate } = require('../utils/validate');
const { allocateNextSid, getStoredRevForSid, setStoredRevForSid } = require('../utils/store');

function validateRule(rule) {
  return validate(rule);
}

function canonicalFormat(rule) {
  const parsed = parseRuleString(rule);
  if (!parsed) return null;

  // order options deterministically
  const ordered = orderOptions(parsed.options);

  // SID/REV discipline
  const sidOpt = ordered.find(o => o.keyword === 'sid');
  const revOpt = ordered.find(o => o.keyword === 'rev');
  if (sidOpt) {
    const sidNumber = Number(String(sidOpt.value).replace(/;$/, ''));
    const stored = getStoredRevForSid(sidNumber);
    if (Number.isFinite(sidNumber)) {
      if (stored > 0) {
        const nextRev = Math.max(stored + 1, (revOpt ? Number(revOpt.value) + 1 : stored + 1));
        if (revOpt) revOpt.value = String(nextRev);
        else ordered.push({ keyword: 'rev', value: String(nextRev) });
        setStoredRevForSid(sidNumber, nextRev);
      } else if (revOpt && Number.isFinite(Number(revOpt.value))) {
        setStoredRevForSid(sidNumber, Number(revOpt.value));
      }
    }
  }

  const optionsText = ordered
    .map(o => (o.value !== '' && o.value != null ? `${o.keyword}: ${o.value}` : o.keyword))
    .join('; ');
  return `${parsed.header} (${optionsText};)`;
}


function allocateSid() {
  const sid = allocateNextSid();
  return { sid };
}

function parse(fileText) {
  return parseFileToSpecs(fileText);
}

module.exports = {
  validate: validateRule,
  canonicalFormat,
  allocateSid,
  parse,
};


