const HTTP_ONLY = new Set([
  'http_uri', 'http_header', 'http_client_body', 'http_server_body',
  'http_method', 'http_cookie', 'http_host', 'http_user_agent'
]);

function parse(rule) {
  const headerMatch = rule.match(/^(.*?)\s*\(/);
  const optionsMatch = rule.match(/\((.*)\)\s*$/);
  if (!headerMatch || !optionsMatch) return null;
  const header = headerMatch[1].trim();
  const options = optionsMatch[1]
    .split(';')
    .map(s => s.trim())
    .filter(Boolean)
    .map(opt => {
      const idx = opt.indexOf(':');
      if (idx === -1) return { keyword: opt, value: '' };
      return { keyword: opt.slice(0, idx).trim(), value: opt.slice(idx + 1).trim() };
    });
  return { header, options };
}
function parsereader(reader){
  const p=reader.split(/\s+/);
  if (reader.length<8){
    return 
  }
}

function parseHeader(header) {
  const p = header.split(/\s+/);
  if (p.length < 7) return null;
  return { action: p[0], protocol: p[1], srcIp: p[2], srcPort: p[3], direction: p[4], dstIp: p[5], dstPort: p[6] };
}

function validate(rule) {
  const errors = [];
  const parsed = parse(rule);
  if (!parsed) return { errors: ['Kural biçimi geçersiz. Parantezli options bekleniyor.'] };

  const header = parseHeader(parsed.header);
  if (!header) errors.push('Header biçimi geçersiz. 7 parça bekleniyor: action protocol src_ip src_port dir dst_ip dst_port');

  const keywords = parsed.options.map(o => o.keyword);
  if (!keywords.includes('msg')) errors.push('msg zorunludur.');
  if (!keywords.includes('sid')) errors.push('sid zorunludur.');

  // rev must be after sid
  const sidIdx = keywords.indexOf('sid');
  const revIdx = keywords.indexOf('rev');
  if (sidIdx !== -1 && revIdx !== -1 && revIdx < sidIdx) errors.push('rev, sid sonrasında gelmelidir (canonical order).');

  // protocol-specific http buffers
  const protocol = header?.protocol?.toLowerCase();
  if (protocol && protocol !== 'http') {
    for (const kw of keywords) {
      if (HTTP_ONLY.has(kw)) errors.push(`${kw} sadece HTTP protokolünde kullanılabilir.`);
    
    }
  }

  const fastPatternCount = keywords.filter(k => k === 'fast_pattern').length;
  if (fastPatternCount > 1) errors.push('fast_pattern en fazla bir kez kullanılabilir.');

  return { errors };
}

module.exports = { validate };


