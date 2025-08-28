function parseRuleString(ruleString) {
  const headerMatch = ruleString.match(/^(.*?)\s*\(/);
  const optionsMatch = ruleString.match(/\((.*)\)\s*$/);
  if (!headerMatch || !optionsMatch) return null;
  const header = headerMatch[1].trim();
  const optionsRaw = optionsMatch[1];
  const options = optionsRaw
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


function parseSingleRule(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  const parsed = parseRuleString(trimmed);
  if (!parsed) return null;

  const parts = parsed.header.split(/\s+/);
  if (parts.length < 7) return null;
  const [Action, Protocol, srcIp, srcPort, Direction, dstIp, dstPort] = parts;

  const ruleOptions = [];
  let lastContent = null;
  for (const item of parsed.options) {
    if (item.keyword === 'content') {
      const contentMatch = item.value.match(/^\"([\s\S]*?)\"(.*)$/);
      let contentValue = '';
      let rest = '';
      if (contentMatch) {
        contentValue = contentMatch[1];
        rest = contentMatch[2] || '';
      } else {
        contentValue = item.value.replace(/^\"|\"$/g, '');
      }
      const modifiers = {};
      const parts = rest.split(/\s+/).filter(Boolean);
      for (const p of parts) {
        if (p === 'nocase') modifiers.nocase = true;
        const d = p.match(/^depth\s*:\s*(\d+)/);
        if (d) modifiers.depth = d[1];
        const o = p.match(/^offset\s*:\s*(\d+)/);
        if (o) modifiers.offset = o[1];
      }
      const contentObj = { keyword: 'content', value: contentValue, modifiers };
      ruleOptions.push(contentObj);
      lastContent = contentObj;
      continue;
    }
    if (lastContent && item.keyword === 'nocase') { lastContent.modifiers.nocase = true; continue; }
    if (lastContent && item.keyword === 'depth') { const m = String(item.value).match(/^(\d+)/); if (m) lastContent.modifiers.depth = m[1]; continue; }
    if (lastContent && item.keyword === 'offset') { const m = String(item.value).match(/^(\d+)/); if (m) lastContent.modifiers.offset = m[1]; continue; }

    if (item.value === '') ruleOptions.push({ keyword: item.keyword, value: true });
    else ruleOptions.push({ keyword: item.keyword, value: item.value.replace(/^\"|\"$/g, '') });
    lastContent = null;
  }

  return {
    headerData: {
      'Action': Action,
      'Protocol': Protocol,
      'Source IP': srcIp,
      'Source Port': srcPort,
      'Direction': Direction,
      'Destination IP': dstIp,
      'Destination Port': dstPort,
    },
    ruleOptions,
  };
}

function parseFileToSpecs(content) {
  const lines = content.split(/\r?\n/);
  const rules = [];
  for (const line of lines) {
    const r = parseSingleRule(line);
    if (r) rules.push(r);
  }
  return rules;
}

module.exports = { parseRuleString, parseSingleRule, parseFileToSpecs };


