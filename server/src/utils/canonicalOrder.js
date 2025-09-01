// Canonical option order definition and helpers

const ORDER = [
  'msg',
  'sid',
  'rev',
  'flow',
  'content',
  'http_uri',
];

function orderOptions(options) {
  const buckets = new Map();
  for (const o of options) {
    const list = buckets.get(o.keyword) || [];
    list.push({ ...o });
    buckets.set(o.keyword, list);
  }

  const ordered = [];
  for (const key of ORDER) {
    const items = buckets.get(key);
    if (items) {
      for (const it of items) ordered.push(it);
      buckets.delete(key);
    }
  }



  const remaining = Array.from(buckets.keys()).sort();
  for (const key of remaining) {
    for (const it of buckets.get(key)) ordered.push(it);
  }
  return ordered;
}

module.exports = { ORDER, orderOptions };


