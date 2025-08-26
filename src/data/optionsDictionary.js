// src/data/optionsDictionary.js

const formatModifiersForDisplay = (modifiers) => {
    if (!modifiers) return '';
    const parts = [];
    if (modifiers.nocase) parts.push('nocase');
    if (modifiers.depth && modifiers.depth !== '') parts.push(`depth:${modifiers.depth}`);
    if (modifiers.offset && modifiers.offset !== '') parts.push(`offset:${modifiers.offset}`);
    return parts.length > 0 ? '; ' + parts.join('; ') : '';
};

const optionsDictionary = {
  'msg': { 
    description: 'Kural mesajı', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val) => `"${val}"`,
    category: 'singular_required',
    allowMultiple: false,
  },
  'sid': { 
    description: 'Kural ID', 
    inputType: 'number', 
    defaultValue: '', 
    format: (val) => val, 
    allowMultiple: false,
    category: 'singular_required'
  },
  'rev': { 
    description: 'Revizyon numarası', 
    inputType: 'number', 
    defaultValue: '1', 
    format: (val) => val, 
    allowMultiple: false,
    category: 'simple_value'
  },
  'classtype': {
    description: 'Saldırı sınıflandırması',
    inputType: 'autocomplete',
    defaultValue: '',
    format: (val) => val,
    allowMultiple: false,
    category: 'classification',
    suggestions: [
        { name: 'trojan-activity', description: 'Trojan aktivitesi tespiti' },
        { name: 'web-application-attack', description: 'Web uygulaması saldırısı' },
        { name: 'successful-user', description: 'Başarılı kullanıcı girişi' },
        { name: 'attempted-user', description: 'Başarısız kullanıcı denemesi' },
        { name: 'attempted-dos', description: 'Hizmet aksatma saldırı denemesi' },
        { name: 'policy-violation', description: 'Politika ihlali' },
        { name: 'malware-cnc', description: 'Zararlı yazılım komuta-kontrol iletişimi' },
    ]
  },
  'reference': {
    description: 'Dış kaynak referansı (CVE vb.)',
    inputType: 'text',
    defaultValue: '',
    format: (val) => val,
    category: 'metadata',
    allowMultiple: true,
  },
  'metadata': {
    description: 'Key-value formatında meta veri',
    inputType: 'text',
    defaultValue: '',
    format: (val) => val,
    category: 'metadata',
    allowMultiple: true,
  },
  'priority': {
    description: 'Uyarı öncelik seviyesi (1-255)',
    inputType: 'number',
    defaultValue: '',
    format: (val) => val,
    allowMultiple: false,
    category: 'metadata',
  },
  'flow': { 
    description: 'Bağlantı durumu', 
    inputType: 'autocomplete', 
    defaultValue: '', 
    format: (val) => val,
    category: 'fixed_option',
    suggestions: [
        { name: 'established', description: 'Kurulmuş TCP bağlantıları' },
        { name: 'not_established', description: 'Henüz kurulmamış TCP bağlantıları' },
        { name: 'stateless', description: 'Bağlantı takibinden bağımsız' },
        { name: 'to_client', description: 'Sunucudan istemciye giden trafik' },
        { name: 'to_server', description: 'İstemciden sunucuya giden trafik' },
        { name: 'from_client', description: 'İstemciden giden trafik (aynı)' },
        { name: 'from_server', description: 'Sunucudan giden trafik (aynı)' },
        { name: 'established,to_server', description: 'Kurulmuş bağlantıda istemciden sunucuya' },
        { name: 'established,to_client', description: 'Kurulmuş bağlantıda sunucudan istemciye' },
    ], 
  },
  'content': { 
    description: 'Aranacak içerik', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val, mods) => `"${val}"${formatModifiersForDisplay(mods)}`,
    category: 'modifier_host'
  },
  'pcre': {
    description: 'Perl Uyumlu Regex ile arama',
    inputType: 'text',
    defaultValue: '',
    format: (val) => `/${val}/`,
    category: 'payload'
  },
  'http.method': {
    description: 'HTTP metodunu kontrol et',
    inputType: 'text',
    defaultValue: '',
    format: (val) => `"${val}"`,
    dependsOnProtocol: 'http',
    category: 'http',
  },
  'http_uri': {
    description: 'HTTP URI içerisinde ara',
    inputType: 'flag',
    defaultValue: true,
    format: () => '', 
    category: 'flag',
    dependsOnProtocol: 'http'
  },
  'nocase': { 
    description: 'Büyük/küçük harf duyarsız arama', 
    inputType: 'flag', 
    defaultValue: false, 
    isModifier: true, 
    dependsOn: 'content' 
  },
  'depth': { 
    description: 'Aramanın başlayacağı byte sayısı', 
    inputType: 'number', 
    defaultValue: '', 
    isModifier: true, 
    dependsOn: 'content' 
  },
  'offset': { 
    description: 'Paket başından itibaren aramanın başlayacağı ofset', 
    inputType: 'number', 
    defaultValue: '', 
    isModifier: true, 
    dependsOn: 'content' 
  },
};

export { optionsDictionary, formatModifiersForDisplay };