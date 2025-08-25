// src/data/optionsDictionary.js

// DEĞİŞTİRİLDİ: Bu fonksiyon artık her bir değiştiriciden sonra noktalı virgül ekliyor.
const formatModifiersForDisplay = (modifiers) => {
    if (!modifiers) return '';
    
    const parts = [];
    if (modifiers.nocase) {
        parts.push('nocase');
    }
    if (modifiers.depth && modifiers.depth !== '') {
        parts.push(`depth:${modifiers.depth}`);
    }
    if (modifiers.offset && modifiers.offset !== '') {
        parts.push(`offset:${modifiers.offset}`);
    }

    // Eğer eklenecek parça varsa, başlarına ve aralarına '; ' koyarak birleştir.
    return parts.length > 0 ? '; ' + parts.join('; ') : '';
};

const optionsDictionary = {
  'msg': { 
    description: 'Kural mesaji', 
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
    description: 'Revizyon numarasi', 
    inputType: 'number', 
    defaultValue: '1', 
    format: (val) => val, 
    allowMultiple: false,
    category: 'simple_value'
  },
  'flow': { 
    description: 'Baglanti durumu', 
    inputType: 'autocomplete', 
    suggestions: ['established', 'to_client', 'from_server', 'not_established', 'only_stream', 'no_stream'], 
    defaultValue: '', 
    format: (val) => val,
    category: 'fixed_option'
  },
  'content': { 
    description: 'Aranacak icerik', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val, mods) => `"${val}"${formatModifiersForDisplay(mods)}`,
    category: 'modifier_host'
  },
  'http_uri': {
    description: 'HTTP URI icerisinde ara',
    inputType: 'flag',
    defaultValue: true,
    format: () => '', 
    category: 'flag',
    dependsOnProtocol: 'http'
  },
  'nocase': { 
    description: 'Buyuk/kucuk harf duyarsiz arama', 
    inputType: 'flag', 
    defaultValue: false, 
    isModifier: true, 
    dependsOn: 'content' 
  },
  'depth': { 
    description: 'Aramanin baslayacagi byte sayisi', 
    inputType: 'number', 
    defaultValue: '', 
    isModifier: true, 
    dependsOn: 'content' 
  },
  'offset': { 
    description: 'Paket basindan itibaren aramanin baslayacagi ofset', 
    inputType: 'number', 
    defaultValue: '', 
    isModifier: true, 
    dependsOn: 'content' 
  },
};

export { optionsDictionary, formatModifiersForDisplay };