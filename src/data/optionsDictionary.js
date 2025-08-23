// src/data/optionsDictionary.js

const formatModifiersForDisplay = (modifiers) => {
    if (!modifiers) return '';
    let str = '';
    if (modifiers.nocase) str += ' nocase';
    if (modifiers.depth && modifiers.depth !== '') str += ` depth:${modifiers.depth}`;
    if (modifiers.offset && modifiers.offset !== '') str += ` offset:${modifiers.offset}`;
    return str;
};

// --- YENİ KATEGORİ SİSTEMİ İLE GÜNCELLENMİŞ SÖZLÜK ---
const optionsDictionary = {
  // Kategori: Tekil ve Gerekli
  'msg': { 
    description: 'Kural mesaji', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val) => `"${val}"`,
    category: 'singular_required', // YENİ: Davranışsal kategori
    allowMultiple : false,
  },
  'sid': { 
    description: 'Kural ID', 
    inputType: 'number', 
    defaultValue: '', 
    format: (val) => val, 
    allowMultiple: false,
    category: 'singular_required' // YENİ: Davranışsal kategori
  },

  // Kategori: Basit Değer Alan
  'rev': { 
    description: 'Revizyon numarasi', 
    inputType: 'number', 
    defaultValue: '1', 
    format: (val) => val, 
    allowMultiple: false,
    category: 'simple_value' // YENİ: Davranışsal kategori
  },
  
  // Kategori: Sabit Seçenekli (Autocomplete)
  'flow': { 
    description: 'Baglanti durumu', 
    inputType: 'autocomplete', 
    suggestions: ['established', 'to_client', 'from_server', 'not_established', 'only_stream', 'no_stream'], 
    defaultValue: '', 
    format: (val) => val,
    category: 'fixed_option' // YENİ: Davranışsal kategori
  },
  
  // Kategori: Değiştirici Alan (Özel Arayüz Gerektiren)
  'content': { 
    description: 'Aranacak icerik', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val, mods) => `"${val}"${formatModifiersForDisplay(mods)}`,
    category: 'modifier_host' // YENİ: Davranışsal kategori
  },

  // YENİ: Flag kategorisi için bir temsilci ekliyoruz
  // Kategori: Değersiz (Flag)
  'http_uri': {
    description: 'HTTP URI icerisinde ara',
    inputType: 'flag', // YENİ: inputType'ı flag olarak belirledik
    defaultValue: true,
    format: () => '', // Değeri olmadığı için formatı boş
    category: 'flag', // YENİ: Davranışsal kategori
    dependsOnProtocol: 'http' // YENİ: Sadece http protokolünde geçerli olduğunu belirtiyoruz
  },

  // --- Değiştiriciler (Bunlar anahtar kelime değil, 'content'e bağlı) ---
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