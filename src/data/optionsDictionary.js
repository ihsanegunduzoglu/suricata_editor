// src/data/optionsDictionary.js

const formatModifiersForDisplay = (modifiers) => {
    if (!modifiers) return '';
    let str = '';
    if (modifiers.nocase) str += ' nocase';
    if (modifiers.depth && modifiers.depth !== '') str += ` depth:${modifiers.depth}`;
    if (modifiers.offset && modifiers.offset !== '') str += ` offset:${modifiers.offset}`;
    return str;
};

const optionsDictionary = {
  'msg': { description: 'Kural mesaji', inputType: 'text', defaultValue: '', format: (val) => `"${val}"` },
  'sid': { description: 'Kural ID', inputType: 'number', defaultValue: '', format: (val) => val, allowMultiple: false },
  'rev': { description: 'Revizyon numarasi', inputType: 'number', defaultValue: '1', format: (val) => val, allowMultiple: false },
  'flow': { description: 'Baglanti durumu', inputType: 'autocomplete', suggestions: ['established', 'to_client', 'from_server', 'not_established', 'only_stream', 'no_stream'], defaultValue: '', format: (val) => val },
  'content': { description: 'Aranacak icerik', inputType: 'text', defaultValue: '', format: (val, mods) => `"${val}"${formatModifiersForDisplay(mods)}` },
  'nocase': { description: 'Buyuk/kucuk harf duyarsiz arama', inputType: 'flag', defaultValue: false, isModifier: true, dependsOn: 'content' },
  'depth': { description: 'Aramanin baslayacagi byte sayisi', inputType: 'number', defaultValue: '', isModifier: true, dependsOn: 'content' },
  'offset': { description: 'Paket basindan itibaren aramanin baslayacagi ofset', inputType: 'number', defaultValue: '', isModifier: true, dependsOn: 'content' },
};

export { optionsDictionary, formatModifiersForDisplay };