// src/utils/ruleGenerator.js

import { optionsDictionary, formatModifiersForDisplay } from "../data/optionsDictionary";

// YENİ: ASCII metni Suricata'nın anlayacağı hex formatına çevirir
const asciiToHex = (str) => {
    if (!str) return '||';
    const hex = Array.from(str)
        .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ');
    return `|${hex}|`;
};

export const generateRuleString = (headerData, ruleOptions) => {
    const headerParts = [
        headerData.Action,
        headerData.Protocol,
        headerData['Source IP'],
        headerData['Source Port'],
        headerData.Direction,
        headerData['Destination IP'],
        headerData['Destination Port']
    ];

    const headerString = headerParts.filter(part => part && part.trim() !== '').join(' ');

    const optionsString = ruleOptions.map(option => {
        const optionInfo = optionsDictionary[option.keyword];
        if (!optionInfo) return '';

        // DEĞİŞİKLİK: content seçeneği için özel formatlama mantığı
        if (option.keyword === 'content') {
            let valuePart;
            const isAlreadyHex = /^\|.*\|$/.test(option.value);

            if (option.format === 'hex') {
                valuePart = isAlreadyHex ? option.value : asciiToHex(option.value);
            } else { // 'ascii'
                // ASCII formatta, metin içindeki tırnak işaretlerinden kaçınıyoruz
                const escapedValue = option.value.replace(/"/g, '\\"');
                valuePart = `"${escapedValue}"`;
            }

            const modifiersPart = formatModifiersForDisplay(option.modifiers);
            return `${option.keyword}:${valuePart}${modifiersPart}`;
        }
        
        if (optionInfo.category === 'flag') {
            return option.keyword;
        }

        if (option.value || String(option.value).trim() !== '') {
            // content dışındaki diğer tüm keyword'ler için standart formatlama
            const formattedValue = optionInfo.format(option.value, option.modifiers);
            return `${option.keyword}:${formattedValue}`;
        }

        return '';
    }).filter(part => part).join('; ');

    return `${headerString} (${optionsString};)`;
};