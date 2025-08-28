// src/utils/ruleGenerator.js

import { optionsDictionary } from "../data/optionsDictionary";

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
        if (!optionInfo) return null;

        if (optionInfo.category === 'flag') {
            return option.keyword;
        }
        
        if (option.value === undefined || option.value === null || String(option.value).trim() === '') {
            return null;
        }

        // Her seçeneğin kendi format fonksiyonunu kullanarak metnini oluştur
        const formattedValue = optionInfo.format(option);
        
        // ruleGenerator'ın ana görevi keyword ve değeri birleştirmektir.
        // format() fonksiyonu sadece değeri formatlar.
        return `${option.keyword}:${formattedValue}`;

    }).filter(part => part !== null).join('; ');

    return `${headerString} (${optionsString};)`;
};