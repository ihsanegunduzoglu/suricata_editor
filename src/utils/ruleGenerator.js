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

    const headerString = headerParts.filter(part => part !== '').join(' ');

    const optionsString = ruleOptions.map(option => {
        const optionInfo = optionsDictionary[option.keyword];
        let optionStr = '';

        if (optionInfo) {
            // "Değersiz (Flag)" tipindeki keyword'ler için özel kontrol
            if (optionInfo.category === 'flag') {
                return option.keyword;
            }
            // Değiştiricisi olan 'content' gibi keyword'ler için özel kontrol
            if (optionInfo.category === 'modifier_host' && option.modifiers) {
                 const formattedValue = optionInfo.format(option.value, option.modifiers);
                 return `${option.keyword}:${formattedValue}`;
            }
            // Diğer tüm standart "keyword:değer" formatındaki seçenekler
            const formattedValue = optionInfo.format(option.value);
            return `${option.keyword}:${formattedValue}`;
        }
        return optionStr;
    }).join('; ');

    return `${headerString} (${optionsString};)`;
};