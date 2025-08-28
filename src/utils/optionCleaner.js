// src/utils/optionCleaner.js

import { optionsDictionary } from '../data/optionsDictionary';
import { toast } from 'react-toastify';

export const cleanOptionsForProtocol = (options, oldProtocol, newProtocol) => {
    // Protokol değişmediyse veya yeni protokol boşsa işlem yapma
    if (oldProtocol === newProtocol || !newProtocol) {
        return options;
    }

    const originalCount = options.length;
    
    const cleanedOptions = options.filter(option => {
        const optionInfo = optionsDictionary[option.keyword];
        // Seçeneğin bir protokol bağımlılığı yoksa, koru
        if (!optionInfo?.dependsOnProtocol) {
            return true;
        }
        // Bağımlılığı varsa ve yeni protokolle eşleşiyorsa, koru
        return optionInfo.dependsOnProtocol === newProtocol.toLowerCase();
    });

    const removedCount = originalCount - cleanedOptions.length;

    // Eğer seçenek kaldırıldıysa kullanıcıyı bilgilendir
    if (removedCount > 0) {
        toast.warn(`${removedCount} adet seçenek, yeni protokolle uyumsuz olduğu için kaldırıldı.`);
    }

    return cleanedOptions;
};