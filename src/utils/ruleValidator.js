// src/utils/ruleValidator.js
import suggestionsData from '../data/suggestionsData';
import { optionsDictionary } from '../data/optionsDictionary';

/**
 * Belirli bir başlık alanının geçerliliğini kontrol eder (Anlık uyarılar için).
 */
export const validateHeaderField = (fieldName, value) => {
    if (!value || value.trim() === '') return null;
    if (value.startsWith('$') || value.toLowerCase() === 'any') {
        return null;
    }
    const validValues = suggestionsData[fieldName];
    if (validValues && !validValues.includes(value.toLowerCase())) {
        return `Geçersiz ${fieldName}: "${value}". Önerilen değerlerden birini kullanın.`;
    }
    return null;
};

/**
 * Belirli bir kural seçeneğinin değerinin formatını kontrol eder (Anlık uyarılar için).
 */
export const validateOptionField = (keyword, value) => {
    if (!value) return null;
    switch (keyword) {
        case 'sid':
        case 'rev':
        case 'priority':
            if (isNaN(parseInt(value, 10))) {
                return `"${keyword}" değeri bir sayı olmalıdır.`;
            }
            break;
        case 'classtype':
            const isValidClasstype = optionsDictionary.classtype.suggestions.some(s => s.name === value);
            if (!isValidClasstype) {
                return `Geçersiz classtype: "${value}".`;
            }
            break;
        default:
            return null;
    }
    return null;
};

/**
 * Kuralı kaydetmeden önce son ve kapsamlı bir kontrol yapar.
 * @returns {string|null} - İlk bulunan kritik hata mesajını veya null döndürür.
 */
export const validateRuleForFinalization = (headerData, ruleOptions) => {
    const isHeaderComplete = Object.values(headerData).every(val => val && val.trim() !== '');
    if (!isHeaderComplete) {
        return 'Kural kaydedilemedi! Lütfen önce tüm başlık alanlarını doldurun.';
    }
    const msgOption = ruleOptions.find(o => o.keyword === 'msg');
    if (!msgOption || !msgOption.value || msgOption.value.trim() === '') {
        return 'Kural kaydedilemedi! "msg" seçeneği zorunludur ve boş bırakılamaz.';
    }
    const sidOption = ruleOptions.find(o => o.keyword === 'sid');
    if (!sidOption || !sidOption.value) {
        return 'Kural kaydedilemedi! "sid" seçeneği zorunludur ve boş bırakılamaz.';
    }
    if (isNaN(parseInt(sidOption.value, 10))) {
        return `Kural kaydedilemedi! "sid" değeri geçerli bir sayı olmalıdır.`;
    }
    return null;
};