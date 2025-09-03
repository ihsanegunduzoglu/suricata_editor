// src/utils/ruleValidator.js
import suggestionsData from '../data/suggestionsData';
import { optionsDictionary } from '../data/optionsDictionary';

/**
 * Belirli bir başlık alanının geçerliliğini kontrol eder (Anlık uyarılar için).
 * ARTIK IP ADRESLERİ İÇİN DAHA ESNEK.
 */
export const validateHeaderField = (fieldName, value) => {
    if (!value || value.trim() === '') return null;

    // IP Adresi alanları için özel, daha esnek bir kontrol
    if (fieldName.toLowerCase().includes('ip')) {
        // Genel geçerli ifadelere (any, değişkenler, negasyon) izin ver
        const isCommonValid = value.toLowerCase() === 'any' || value.startsWith('$') || value.startsWith('!');
        if (isCommonValid) return null;

        // Basit bir IP adresi veya CIDR formatı regex'i
        const ipRegex = /^((\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?)$/;
        if (ipRegex.test(value)) {
            return null; // Eğer format doğruysa, hata verme
        }
        
        // Eğer hiçbirine uymuyorsa, uyarı ver ama engelleme
        return `Geçersiz IP formatı: "${value}". Örnek: 8.8.8.8 veya 192.168.1.0/24`;
    }

    // Diğer alanlar için eski basit kontrol devam edebilir
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
 * Belirli bir kural seçeneğinin değerinin formatını kontrol eder.
 */
export const validateOptionField = (keyword, value) => {
    if (!value || String(value).trim() === '') {
        const cannotBeEmpty = ['sid', 'rev', 'priority', 'classtype', 'content', 'pcre', 'http.method'];
        if (cannotBeEmpty.includes(keyword)) {
            return `"${keyword}" seçeneği için bir değer girilmelidir.`;
        }
        return null; 
    }

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
 */
export const validateRuleForFinalization = (headerData, ruleOptions) => {
    const isHeaderComplete = Object.values(headerData).every(val => val && val.trim() !== '');
    if (!isHeaderComplete) {
        return 'Kural kaydedilemedi! Lütfen önce tüm başlık alanlarını doldurun.';
    }

    for (const fieldName in headerData) {
        const value = headerData[fieldName];
        // Buradaki kontrol artık daha esnek olduğu için sorun çıkarmayacak
        const fieldValidationError = validateHeaderField(fieldName, value);
        if (fieldValidationError) {
            return `Kural kaydedilemedi! ${fieldValidationError}`;
        }
    }

    for (const option of ruleOptions) {
        const optionValidationError = validateOptionField(option.keyword, option.value);
        if (optionValidationError) {
            return `Kural kaydedilemedi! ${optionValidationError}`;
        }
    }

    const msgOption = ruleOptions.find(o => o.keyword === 'msg');
    if (!msgOption) {
        return 'Kural kaydedilemedi! "msg" seçeneği zorunludur.';
    }

    const sidOption = ruleOptions.find(o => o.keyword === 'sid');
    if (!sidOption) {
        return 'Kural kaydedilemedi! "sid" seçeneği zorunludur.';
    }
    
    return null;
};