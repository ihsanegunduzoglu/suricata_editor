// src/utils/ruleValidator.js
import suggestionsData from '../data/suggestionsData';
import { optionsDictionary } from '../data/optionsDictionary';

/**
 * Belirli bir başlık alanının geçerliliğini kontrol eder (Anlık uyarılar için).
 */
export const validateHeaderField = (fieldName, value) => {
    if (!value || value.trim() === '') return null;
    const trimmed = value.trim();
    if (trimmed.startsWith('$') || trimmed.toLowerCase() === 'any') return null;

    const IPV4_PART = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)';
    const ipv4Regex = new RegExp(`^(?:${IPV4_PART}\\.){3}${IPV4_PART}$`);
    const ipv4CidrRegex = new RegExp(`^(?:${IPV4_PART}\\.){3}${IPV4_PART}\\/(?:3[0-2]|[12]?\\d)$`);
    const portRegex = /^([0-9]{1,5})$/;
    const portRangeRegex = /^([0-9]{1,5}):([0-9]{1,5})$/;

    if (fieldName === 'Source IP' || fieldName === 'Destination IP') {
        if (ipv4Regex.test(trimmed) || ipv4CidrRegex.test(trimmed)) return null;
        return `Geçersiz ${fieldName}: "${value}". Geçerli bir IPv4 veya CIDR değeri giriniz.`;
    }

    if (fieldName === 'Source Port' || fieldName === 'Destination Port') {
        if (portRegex.test(trimmed)) {
            const p = Number(trimmed);
            if (p >= 0 && p <= 65535) return null;
        }
        const m = trimmed.match(portRangeRegex);
        if (m) {
            const p1 = Number(m[1]);
            const p2 = Number(m[2]);
            if (p1 >= 0 && p1 <= 65535 && p2 >= 0 && p2 <= 65535 && p1 <= p2) return null;
        }
        return `Geçersiz ${fieldName}: "${value}". Geçerli bir port veya port aralığı (örn: 80 ya da 1024:65535) giriniz.`;
    }

    const validValues = suggestionsData[fieldName];
    if (validValues && !validValues.includes(trimmed.toLowerCase())) {
        return `Geçersiz ${fieldName}: "${value}". Önerilen değerlerden birini kullanın.`;
    }
    return null;
};

/**
 * Belirli bir kural seçeneğinin değerinin formatını kontrol eder.
 * ARTIK BOŞ DEĞERLERİ DE KONTROL EDİYOR.
 */
export const validateOptionField = (keyword, value) => {
    // Boş veya sadece boşluk içeren değerleri kontrol et
    if (!value || String(value).trim() === '') {
        // Bu anahtar kelimeler eklendiğinde boş bırakılamaz
        const cannotBeEmpty = ['sid', 'rev', 'priority', 'classtype', 'content', 'pcre', 'http.method'];
        if (cannotBeEmpty.includes(keyword)) {
            return `"${keyword}" seçeneği için bir değer girilmelidir.`;
        }
        // Diğerleri (örn: reference, metadata) için boş değere izin verilebilir, bu yüzden null dönebiliriz.
        return null; 
    }

    // Formata özel kontroller
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
            return null; // Formatı kontrol edilmeyen diğer tüm seçenekler için
    }
    return null;
};

/**
 * Kuralı kaydetmeden önce son ve kapsamlı bir kontrol yapar.
 */
export const validateRuleForFinalization = (headerData, ruleOptions) => {
    // 1. Başlık alanlarının dolu olup olmadığını kontrol et
    const isHeaderComplete = Object.values(headerData).every(val => val && val.trim() !== '');
    if (!isHeaderComplete) {
        return 'Kural kaydedilemedi! Lütfen önce tüm başlık alanlarını doldurun.';
    }

    // 2. Başlık alanlarındaki değerlerin geçerli olup olmadığını kontrol et
    for (const fieldName in headerData) {
        const value = headerData[fieldName];
        const fieldValidationError = validateHeaderField(fieldName, value);
        if (fieldValidationError) {
            return `Kural kaydedilemedi! ${fieldValidationError}`;
        }
    }

    // YENİ EKLENEN ADIM:
    // 3. Eklenmiş olan tüm seçeneklerin değerlerinin geçerli olup olmadığını kontrol et
    for (const option of ruleOptions) {
        const optionValidationError = validateOptionField(option.keyword, option.value);
        if (optionValidationError) {
            return `Kural kaydedilemedi! ${optionValidationError}`;
        }
    }

    // 4. 'msg' seçeneğinin zorunluluğunu kontrol et
    const msgOption = ruleOptions.find(o => o.keyword === 'msg');
    if (!msgOption) { // Değerinin boş olup olmadığını yukarıdaki döngü zaten kontrol etti.
        return 'Kural kaydedilemedi! "msg" seçeneği zorunludur.';
    }

    // 5. 'sid' seçeneğinin zorunluluğunu kontrol et
    const sidOption = ruleOptions.find(o => o.keyword === 'sid');
    if (!sidOption) { // Değerinin boş veya geçersiz olup olmadığını yukarıdaki döngü zaten kontrol etti.
        return 'Kural kaydedilemedi! "sid" seçeneği zorunludur.';
    }
    
    // Tüm kontrollerden geçerse null döndür (hata yok)
    return null;
};