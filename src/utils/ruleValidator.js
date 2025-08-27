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