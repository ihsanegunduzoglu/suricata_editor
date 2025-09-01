// src/utils/payloadAnalyzer.js

const hexToAscii = (hexString) => {
    try {
        const cleanedHex = hexString.replace(/\|/g, '').trim();
        let hexBytes = [];
        if (cleanedHex.includes(' ')) {
            hexBytes = cleanedHex.split(' ');
        } else {
            for (let i = 0; i < cleanedHex.length; i += 2) {
                hexBytes.push(cleanedHex.substring(i, i + 2));
            }
        }
        return hexBytes
            .filter(byte => byte.length === 2)
            .map(byte => {
                const charCode = parseInt(byte, 16);
                return (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
            })
            .join('');
    } catch (error) {
        console.error("Hex'ten ASCII'ye çevirme hatası:", error);
        return '';
    }
};

const normalizePayload = (payload) => {
    const trimmedPayload = payload.trim();
    const isHexPattern = /^(?:\|([0-9A-Fa-f]{2}\s*)+?\|)|^(?:([0-9A-Fa-f]{2}\s*)+)$/;
    if (isHexPattern.test(trimmedPayload)) {
        return hexToAscii(trimmedPayload);
    }
    return trimmedPayload;
};

export const analyzePayload = (rawPayload, contentMatchers) => {
    if (!rawPayload || rawPayload.trim() === '') {
        return { error: "Lütfen analiz edilecek bir payload girin." };
    }
    if (!contentMatchers || contentMatchers.length < 2) {
        return { error: "Lütfen en az iki adet 'content' girin." };
    }
    if (contentMatchers.some(m => !m || m.trim() === '')) {
        return { error: "Tüm 'content' alanlarını doldurun." };
    }

    const payload = normalizePayload(rawPayload);
    const results = [];
    let lastMatch = null;

    for (const matcher of contentMatchers) {
        const searchFromIndex = lastMatch ? lastMatch.end + 1 : 0;
        const startIndex = payload.indexOf(matcher, searchFromIndex);
        if (startIndex === -1) {
            results.push({ value: matcher, found: false });
            return {
                payload,
                results,
                error: `'${matcher}' payload içinde bulunamadı veya sıralı değil.`
            };
        }
        const endIndex = startIndex + matcher.length - 1;
        const currentMatch = {
            value: matcher,
            start: startIndex,
            end: endIndex,
            found: true
        };
        if (lastMatch) {
            // DÜZELTME: distance hesaplaması (aradaki boşluk değil, göreli mesafe)
            currentMatch.distance = startIndex - lastMatch.end;
            // DÜZELTME: within hesaplaması (toplam aralık uzunluğu)
            currentMatch.within = endIndex - lastMatch.start + 1;
        }
        results.push(currentMatch);
        lastMatch = currentMatch;
    }

    const visualizationChars = Array(payload.length).fill('.'); 
    results.forEach(match => {
        if (match.found) {
            for (let i = 0; i < match.value.length; i++) {
                if (match.start + i < visualizationChars.length) {
                    visualizationChars[match.start + i] = match.value[i];
                }
            }
        }
    });

    return {
        payload,
        results,
        visualization: visualizationChars.join('')
    };
};

// YENİ: Fonksiyonu 'default' olarak dışa aktarmaya devam ediyoruz
export default analyzePayload;