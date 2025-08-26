// src/components/InfoPanel.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { infoData } from '../data/infoData';
import { optionsDictionary } from '../data/optionsDictionary';

// Tüm Ana Seçenekleri Listeleyen Bileşen
const AllOptionsInfo = () => {
    const optionKeywords = Object.keys(optionsDictionary).filter(k => !optionsDictionary[k].isModifier);
    return (
        <div className="all-options-info">
            <h3>Tüm Kural Seçenekleri</h3>
            <p>Mevcut tüm kural seçeneklerinin bir listesi aşağıdadır.</p>
            <ul className="info-options-list">
                {optionKeywords.map(keyword => (
                    <li key={keyword}>
                        <strong>{keyword}</strong>
                        <span>{infoData[keyword]?.summary || optionsDictionary[keyword].description}</span>
                    </li>
                ))}
            </ul>
        </div>
    );
};

// Tüm Değiştiricileri Listeleyen Bileşen
const AllModifiersInfo = () => {
    const modifierKeywords = Object.keys(optionsDictionary).filter(k => optionsDictionary[k].isModifier);
    return (
        <div className="all-options-info">
            <h3>"content" Değiştiricileri</h3>
            <p>"content" anahtar kelimesinin davranışını değiştiren tüm seçenekler:</p>
            <ul className="info-options-list">
                {modifierKeywords.map(keyword => (
                    <li key={keyword}>
                        <strong>{keyword}</strong>
                        <span>{infoData[keyword]?.summary || optionsDictionary[keyword].description}</span>
                    </li>
                ))}
            </ul>
        </div>
    );
};

// Ana Bilgi Paneli Bileşeni
const InfoPanel = () => {
    const { activeTopic, optionsViewActive, modifierInfoActive } = useRule();
    // HATA BURADAYDI, DÜZELTİLDİ: active.Topic yerine activeTopic
    const currentInfo = activeTopic ? infoData[activeTopic] : null;

    // 1. Durum: Eğer belirli bir konu seçiliyse (hover veya focus), o konunun detayını göster.
    if (currentInfo) {
        return (
            <div className="info-panel-content">
                <h3>{currentInfo.title}</h3>
                {currentInfo.summary && <p className="info-summary">{currentInfo.summary}</p>}
                {currentInfo.details && <div className="info-block"><h4>Detaylar</h4><p>{currentInfo.details}</p></div>}
                {currentInfo.syntax && <div className="info-block"><h4>Sözdizimi</h4><pre className="info-code"><code>{currentInfo.syntax}</code></pre></div>}
                {currentInfo.example && <div className="info-block"><h4>Örnek</h4><pre className="info-code"><code>{currentInfo.example}</code></pre></div>}
                {currentInfo.options && <div className="info-block"><h4>Seçenekler</h4><ul className="info-options-list">{currentInfo.options.map(opt => (<li key={opt.name}><strong>{opt.name}</strong><span>{opt.detail}</span></li>))}</ul></div>}
            </div>
        );
    }

    // 2. Durum: Eğer "Değiştirici Ekle" alanı aktifse, tüm değiştiricileri listele.
    if (modifierInfoActive) {
        return <AllModifiersInfo />;
    }

    // 3. Durum: Eğer ana seçenek ekleme aşamasındaysak, tüm seçenekleri listele.
    if (optionsViewActive) {
        return <AllOptionsInfo />;
    }

    // 4. Durum (Varsayılan): Header aşamasındaysak, genel karşılama mesajını göster.
    return (
        <div className="panel-placeholder">
            <h3>Bilgi Paneli</h3>
            <p>Kuralın bir bölümünü seçerek hakkında detaylı bilgi alabilirsiniz.</p>
        </div>
    );
};

export default InfoPanel;