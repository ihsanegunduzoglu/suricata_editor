// src/components/InfoPanel.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import { infoData } from '../data/infoData';
import { optionsDictionary } from '../data/optionsDictionary';

// Taktik listesini gösteren alt bileşen
const MitreTacticList = () => {
    const { activeTopic } = useRule();
    const listRef = useRef(null);
    const [tactics, setTactics] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        fetch('http://127.0.0.1:5000/api/tactics')
            .then(res => res.json())
            .then(data => { setTactics(data); setIsLoading(false); })
            .catch(() => setIsLoading(false));
    }, []);

    useEffect(() => {
        if (activeTopic && listRef.current) {
            const el = listRef.current.querySelector(`#info-item-${activeTopic.replace('.', '-')}`);
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }, [activeTopic]);

    return (
        <div className="info-panel-content">
            <h3>MITRE ATT&CK Taktikleri</h3>
            <p>Bir taktik seçerek ilişkili teknikleri listeleyebilirsiniz.</p>
            {isLoading ? <p>Yükleniyor...</p> : (
                <ul className="info-options-list" ref={listRef}>
                    {tactics.map(tactic => (
                        <li key={tactic.id} id={`info-item-${tactic.id}`} className={activeTopic === tactic.id ? 'is-highlighted' : ''}>
                            <strong>{tactic.name} ({tactic.id})</strong>
                            <span>{tactic.description}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

// Teknik listesini gösteren alt bileşen
const MitreTechniqueList = ({ tacticId }) => {
    const { activeTopic } = useRule();
    const listRef = useRef(null);
    const [techniques, setTechniques] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        if (tacticId) {
            setIsLoading(true);
            fetch(`http://127.0.0.1:5000/api/techniques/${tacticId}`)
                .then(res => res.json())
                .then(data => { setTechniques(data); setIsLoading(false); })
                .catch(() => setIsLoading(false));
        }
    }, [tacticId]);

    useEffect(() => {
        if (activeTopic && listRef.current) {
            const el = listRef.current.querySelector(`#info-item-${activeTopic.replace('.', '-')}`);
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }, [activeTopic]);

    return (
        <div className="info-panel-content">
            <h3>Teknikler ({tacticId})</h3>
            <p>Aşağıda seçtiğiniz taktik ile ilişkili teknikler listelenmiştir.</p>
            {isLoading ? <p>Yükleniyor...</p> : (
                <ul className="info-options-list" ref={listRef}>
                    {techniques.map(tech => (
                        <li key={tech.id} id={`info-item-${tech.id.replace('.', '-')}`} className={activeTopic === tech.id ? 'is-highlighted' : ''}>
                            <strong>{tech.name} ({tech.id})</strong>
                            <span>{tech.description}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

// Sub-teknik listesini gösteren alt bileşen
const MitreSubtechniqueList = ({ techniqueId }) => {
    const { activeTopic } = useRule();
    const listRef = useRef(null);
    const [subtechniques, setSubtechniques] = useState([]);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        if (techniqueId) {
            setIsLoading(true);
            fetch(`http://127.0.0.1:5000/api/subtechniques/${techniqueId}`)
                .then(res => res.json())
                .then(data => { setSubtechniques(data); setIsLoading(false); })
                .catch(() => setIsLoading(false));
        }
    }, [techniqueId]);

    useEffect(() => {
        if (activeTopic && listRef.current) {
            const el = listRef.current.querySelector(`#info-item-${activeTopic.replace('.', '-')}`);
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }, [activeTopic]);
    
    return (
        <div className="info-panel-content">
            <h3>Alt-Teknikler ({techniqueId})</h3>
            <p>Aşağıda seçtiğiniz teknik ile ilişkili alt-teknikler listelenmiştir.</p>
            {isLoading ? <p>Yükleniyor...</p> : (
                <ul className="info-options-list" ref={listRef}>
                    {subtechniques.map(sub => (
                        <li key={sub.id} id={`info-item-${sub.id.replace('.', '-')}`} className={activeTopic === sub.id ? 'is-highlighted' : ''}>
                            <strong>{sub.name} ({sub.id})</strong>
                            <span>{sub.description}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

// Tüm kural seçeneklerini listeleyen alt bileşen
const AllOptionsInfo = () => {
    const { activeTopic } = useRule();
    const listRef = useRef(null);
    const optionKeywords = Object.keys(optionsDictionary).filter(k => !optionsDictionary[k].isModifier);
    
    useEffect(() => {
        if (activeTopic && listRef.current) {
            const highlightedElement = listRef.current.querySelector(`#info-item-${activeTopic}`);
            if (highlightedElement) {
                highlightedElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    }, [activeTopic]);

    return (
        <div className="all-options-info">
            <h3>Tüm Kural Seçenekleri</h3>
            <p>Mevcut tüm kural seçeneklerinin bir listesi aşağıdadır.</p>
            <ul className="info-options-list" ref={listRef}>
                {optionKeywords.map(keyword => (
                    <li key={keyword} id={`info-item-${keyword}`} className={activeTopic === keyword ? 'is-highlighted' : ''}>
                        <strong>{keyword}</strong>
                        <span>{infoData[keyword]?.summary || optionsDictionary[keyword].description}</span>
                    </li>
                ))}
            </ul>
        </div>
    );
};

// "content" değiştiricilerini listeleyen alt bileşen
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
    const { activeTopic, optionsViewActive, modifierInfoActive, mitreInfo } = useRule();
    const currentInfo = activeTopic ? infoData[activeTopic] : null;

    if (mitreInfo) {
        if (mitreInfo.type === 'tactic_list') return <MitreTacticList />;
        if (mitreInfo.type === 'technique_list' && mitreInfo.tacticId) return <MitreTechniqueList tacticId={mitreInfo.tacticId} />;
        if (mitreInfo.type === 'subtechnique_list' && mitreInfo.techniqueId) return <MitreSubtechniqueList techniqueId={mitreInfo.techniqueId} />;
    }

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

    if (modifierInfoActive) return <AllModifiersInfo />;
    if (optionsViewActive) return <AllOptionsInfo />;

    return (
        <div className="panel-placeholder">
            <h3>Bilgi Paneli</h3>
            <p>Kuralın bir bölümünü seçerek hakkında detaylı bilgi alabilirsiniz.</p>
        </div>
    );
};

export default InfoPanel;