// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
// YENİ: Koyu ve Açık mod için iki farklı stil import ediyoruz
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';

// DEĞİŞİKLİK: isBeingEdited prop'unu alıyoruz
const FinalizedRule = ({ session, isBeingEdited, isSelected, onToggleSelected }) => {
    // DEĞİŞİKLİK: cancelEditing fonksiyonunu da context'ten alıyoruz
    const { deleteRule, duplicateRule, startEditingRule, cancelEditing ,theme, focusHeaderField, focusOption } = useRule();
  
    
    const handleCopyToClipboard = () => {
        navigator.clipboard.writeText(session.ruleString);
        toast.success('Kural panoya kopyalandı!');
    };

    const handleEditToggle = () => {
        if (isBeingEdited) {
            cancelEditing();
        } else {
            startEditingRule(session.id);
        }
    };

    // YENİ: Tema durumuna göre doğru renklendirme stilini seçiyoruz
    const syntaxTheme = theme === 'light' ? vs : vscDarkPlus;

    return (
        <div className={`finalized-rule-container ${isBeingEdited ? 'is-being-edited' : ''}`}>
            <div className="rule-actions">
                <button 
                    className="rule-action-btn" 
                    title={isSelected ? "Seçimi kaldır" : "Seç"}
                    onClick={onToggleSelected}
                >
                    {isSelected ? '✓' : ''}
                </button>
                <button 
                    className="rule-action-btn" 
                    title={isBeingEdited ? "Düzenlemeyi İptal Et" : "Düzenle"}
                    onClick={handleEditToggle}
                >
                    {isBeingEdited ? '↩️' : '✏️'}
                </button>
                <button 
                    className="rule-action-btn" 
                    title="Sil"
                    onClick={() => deleteRule(session.id)}
                    disabled={isBeingEdited}
                >
                    ✖
                </button>
                <button 
                    className="rule-action-btn" 
                    title="Panoya Kopyala"
                    onClick={handleCopyToClipboard}
                    disabled={isBeingEdited}
                >
                    📋
                </button>
                <button 
                    className="rule-action-btn" 
                    title="Çoğalt"
                    onClick={() => duplicateRule(session)}
                    disabled={isBeingEdited}
                >
                    ➕
                </button>
            </div>
            {(() => {
                const text = session.ruleString || '';
                const m = text.match(/^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<->)\s+(\S+)\s+(\S+)\s*\(/);
                if (!m) {
                    return (
                        <SyntaxHighlighter 
                            language="bash" 
                            style={syntaxTheme}
                            customStyle={{ margin: 0, padding: '1.5em', backgroundColor: 'transparent' }}
                            codeTagProps={{ style: { fontSize: '1rem', fontFamily: "'Consolas', 'Courier New', monospace" } }}
                            wrapLines
                            wrapLongLines
                        >
                            {text}
                        </SyntaxHighlighter>
                    );
                }
                const [, action, proto, sip, sport, dir, dip, dport] = m;
                const idx = text.indexOf('(');
                const optionsPart = idx >= 0 ? text.slice(idx) : '';
                const optionsBody = idx >= 0 ? text.slice(idx + 1, text.lastIndexOf(')')) : '';
                const optionSegments = optionsBody ? optionsBody.split(';').map(s => s.trim()).filter(Boolean) : [];
                const findNthIndexByKeyword = (options, keyword, nth) => {
                    let count = 0;
                    for (let idx = 0; idx < options.length; idx++) {
                        if (options[idx].keyword === keyword) {
                            count += 1;
                            if (count === nth) return idx;
                        }
                    }
                    return options.findIndex(o => o.keyword === keyword);
                };
                const keywordSeenCount = {};
                const join = (a, b) => a + ' ' + b;
                const ensureEditingThen = (fn) => {
                    if (!isBeingEdited) {
                        startEditingRule(session.id);
                        setTimeout(fn, 0);
                    } else {
                        fn();
                    }
                };

                return (
                    <pre style={{ margin: 0, padding: '1.5em', fontSize: '1rem', fontFamily: "'Consolas','Courier New', monospace" }}>
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Action', true, action))} style={{ cursor: 'pointer' }}>{action}</span>{' '}
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Protocol', true, proto))} style={{ cursor: 'pointer' }}>{proto}</span>{' '}
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Source IP', true, sip))} style={{ cursor: 'pointer' }}>{sip}</span>{' '}
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Source Port', true, sport))} style={{ cursor: 'pointer' }}>{sport}</span>{' '}
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Direction', true, dir))} style={{ cursor: 'pointer' }}>{dir}</span>{' '}
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Destination IP', true, dip))} style={{ cursor: 'pointer' }}>{dip}</span>{' '}
                        <span onClick={() => ensureEditingThen(() => focusHeaderField('Destination Port', true, dport))} style={{ cursor: 'pointer' }}>{dport}</span>
                        {' '}
                        (
                        {optionSegments.map((seg, i) => {
                            const m = seg.match(/^([a-zA-Z0-9_.]+)\s*:/);
                            const keyword = m ? m[1] : seg.trim();
                            const isFlag = !m;
                            keywordSeenCount[keyword] = (keywordSeenCount[keyword] || 0) + 1;
                            const preferredIndex = findNthIndexByKeyword(session.ruleOptions || [], keyword, keywordSeenCount[keyword]);
                            const onClick = () => {
                                ensureEditingThen(() => {
                                    if (isFlag) {
                                        focusOption(keyword, false, preferredIndex >= 0 ? preferredIndex : null);
                                    } else {
                                        const expandDetails = keyword === 'content';
                                        focusOption(keyword, expandDetails, preferredIndex >= 0 ? preferredIndex : null);
                                    }
                                });
                            };
                            return (
                                <span key={i} onClick={onClick} style={{ cursor: 'pointer' }}>
                                    {seg}
                                    {i < optionSegments.length - 1 ? '; ' : ''}
                                </span>
                            );
                        })}
                        ;)
                    </pre>
                );
            })()}
        </div>
    );
};

export default FinalizedRule;