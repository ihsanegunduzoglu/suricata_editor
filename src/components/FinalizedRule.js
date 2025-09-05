// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Pencil, Trash2, Copy, PlusSquare, Undo2 } from 'lucide-react';

const FinalizedRule = ({ session, isBeingEdited, isSelected, onToggleSelected }) => {
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
     
    const syntaxTheme = theme === 'light' ? vs : vscDarkPlus;
    const containerClassName = `finalized-rule-container ${isBeingEdited ? 'is-being-edited' : ''} ${isSelected ? 'is-selected' : ''}`;

    return (
        <div className={containerClassName}>
            <div className="rule-actions">
                <input 
                    type="checkbox" 
                    className="rule-selection-checkbox"
                    checked={isSelected}
                    onChange={onToggleSelected}
                    title="Bu kuralı seç"
                />
                <button 
                    className={`rule-action-btn ${isBeingEdited ? 'is-editing-active-btn pulse-animation' : ''}`}
                    title={isBeingEdited ? "Düzenlemeyi İptal Et" : "Düzenle"} 
                    onClick={handleEditToggle}
                >
                    {isBeingEdited ? <Undo2 size={16} /> : <Pencil size={16} />}
                </button>
                <button className="rule-action-btn" title="Sil" onClick={() => deleteRule(session.id)} disabled={isBeingEdited}>
                    <Trash2 size={16} />
                </button>
                <button className="rule-action-btn" title="Panoya Kopyala" onClick={handleCopyToClipboard} disabled={isBeingEdited}>
                    <Copy size={16} />
                </button>
                <button className="rule-action-btn" title="Çoğalt" onClick={() => duplicateRule(session)} disabled={isBeingEdited}>
                    <PlusSquare size={16} />
                </button>
            </div>
            {(() => {
                const text = session.ruleString || '';
                const headerMatch = text.match(/^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<->)\s+(\S+)\s+(\S+)\s+\(/);

                if (!headerMatch) {
                    // Eğer kural yapısı beklenmedikse, basit highlighter ile göster
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

                const [, action, proto, sip, sport, dir, dip, dport] = headerMatch;
                const optionsBody = text.substring(text.indexOf('(') + 1, text.lastIndexOf(')'));
                const optionSegments = optionsBody.split(';').map(s => s.trim()).filter(Boolean);

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

                const ensureEditingThen = (fn) => {
                    if (!isBeingEdited) {
                        startEditingRule(session.id);
                        setTimeout(fn, 50); // Focus için küçük bir gecikme
                    } else {
                        fn();
                    }
                };

                return (
                    <pre className="rule-display" style={{ margin: 0, padding: '1.5em', fontSize: '1rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: "'Consolas','Courier New', monospace" }}>
                        <span className="rule-part-action" onClick={() => ensureEditingThen(() => focusHeaderField('Action', true, action))} style={{ cursor: 'pointer' }}>{action}</span>{' '}
                        <span className="rule-part-protocol" onClick={() => ensureEditingThen(() => focusHeaderField('Protocol', true, proto))} style={{ cursor: 'pointer' }}>{proto}</span>{' '}
                        <span className="rule-part-address" onClick={() => ensureEditingThen(() => focusHeaderField('Source IP', true, sip))} style={{ cursor: 'pointer' }}>{sip}</span>{' '}
                        <span className="rule-part-address" onClick={() => ensureEditingThen(() => focusHeaderField('Source Port', true, sport))} style={{ cursor: 'pointer' }}>{sport}</span>{' '}
                        <span className="rule-part-direction" onClick={() => ensureEditingThen(() => focusHeaderField('Direction', true, dir))} style={{ cursor: 'pointer' }}>{dir}</span>{' '}
                        <span className="rule-part-address" onClick={() => ensureEditingThen(() => focusHeaderField('Destination IP', true, dip))} style={{ cursor: 'pointer' }}>{dip}</span>{' '}
                        <span className="rule-part-address" onClick={() => ensureEditingThen(() => focusHeaderField('Destination Port', true, dport))} style={{ cursor: 'pointer' }}>{dport}</span>{' '}
                        <span className="rule-part-punctuation">(</span>
                        {optionSegments.map((seg, i) => {
                            const segMatch = seg.match(/^([^:]+)(?::(.*))?$/);
                            const keyword = segMatch ? segMatch[1].trim() : seg;
                            const value = segMatch && segMatch[2] ? segMatch[2].trim() : null;

                            keywordSeenCount[keyword] = (keywordSeenCount[keyword] || 0) + 1;
                            const preferredIndex = findNthIndexByKeyword(session.ruleOptions || [], keyword, keywordSeenCount[keyword]);
                            
                            const onClick = () => {
                                ensureEditingThen(() => {
                                    focusOption(keyword, keyword === 'content', preferredIndex >= 0 ? preferredIndex : null);
                                });
                            };

                            return (
                                <span key={i} onClick={onClick} style={{ cursor: 'pointer' }}>
                                    <span className="rule-part-option-keyword">{keyword}</span>
                                    {value !== null && <span className="rule-part-punctuation">:</span>}
                                    {value !== null && <span className="rule-part-option-value">{value}</span>}
                                    {i < optionSegments.length - 1 && <span className="rule-part-punctuation">; </span>}
                                </span>
                            );
                        })}
                        <span className="rule-part-punctuation">)</span>
                    </pre>
                );
            })()}
        </div>
    );
};

export default FinalizedRule;