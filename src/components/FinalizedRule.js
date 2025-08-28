// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';

// YENİ: Kural seçimi için proplar eklendi: isSelected, onToggleSelect
const FinalizedRule = ({ session, isBeingEdited, isSelected, onToggleSelect }) => {
    const { deleteRule, duplicateRule, startEditingRule, cancelEditing, theme } = useRule();
    
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

    // YENİ: Seçili olma durumuna göre ek bir class
    const containerClassName = `finalized-rule-container ${isBeingEdited ? 'is-being-edited' : ''} ${isSelected ? 'is-selected' : ''}`;

    return (
        <div className={containerClassName}>
            <div className="rule-actions">
                {/* YENİ: Kural seçimi için checkbox */}
                <input 
                    type="checkbox" 
                    className="rule-selection-checkbox"
                    checked={isSelected}
                    onChange={onToggleSelect}
                    title="Bu kuralı seç"
                />
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
            <SyntaxHighlighter 
                language="bash" 
                style={syntaxTheme}
                customStyle={{ margin: 0, padding: '1.5em 1.5em 1.5em 3.5em' }} // YENİ: Checkbox için solda boşluk
                codeTagProps={{ style: { fontSize: '1rem', fontFamily: "'Consolas', 'Courier New', monospace" } }}
                wrapLines={true}
                wrapLongLines={true}
            >
                {session.ruleString}
            </SyntaxHighlighter>
        </div>
    );
};

export default FinalizedRule;