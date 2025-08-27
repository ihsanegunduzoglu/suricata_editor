// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
// YENİ: Koyu ve Açık mod için iki farklı stil import ediyoruz
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';

const FinalizedRule = ({ session, isBeingEdited }) => {
    // YENİ: Mevcut temayı context'ten alıyoruz
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

    // YENİ: Tema durumuna göre doğru renklendirme stilini seçiyoruz
    const syntaxTheme = theme === 'light' ? vs : vscDarkPlus;

    return (
        <div className={`finalized-rule-container ${isBeingEdited ? 'is-being-edited' : ''}`}>
            <div className="rule-actions">
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
                style={syntaxTheme} // YENİ: Dinamik stili burada kullanıyoruz
                customStyle={{ margin: 0, padding: '1.5em', backgroundColor: 'transparent' }}
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