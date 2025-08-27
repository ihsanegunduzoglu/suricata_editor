// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

// DEĞİŞİKLİK: isBeingEdited prop'unu alıyoruz
const FinalizedRule = ({ session, isBeingEdited, isSelected, onToggleSelected }) => {
    // DEĞİŞİKLİK: cancelEditing fonksiyonunu da context'ten alıyoruz
    const { deleteRule, duplicateRule, startEditingRule, cancelEditing } = useRule();
    
    const handleCopyToClipboard = () => {
        navigator.clipboard.writeText(session.ruleString);
        toast.success('Kural panoya kopyalandı!');
    };

    // DEĞİŞİKLİK: Düzenleme butonu artık iki işlevli: başlatma ve iptal etme
    const handleEditToggle = () => {
        if (isBeingEdited) {
            cancelEditing(); // Eğer bu kural zaten düzenleniyorsa, düzenlemeyi iptal et
        } else {
            startEditingRule(session.id); // Değilse, düzenlemeyi başlat
        }
    };

    // DEĞİŞİKLİK: Ana konteyner'a isBeingEdited durumuna göre dinamik sınıf ekliyoruz
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
                    disabled={isBeingEdited} // Düzenleme sırasında silmeyi engelle
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
                style={vscDarkPlus}
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