// src/components/FinalizedRule.js

import React, { useState } from 'react';
import { useRule } from '../context/RuleContext';

const FinalizedRule = ({ session }) => {
    const { deleteRule, duplicateRule, startEditingRule, editingSessionId } = useRule();
    const [copyStatus, setCopyStatus] = useState('Kopyala');

    const handleCopyToClipboard = () => {
        navigator.clipboard.writeText(session.ruleString);
        setCopyStatus('Kopyalandı!');
        setTimeout(() => setCopyStatus('Kopyala'), 2000);
    };
    
    // YENİ: Bu kuralın şu an düzenlenip düzenlenmediğini kontrol et
    const isCurrentlyEditing = editingSessionId === session.id;

    return (
        // YENİ: Eğer düzenleniyorsa özel bir sınıf ekliyoruz
        <div className={`finalized-rule-container ${isCurrentlyEditing ? 'is-editing' : ''}`}>
            <div className="rule-actions">
                 {/* YENİ: Düzenle butonu */}
                <button 
                    className="rule-action-btn" 
                    title="Düzenle"
                    onClick={() => startEditingRule(session.id)}
                >
                    ✏️
                </button>
                <button 
                    className="rule-action-btn" 
                    title="Sil"
                    onClick={() => deleteRule(session.id)}
                >
                    ✖
                </button>
                <button 
                    className="rule-action-btn" 
                    title={copyStatus}
                    onClick={handleCopyToClipboard}
                >
                    📋
                </button>
                <button 
                    className="rule-action-btn" 
                    title="Çoğalt"
                    onClick={() => duplicateRule(session)}
                >
                    ➕
                </button>
            </div>
            <pre className="finalized-rule-text">{session.ruleString}</pre>
        </div>
    );
};

export default FinalizedRule;