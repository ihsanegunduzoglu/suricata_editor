// src/components/FinalizedRule.js

import React from 'react'; // useState kaldırıldı
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify'; // YENİ: toast import'u

const FinalizedRule = ({ session }) => {
    const { deleteRule, duplicateRule, startEditingRule, editingSessionId } = useRule();
    
    // DEĞİŞİKLİK: Lokal 'copyStatus' state'ine artık ihtiyacımız yok.
    // const [copyStatus, setCopyStatus] = useState('Kopyala');

    const handleCopyToClipboard = () => {
        navigator.clipboard.writeText(session.ruleString);
        // DEĞİŞİKLİK: setCopyStatus yerine toast.success() kullanıyoruz.
        toast.success('Kural panoya kopyalandı!');
    };
    
    const isCurrentlyEditing = editingSessionId === session.id;

    return (
        <div className={`finalized-rule-container ${isCurrentlyEditing ? 'is-editing' : ''}`}>
            <div className="rule-actions">
                <button className="rule-action-btn" title="Düzenle" onClick={() => startEditingRule(session.id)}>
                    ✏️
                </button>
                <button className="rule-action-btn" title="Sil" onClick={() => deleteRule(session.id)}>
                    ✖
                </button>
                <button className="rule-action-btn" title="Panoya Kopyala" onClick={handleCopyToClipboard}>
                    📋
                </button>
                <button className="rule-action-btn" title="Çoğalt" onClick={() => duplicateRule(session)}>
                    ➕
                </button>
            </div>
            <pre className="finalized-rule-text">{session.ruleString}</pre>
        </div>
    );
};

export default FinalizedRule;