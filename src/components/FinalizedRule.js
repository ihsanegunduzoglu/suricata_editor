// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';

// YENİ: Renklendirme kütüphanesini ve karanlık tema stilini import ediyoruz
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';


const FinalizedRule = ({ session }) => {
    const { deleteRule, duplicateRule, startEditingRule, cancelEditing, editingSessionId } = useRule();
    
    const handleCopyToClipboard = () => {
        navigator.clipboard.writeText(session.ruleString);
        toast.success('Kural panoya kopyalandı!');
    };
    
    const isCurrentlyEditing = editingSessionId === session.id;

    const handleEditToggle = () => {
        if (isCurrentlyEditing) {
            cancelEditing();
        } else {
            startEditingRule(session.id);
        }
    };

    return (
        <div className={`finalized-rule-container ${isCurrentlyEditing ? 'is-editing' : ''}`}>
            <div className="rule-actions">
                <button 
                    className="rule-action-btn" 
                    title={isCurrentlyEditing ? "Düzenlemeyi Kapat" : "Düzenle"}
                    onClick={handleEditToggle}
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
                    title="Panoya Kopyala"
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
            {/* DEĞİŞİKLİK: Eski <pre> etiketi yerine SyntaxHighlighter bileşenini kullanıyoruz */}
            <SyntaxHighlighter 
                language="bash" 
                style={vscDarkPlus}
                customStyle={{
                    margin: 0,
                    padding: '1.5em',
                    backgroundColor: 'transparent',
                }}
                codeTagProps={{
                    style: {
                        fontSize: '1rem', // Yazı tipini buradan büyütüyoruz
                        fontFamily: "'Consolas', 'Courier New', monospace" // Font ailesini de garantileyelim
                    }
                }}
                wrapLines={true}
                wrapLongLines={true}
            >
                {session.ruleString}
            </SyntaxHighlighter>
        </div>
    );
};

export default FinalizedRule;