// src/components/FinalizedRule.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { toast } from 'react-toastify';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Pencil, Trash2, Copy, PlusSquare, Undo2, TestTube2 } from 'lucide-react';

const FinalizedRule = ({ session, isBeingEdited, isSelected, onToggleSelect }) => {
    const { deleteRule, duplicateRule, startEditingRule, cancelEditing, theme, setRuleToTest, setInfoPanelTab } = useRule();
    
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

    const handleTestClick = () => {
        setRuleToTest(session.ruleString);
        setInfoPanelTab('test_lab');
        toast.info("Kural, test için laboratuvara gönderildi.");
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
                    onChange={onToggleSelect}
                    title="Bu kuralı seç"
                />
                <button className="rule-action-btn" title="Bu Kuralı Test Et" onClick={handleTestClick}>
                    <TestTube2 size={16} />
                </button>
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
            <SyntaxHighlighter 
                language="bash" 
                style={syntaxTheme}
                customStyle={{ margin: 0, padding: '1.5em', backgroundColor: 'transparent' }}
                codeTagProps={{ style: { fontSize: '1rem', fontFamily: "'Fira Code', 'Consolas', monospace" } }}
                wrapLines={true}
                wrapLongLines={true}
            >
                {session.ruleString}
            </SyntaxHighlighter>
        </div>
    );
};

export default FinalizedRule;