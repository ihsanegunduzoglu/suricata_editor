// src/components/RuleListPanel.js

import React from 'react';
import { useRule } from '../context/RuleContext';

// YENİ: Gelen prop'ları karşılıyoruz
const RuleListPanel = ({ isPanelOpen, togglePanel }) => {
    const { completedRules } = useRule();

    return (
        <div className="rule-list-panel">
            <div className="panel-header">
                {/* YENİ: Panel açıkken başlık görünür */}
                {isPanelOpen && <h3>Tamamlanmış Kurallar</h3>}
                {/* YENİ: Açma/Kapama butonu */}
                <button onClick={togglePanel} className="panel-toggle-btn">
                    {isPanelOpen ? '‹' : '›'}
                </button>
            </div>
            
            {/* YENİ: Panel sadece açıkken liste içeriği görünür */}
            {isPanelOpen && (
                <ul>
                    {completedRules.length === 0 ? (
                        <li style={{ color: '#666' }}>Henüz kural eklenmedi.</li>
                    ) : (
                        completedRules.map((rule, index) => (
                            <li key={index}>{rule}</li>
                        ))
                    )}
                </ul>
            )}
        </div>
    );
};

export default RuleListPanel;