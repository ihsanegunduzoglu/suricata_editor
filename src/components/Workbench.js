// src/components/Workbench.js

import React, { useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel';
import TopMenuBar from './TopMenuBar';
import ValidationPanel from './ValidationPanel';

const Workbench = () => {
    // YENİ: Kural seçimi ve import için gerekli state ve fonksiyonlar context'ten alındı
    const { ruleSessions, editingSourceId, isRulesListVisible, isInfoPanelVisible, selectedRuleIds, setSelectedRuleIds, importRules } = useRule();
    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = ruleSessions.filter(session => session.status === 'finalized');

    // YENİ: Eksik olan ref ve değişkenler tanımlandı
    const fileInputRef = useRef(null);
    const finalizedRuleIds = finalizedSessions.map(s => s.id);
    const allSelected = finalizedRuleIds.length > 0 && finalizedRuleIds.every(id => selectedRuleIds.has(id));

    const handleExport = () => {
        // YENİ: Sadece seçili kuralları veya hiçbiri seçili değilse tüm kuralları dışa aktar
        const rulesToExport = finalizedSessions.filter(session => selectedRuleIds.size === 0 || selectedRuleIds.has(session.id));

        if (rulesToExport.length === 0) {
            toast.warn('Dışa aktarılacak kural bulunmuyor.');
            return;
        }

        const rulesString = rulesToExport.map(session => session.ruleString).join('\n\n');
        const blob = new Blob([rulesString], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'custom.rules';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    // YENİ: Eksik fonksiyonlar tanımlandı
    const handleImportClick = () => {
        fileInputRef.current?.click();
    };

    const handleImportFile = (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                importRules(e.target.result);
            };
            reader.readAsText(file);
        }
        event.target.value = null; // Aynı dosyayı tekrar seçebilmek için
    };

    const clearSelection = () => {
        setSelectedRuleIds(new Set());
    };

    const selectAllFinalized = () => {
        setSelectedRuleIds(new Set(finalizedRuleIds));
    };

    const handleToggleSelect = (ruleId) => {
        setSelectedRuleIds(prev => {
            const newSet = new Set(prev);
            if (newSet.has(ruleId)) {
                newSet.delete(ruleId);
            } else {
                newSet.add(ruleId);
            }
            return newSet;
        });
    };
    
    const layoutClassName = `app-layout ${!isInfoPanelVisible ? 'single-column' : ''}`;

    return (
        <div className="app-container">
            <TopMenuBar />
            <div className={layoutClassName}>
                <div className="main-content-area">
                    <div className="active-editor-container">
                        {activeSession ? (
                            <div className="active-editor-wrapper">
                                <HeaderEditor key={activeSession.id} session={activeSession} />
                            </div>
                        ) : (
                            <p>Yeni kural oluşturuluyor...</p>
                        )}
                        <ValidationPanel />
                    </div>

                    {isRulesListVisible && (
                        <div className="finalized-rules-list">
                             {/* YENİ: Araç çubuğu eklendi */}
                            <div className="rules-toolbar">
                                <button onClick={handleImportClick} title="Kuralları İçe Aktar">Import</button>
                                <button onClick={handleExport} title="Seçili Kuralları Dışa Aktar">Export</button>
                                <button onClick={allSelected ? clearSelection : selectAllFinalized}>
                                    {allSelected ? 'Seçimi Temizle' : 'Tümünü Seç'}
                                </button>
                            </div>
                            <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleImportFile} accept=".rules,.txt" />
                            <div className="rules-scroll-wrapper"> 
                                {finalizedSessions.reverse().map(session => (
                                    <FinalizedRule 
                                        key={session.id} 
                                        session={session} 
                                        isBeingEdited={session.id === editingSourceId}
                                        // YENİ: Seçim için gerekli proplar eklendi
                                        isSelected={selectedRuleIds.has(session.id)}
                                        onToggleSelect={() => handleToggleSelect(session.id)}
                                    />
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {isInfoPanelVisible && (
                    <div className="right-info-panel">
                        <InfoPanel />
                    </div>
                )}
            </div>
        </div>
    );
};

export default Workbench;