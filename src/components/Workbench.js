// src/components/Workbench.js

import React, { useMemo, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel';
import TopMenuBar from './TopMenuBar';
import ValidationPanel from './ValidationPanel'; 

const Workbench = () => {
    const { ruleSessions, editingSourceId, isRulesListVisible, isInfoPanelVisible, appendImportedRules, selectedRuleIds, toggleRuleSelected, selectAllFinalized, clearSelection, deleteRulesByIds } = useRule();
    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = useMemo(() => ruleSessions.filter(session => session.status === 'finalized'), [ruleSessions]);
    const fileInputRef = useRef(null);
    const allSelected = selectedRuleIds.length > 0 && selectedRuleIds.length === finalizedSessions.length;

    const handleExport = () => {
       
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce en az bir kural seçin.');
            return;
        }

        const source = finalizedSessions.filter(s => selectedRuleIds.includes(s.id));
        const finalizedRules = source
            .map(session => session.ruleString)
            .join('\n\n');

        if (!finalizedRules || finalizedRules.length === 0) {
            toast.warn('Dışa aktarılacak kural bulunmuyor.');
            return;
        }

        const blob = new Blob([finalizedRules], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'selected.rules';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
    
    const handleImportClick = () => {
        fileInputRef.current?.click();
    };

    const handleBulkDelete = () => {
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce silmek için en az bir kural seçin.');
            return;
        }
        deleteRulesByIds(selectedRuleIds);
    };

    const handleImportFile = async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        try {
            const form = new FormData();
            form.append('file', file);
            const res = await fetch('/rules/parse', { method: 'POST', body: form });
            if (!res.ok) throw new Error('Sunucu hatası');
            const data = await res.json();
            if (!data || !Array.isArray(data.rules)) throw new Error('Geçersiz yanıt');
            appendImportedRules(data.rules);
        } catch (err) {
            toast.error('İçe aktarma başarısız: ' + (err?.message || 'Bilinmeyen hata'));
        } finally {
            // aynı dosyayı tekrar seçebilmek için inputu sıfırla
            if (fileInputRef.current) fileInputRef.current.value = '';
        }
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
                        {/* YENİ: Hata/Uyarı paneli burada gösterilecek */}
                        <ValidationPanel />
                    </div>

                    {isRulesListVisible && (
                        <div className="finalized-rules-list">
                            <div className="rules-toolbar">
                                <button 
                                    onClick={handleExport} 
                                    className="toolbar-button export-button"
                                    title="Kuralları .rules dosyası olarak indir"
                                >
                                    ⇩
                                </button>
                                <button 
                                    onClick={handleImportClick}
                                    className="toolbar-button import-button"
                                    title=".rules dosyasından içe aktar"
                                >
                                    ⇧
                                </button>
                                <button
                                    onClick={handleBulkDelete}
                                    className="toolbar-button delete-button"
                                    title="Seçilen kuralları sil"
                                >
                                    🗑
                                </button>
                                <button 
                                    onClick={() => { allSelected ? clearSelection() : selectAllFinalized(); }}
                                    className="toolbar-button select-all-button"
                                    title={allSelected ? "Tüm tikleri kaldır" : "Tümünü seç"}
                                >
                                    ✓
                                </button>
                            </div>
                            <input type="file" ref={fileInputRef} accept=".rules,.txt" style={{ display: 'none' }} onChange={handleImportFile} />
                            <div className="rules-scroll-wrapper"> 
                                {finalizedSessions.slice().reverse().map(session => (
                                    <FinalizedRule 
                                        key={session.id} 
                                        session={session} 
                                        isSelected={selectedRuleIds.includes(session.id)}
                                        onToggleSelected={() => toggleRuleSelected(session.id)}
                                        isBeingEdited={session.id === editingSourceId}
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