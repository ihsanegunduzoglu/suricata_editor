// src/components/Workbench.js

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel';
import TopMenuBar from './TopMenuBar';
import ValidationPanel from './ValidationPanel';
import { optionsDictionary } from '../data/optionsDictionary';

const Workbench = () => {

    const { ruleSessions, editingSourceId, isRulesListVisible, isInfoPanelVisible, appendImportedRules, selectedRuleIds, toggleRuleSelected, selectAllFinalized, clearSelection, deleteRulesByIds, updateRuleOptions, theme } = useRule();

    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = useMemo(() => ruleSessions.filter(session => session.status === 'finalized'), [ruleSessions]);
    const fileInputRef = useRef(null);
    const rulesScrollRef = useRef(null);
    const [toolbarOpacity, setToolbarOpacity] = useState(0.9);
    const finalizedRuleIds = finalizedSessions.map(s => s.id);
    const allSelected = selectedRuleIds.length > 0 && selectedRuleIds.length === finalizedRuleIds.length;
    
    
    const prevProtocolRef = useRef();
    useEffect(() => {
        if (!activeSession) return;
        const currentProtocol = activeSession.headerData.Protocol;
        if (prevProtocolRef.current && currentProtocol !== prevProtocolRef.current) {
            const originalOptions = activeSession.ruleOptions;
            const cleanedOptions = originalOptions.filter(option => {
                const optionInfo = optionsDictionary[option.keyword];
                if (!optionInfo?.dependsOnProtocol) return true;
                return optionInfo.dependsOnProtocol === currentProtocol.toLowerCase();
            });
            const removedCount = originalOptions.length - cleanedOptions.length;
            if (removedCount > 0) {
                updateRuleOptions(activeSession.id, cleanedOptions);
                toast.warn(`${removedCount} adet seçenek, yeni protokolle uyumsuz olduğu için kaldırıldı.`);
            }
        }
        prevProtocolRef.current = currentProtocol;
    }, [activeSession?.headerData.Protocol, activeSession?.id, activeSession?.ruleOptions, updateRuleOptions]);

    const handleExport = () => {
        const rulesToExport = finalizedSessions.filter(session => selectedRuleIds.length === 0 || selectedRuleIds.includes(session.id));
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
                <div className="main-content-area glass-effect">
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
                            <div className="rules-toolbar" style={{
                                backgroundColor: theme === 'light' 
                                    ? `rgba(255,255,255, ${toolbarOpacity})` 
                                    : `rgba(28,27,34, ${toolbarOpacity})`,
                                border: toolbarOpacity > 0.15 ? '1px solid var(--border-primary)' : '1px solid transparent',
                                boxShadow: toolbarOpacity > 0.5 ? '0 4px 12px var(--shadow-color)' : 'none',
                                backdropFilter: 'blur(8px)'
                            }}>
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
                            <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleImportFile} accept=".rules,.txt" />
                            <div className="rules-scroll-wrapper" ref={rulesScrollRef} onScroll={(e) => {
                                const t = e.currentTarget.scrollTop || 0;
                                const next = Math.max(0.2, 1 - t / 300);
                                setToolbarOpacity(next);
                            }}> 
                                {finalizedSessions.slice().reverse().map(session => (
                                    <FinalizedRule 
                                        key={session.id} 
                                        session={session} 
                                        isBeingEdited={session.id === editingSourceId}
                                        isSelected={selectedRuleIds.includes(session.id)}
                                        onToggleSelected={() => toggleRuleSelected(session.id)}
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