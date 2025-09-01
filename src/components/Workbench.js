// src/components/Workbench.js

import React, { useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel';
import TopMenuBar from './TopMenuBar';
import ValidationPanel from './ValidationPanel';
import { optionsDictionary } from '../data/optionsDictionary';
import { FileUp, FileDown, CheckSquare, Square } from 'lucide-react';

// YENİ: react-resizable-panels kütüphanesinden bileşenleri import ediyoruz
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";

const Workbench = () => {
    const { ruleSessions, editingSourceId, isRulesListVisible, isInfoPanelVisible, selectedRuleIds, setSelectedRuleIds, importRules, updateRuleOptions } = useRule();
    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = ruleSessions.filter(session => session.status === 'finalized');
    const fileInputRef = useRef(null);
    const finalizedRuleIds = finalizedSessions.map(s => s.id);
    const allSelected = finalizedRuleIds.length > 0 && finalizedRuleIds.every(id => selectedRuleIds.has(id));

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

    const handleImportClick = () => { fileInputRef.current?.click(); };
    const handleImportFile = (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => { importRules(e.target.result); };
            reader.readAsText(file);
        }
        event.target.value = null;
    };
    const clearSelection = () => { setSelectedRuleIds(new Set()); };
    const selectAllFinalized = () => { setSelectedRuleIds(new Set(finalizedRuleIds)); };
    const handleToggleSelect = (ruleId) => {
        setSelectedRuleIds(prev => {
            const newSet = new Set(prev);
            if (newSet.has(ruleId)) { newSet.delete(ruleId); } else { newSet.add(ruleId); }
            return newSet;
        });
    };
    
    // DEĞİŞİKLİK: Eski .app-layout yapısı yerine PanelGroup kullanıyoruz
    return (
        <div className="app-container">
            <TopMenuBar />
            <PanelGroup direction="horizontal" className="app-layout-resizable">
                {/* Sol Panel: Ana İçerik */}
                <Panel defaultSize={65} minSize={30}>
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
                                <div className="rules-toolbar">
                                    <button onClick={handleImportClick}><FileUp size={16}/> Import</button>
                                    <button onClick={handleExport}><FileDown size={16}/> Export</button>
                                    <button onClick={allSelected ? clearSelection : selectAllFinalized}>
                                        {allSelected ? <CheckSquare size={16}/> : <Square size={16}/>}
                                        {allSelected ? 'Seçimi Bırak' : 'Tümünü Seç'}
                                    </button>
                                </div>
                                <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleImportFile} accept=".rules,.txt" />
                                <div className="rules-scroll-wrapper"> 
                                    {finalizedSessions.slice().reverse().map(session => (
                                        <FinalizedRule 
                                            key={session.id} 
                                            session={session} 
                                            isBeingEdited={session.id === editingSourceId}
                                            isSelected={selectedRuleIds.has(session.id)}
                                            onToggleSelect={() => handleToggleSelect(session.id)}
                                        />
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </Panel>
                
                {/* Paneller Arası Ayırıcı */}
                <PanelResizeHandle className="resize-handle" />

                {/* Sağ Panel: Bilgi Paneli (Eğer görünürse) */}
                {isInfoPanelVisible && (
                    <Panel defaultSize={35} minSize={20}>
                        <div className="right-info-panel glass-effect">
                            <InfoPanel />
                        </div>
                    </Panel>
                )}
            </PanelGroup>
        </div>
    );
};

export default Workbench;