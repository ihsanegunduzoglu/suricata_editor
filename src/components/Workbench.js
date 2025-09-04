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
import { FileUp, FileDown, CheckSquare, Square, Save, X, BookmarkPlus, TestTube2, Trash2 } from 'lucide-react';
import { generateRuleString } from '../utils/ruleGenerator';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';

const Workbench = () => {

    const {
        ruleSessions,
        editingSourceId,
        isRulesListVisible,
        isInfoPanelVisible,
        appendImportedRules,
        selectedRuleIds,
        toggleRuleSelected,
        selectAllFinalized,
        clearSelection,
        deleteRulesByIds,
        updateRuleOptions,
        theme,
        finalizeRule,
        cancelEditing,
        saveUserTemplate,
        setRuleToTest,
        setInfoPanelTab,
        setInfoPanelVisibility,
    } = useRule();

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
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce en az bir kural seçin.');
            return;
        }
        const rulesToExport = finalizedSessions.filter(session => selectedRuleIds.includes(session.id));
        if (rulesToExport.length === 0) {
            toast.warn('Seçili kurallar bulunamadı.');
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

    const handleActiveRuleTest = () => {
        if (!activeSession) return;
        const currentRuleString = generateRuleString(activeSession.headerData, activeSession.ruleOptions);
        if (!currentRuleString || !currentRuleString.includes('sid:')) {
            toast.warn('Test etmek için lütfen önce geçerli bir kural oluşturun.');
            return;
        }
        setRuleToTest(currentRuleString);
        setInfoPanelTab('test_lab');
        toast.info('Aktif kural, test için laboratuvara gönderildi.');
    };

    const handleImportClick = () => { fileInputRef.current?.click(); };

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
            if (fileInputRef.current) fileInputRef.current.value = '';
        }
    };

    return (
        <div className="app-container">
            <TopMenuBar />
            <div className="app-layout-resizable">
                <PanelGroup direction="horizontal" className="panels-root" style={{ height: '100%' }}>
                    <Panel defaultSize={65} minSize={45}>
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

                            <div className="global-action-bar">
                                <div className="toolbar-group-left">
                                    <button onClick={handleImportClick}><FileUp size={16}/> Import</button>
                                    <button onClick={handleExport}><FileDown size={16}/> Export</button>
                                    <button onClick={() => { allSelected ? clearSelection() : selectAllFinalized(); }}>
                                        {allSelected ? <CheckSquare size={16}/> : <Square size={16}/>} {allSelected ? 'Seçimi Bırak' : 'Tümünü Seç'}
                                    </button>
                                    <button onClick={handleBulkDelete}><Trash2 size={16}/> Sil</button>
                                </div>

                                <div className='action-bar-spacer'></div>

                                <div className="toolbar-group-right">
                                    <button onClick={() => activeSession && finalizeRule(activeSession.id)}><Save size={16}/> Kaydet</button>
                                    <button onClick={cancelEditing}><X size={16}/> İptal Et</button>
                                    <button onClick={saveUserTemplate}><BookmarkPlus size={16}/> Şablon Yap</button>
                                    <button onClick={handleActiveRuleTest}><TestTube2 size={16}/> Test Et</button>
                                </div>
                            </div>

                            {isRulesListVisible && (
                                <div className="finalized-rules-list">
                                    <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleImportFile} accept=".rules,.txt" />
                                    <div
                                        className="rules-scroll-wrapper"
                                        ref={rulesScrollRef}
                                        onScroll={(e) => {
                                            const t = e.currentTarget.scrollTop || 0;
                                            const next = Math.max(0.2, 1 - t / 300);
                                            setToolbarOpacity(next);
                                        }}
                                    >
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
                    </Panel>

                    <PanelResizeHandle className="resize-handle" />

                    <Panel defaultSize={35} minSize={15} collapsible collapsedSize={0}
                        onCollapse={() => { if (isInfoPanelVisible) setInfoPanelVisibility(false); }}
                        onExpand={() => { if (!isInfoPanelVisible) setInfoPanelVisibility(true); }}
                    >
                        <div className="right-info-panel glass-effect">
                            <InfoPanel />
                        </div>
                    </Panel>
                </PanelGroup>
            </div>
        </div>

    );
};

export default Workbench;