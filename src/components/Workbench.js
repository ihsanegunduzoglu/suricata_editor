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
import { FileUp, FileDown, CheckSquare, Square, Save, X, BookmarkPlus, TestTube2 } from 'lucide-react';
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { generateRuleString } from '../utils/ruleGenerator';


const Workbench = () => {
    const {
        ruleSessions,
        editingSourceId,
        isRulesListVisible,
        isInfoPanelVisible,
        setInfoPanelVisibility,
        selectedRuleIds,
        setSelectedRuleIds,
        importRules,
        updateRuleOptions,
        finalizeRule,
        cancelEditing,
        saveUserTemplate,
        setRuleToTest,
        setInfoPanelTab,
    } = useRule();

    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = ruleSessions.filter(session => session.status === 'finalized');
    const fileInputRef = useRef(null);
    const infoPanelRef = useRef(null);
    const finalizedRuleIds = finalizedSessions.map(s => s.id);
    const allSelected = finalizedRuleIds.length > 0 && finalizedRuleIds.every(id => selectedRuleIds.has(id));
    
    const mainContentRef = useRef(null);
    const activeEditorRef = useRef(null);

    useEffect(() => {
        if (editingSourceId && mainContentRef.current && activeEditorRef.current) {
            const mainPanel = mainContentRef.current;
            const editorElement = activeEditorRef.current;
            
            const editorTopOffset = editorElement.offsetTop;
            mainPanel.scrollTo({
                top: editorTopOffset - 24,
                behavior: 'smooth'
            });

            editorElement.classList.remove('highlight-on-edit');
            void editorElement.offsetWidth; 
            editorElement.classList.add('highlight-on-edit');
            
            const animationTimeout = setTimeout(() => {
                editorElement.classList.remove('highlight-on-edit');
            }, 1200);

            return () => clearTimeout(animationTimeout);
        }
    }, [editingSourceId]);

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

    useEffect(() => {
        const panel = infoPanelRef.current;
        if (panel) {
            if (isInfoPanelVisible && panel.isCollapsed()) {
                panel.expand();
            } else if (!isInfoPanelVisible && !panel.isCollapsed()) {
                panel.collapse();
            }
        }
    }, [isInfoPanelVisible]);

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
    
    const handleActiveRuleTest = () => {
        if (!activeSession) return;
        const currentRuleString = generateRuleString(activeSession.headerData, activeSession.ruleOptions);
        if (!currentRuleString || !currentRuleString.includes('sid:')) {
            toast.warn("Test etmek için lütfen önce geçerli bir kural oluşturun.");
            return;
        }
        setRuleToTest(currentRuleString);
        setInfoPanelTab('test_lab');
        toast.info("Aktif kural, test için laboratuvara gönderildi.");
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
    
    return (
        <div className="app-container">
            <TopMenuBar />
            <PanelGroup direction="horizontal" className="app-layout-resizable">
                <Panel defaultSize={65} minSize={50}>
                    <div className="main-content-area glass-effect" ref={mainContentRef}>
                        <div className="active-editor-container" ref={activeEditorRef}>
                            {activeSession ? (
                                <div className="active-editor-wrapper">
                                    <HeaderEditor key={activeSession.id} session={activeSession} />
                                </div>
                            ) : (
                                <p>Yeni kural oluşturuluyor...</p>
                            )}
                            
                            <ValidationPanel />
                        </div>
                        
                        {/* YENİ MERKEZİ EYLEM ÇUBUĞU */}
                        <div className="global-action-bar">
                            <div className="toolbar-group-left">
                                <button onClick={handleImportClick}><FileUp size={16}/> Import</button>
                                <button onClick={handleExport}><FileDown size={16}/> Export</button>
                                <button onClick={allSelected ? clearSelection : selectAllFinalized}>
                                    {allSelected ? <CheckSquare size={16}/> : <Square size={16}/>}
                                    {allSelected ? 'Seçimi Bırak' : 'Tümünü Seç'}
                                </button>
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
                
                <PanelResizeHandle className="resize-handle" />

                <Panel
                    ref={infoPanelRef}
                    defaultSize={35}
                    minSize={15}
                    collapsible={true}
                    collapsedSize={0}
                    order={2}
                    onCollapse={() => {
                        if (isInfoPanelVisible) {
                            setInfoPanelVisibility(false);
                        }
                    }}
                    onExpand={() => {
                        if (!isInfoPanelVisible) {
                            setInfoPanelVisibility(true);
                        }
                    }}
                >
                    <div className="right-info-panel glass-effect">
                        <InfoPanel />
                    </div>
                </Panel>
            </PanelGroup>
        </div>
    );
};

export default Workbench;