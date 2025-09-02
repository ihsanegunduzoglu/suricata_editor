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
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";

const Workbench = () => {
    const {
        ruleSessions,
        editingSourceId,
        isRulesListVisible,
        isInfoPanelVisible,
        appendImportedRules,
        toggleRuleSelected,
        selectAllFinalized,
        clearSelection,
        deleteRulesByIds,
        setInfoPanelVisibility,
        selectedRuleIds,
        setSelectedRuleIds,
        importRules,
        updateRuleOptions,
    } = useRule();

    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = ruleSessions.filter(session => session.status === 'finalized');
    const fileInputRef = useRef(null);
    const finalizedRuleIds = finalizedSessions.map(s => s.id);
    const allSelected = finalizedRuleIds.length > 0 && finalizedRuleIds.every(id => selectedRuleIds.has(id));
    
    // YENİ REFLER
    const mainContentRef = useRef(null); // Kaydırılacak ana panel
    const activeEditorRef = useRef(null); // Kaydırılacak ve vurgulanacak hedef

    // YENİ useEffect: Düzenleme başladığında kaydırma ve vurgu yapar
    useEffect(() => {
        if (editingSourceId && mainContentRef.current && activeEditorRef.current) {
            const mainPanel = mainContentRef.current;
            const editorElement = activeEditorRef.current;
            
            // 1. Kaydırma
            const editorTopOffset = editorElement.offsetTop;
            mainPanel.scrollTo({
                top: editorTopOffset - 24, // 24px'lik bir üst boşluk bırak
                behavior: 'smooth'
            });

            // 2. Vurgu animasyonunu yeniden tetikleme
            editorElement.classList.remove('highlight-on-edit');
            // Tarayıcının class'ın kaldırıldığını fark etmesi için küçük bir "hile"
            void editorElement.offsetWidth; 
            editorElement.classList.add('highlight-on-edit');
            
            // Animasyon bittikten sonra class'ı temizle ki tekrar tetiklenebilsin
            const animationTimeout = setTimeout(() => {
                editorElement.classList.remove('highlight-on-edit');
            }, 1200); // Animasyon süresinden biraz uzun

            return () => clearTimeout(animationTimeout);
        }
    }, [editingSourceId]); // Sadece editingSourceId değiştiğinde çalışır

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
            <PanelGroup direction="horizontal" className="app-layout-resizable">
                {/* DEĞİŞİKLİK BURADA: minSize değeri eklendi */}
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
                )}
            </div>
        </div>
    );
};


export default Workbench;