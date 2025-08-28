// src/components/Workbench.js

import React, { useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel';
import TopMenuBar from './TopMenuBar';
<<<<<<< HEAD
import ValidationPanel from './ValidationPanel';
import { optionsDictionary } from '../data/optionsDictionary'; // YENİ: Protokol kontrolü için import edildi
=======
import ValidationPanel from './ValidationPanel'; 
>>>>>>> ddd6b3f67e748b35ddbd80ec4c8bfc55bf3a6776

const Workbench = () => {
    // YENİ: updateRuleOptions fonksiyonunu context'ten alıyoruz
    const { ruleSessions, editingSourceId, isRulesListVisible, isInfoPanelVisible, updateRuleOptions } = useRule();
    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = ruleSessions.filter(session => session.status === 'finalized');

    // YENİ: Protokol değişikliğini takip etmek için yan etki (side effect)
    const prevProtocolRef = useRef();
    useEffect(() => {
        if (!activeSession) return;

        const currentProtocol = activeSession.headerData.Protocol;

        // Sadece protokol gerçekten değiştiğinde ve bu ilk render olmadığında çalış
        if (prevProtocolRef.current && currentProtocol !== prevProtocolRef.current) {
            const originalOptions = activeSession.ruleOptions;
            
            const cleanedOptions = originalOptions.filter(option => {
                const optionInfo = optionsDictionary[option.keyword];
                if (!optionInfo?.dependsOnProtocol) {
                    return true; // Bağımlılık yoksa koru
                }
                return optionInfo.dependsOnProtocol === currentProtocol.toLowerCase(); // Varsa ve eşleşiyorsa koru
            });

            const removedCount = originalOptions.length - cleanedOptions.length;
            if (removedCount > 0) {
                updateRuleOptions(activeSession.id, cleanedOptions);
                toast.warn(`${removedCount} adet seçenek, yeni protokolle uyumsuz olduğu için kaldırıldı.`);
            }
        }

        // Mevcut protokolü, bir sonraki kontrol için referansta sakla
        prevProtocolRef.current = currentProtocol;

    }, [activeSession?.headerData.Protocol, activeSession?.id, activeSession?.ruleOptions, updateRuleOptions]);


    const handleExport = () => {
<<<<<<< HEAD
        const finalizedRules = finalizedSessions
=======
       
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce en az bir kural seçin.');
            return;
        }

        const source = finalizedSessions.filter(s => selectedRuleIds.includes(s.id));
        const finalizedRules = source
>>>>>>> ddd6b3f67e748b35ddbd80ec4c8bfc55bf3a6776
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
<<<<<<< HEAD
        a.download = 'custom.rules';
=======
        a.download = 'selected.rules';
>>>>>>> ddd6b3f67e748b35ddbd80ec4c8bfc55bf3a6776
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
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
<<<<<<< HEAD
                            <button 
                                onClick={handleExport} 
                                className="toolbar-button export-button"
                                title="Kuralları .rules dosyası olarak indir"
                            >
                                ⇩
                            </button>
=======
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
                                    onClick={() => { allSelected ? clearSelection() : selectAllFinalized(); }}
                                    className="toolbar-button select-all-button"
                                    title={allSelected ? "Tüm tikleri kaldır" : "Tümünü seç"}
                                >
                                    ✓
                                </button>
                            </div>
                            <input type="file" ref={fileInputRef} accept=".rules,.txt" style={{ display: 'none' }} onChange={handleImportFile} />
>>>>>>> ddd6b3f67e748b35ddbd80ec4c8bfc55bf3a6776
                            <div className="rules-scroll-wrapper"> 
                                {finalizedSessions.reverse().map(session => (
                                    <FinalizedRule 
                                        key={session.id} 
                                        session={session} 
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