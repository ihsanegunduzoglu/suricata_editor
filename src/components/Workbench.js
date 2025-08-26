// src/components/Workbench.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel'; // YENİ: InfoPanel'i içeri aktar

const Workbench = () => {
    const { ruleSessions, editingSourceId } = useRule();

    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = ruleSessions.filter(session => session.status === 'finalized');

    const handleExport = () => {
        const finalizedRules = finalizedSessions
            .map(session => session.ruleString)
            .join('\n\n');

        if (!finalizedRules || finalizedRules.length === 0) {
            toast.warn('Dışa aktarılacak tamamlanmış bir kural bulunmuyor.');
            return;
        }

        const blob = new Blob([finalizedRules], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'custom.rules';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };
    
    return (
        <div className="app-layout">
            <div className="main-content-area">
                <div className="active-editor-container">
                    {activeSession ? (
                        <div className="active-editor-wrapper">
                            <HeaderEditor key={activeSession.id} session={activeSession} />
                        </div>
                    ) : (
                        <p>Yeni kural oluşturuluyor...</p>
                    )}
                </div>

                <div className="finalized-rules-list">
                    <button 
                        onClick={handleExport} 
                        className="toolbar-button export-button"
                        title="Kuralları .rules dosyası olarak indir"
                    >
                        ⇩
                    </button>
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
            </div>

            <div className="right-info-panel">
                <InfoPanel /> {/* Placeholder yerine yeni bileşenimizi koyuyoruz */}
            </div>
        </div>
    );
};

export default Workbench;