// src/components/Workbench.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';

const Workbench = () => {
    // DEĞİŞİKLİK: editingSourceId'yi context'ten alıyoruz
    const { ruleSessions, editingSourceId } = useRule();

    const activeSession = ruleSessions.find(session => session.status === 'editing');
    // DEĞİŞİKLİK: Artık tüm kurallar (boş editör hariç) finalized olarak kabul ediliyor
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
                    <div className="workbench-toolbar">
                        <button onClick={handleExport} className="toolbar-button" title="Kuralları .rules dosyası olarak indir">
                            ⇩
                        </button>
                    </div>
                    
                    {activeSession ? (
                        <div className="active-editor-wrapper">
                            <HeaderEditor key={activeSession.id} session={activeSession} />
                        </div>
                    ) : (
                        <p>Yeni kural oluşturuluyor...</p>
                    )}
                </div>

                <div className="finalized-rules-list">
                    {finalizedSessions.reverse().map(session => (
                        <FinalizedRule 
                            key={session.id} 
                            session={session} 
                            // DEĞİŞİKLİK: Bu kuralın düzenlenip düzenlenmediği bilgisini prop olarak geçiyoruz
                            isBeingEdited={session.id === editingSourceId}
                        />
                    ))}
                </div>
            </div>

            <div className="right-info-panel">
                <div className="panel-placeholder">
                    <h3>Bilgi Paneli</h3>
                    <p>Seçili kuralla ilgili detaylar veya diğer yardımcı bilgiler ileride burada gösterilecektir.</p>
                </div>
            </div>
        </div>
    );
};

export default Workbench;