// src/components/Workbench.js

import React, { useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';

const Workbench = () => {
    const { ruleSessions } = useRule();
    const endOfPageRef = useRef(null);

    useEffect(() => {
        endOfPageRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [ruleSessions.length]);
    
    const handleExport = () => {
        const finalizedRules = ruleSessions
            .filter(session => session.status === 'finalized')
            .map(session => session.ruleString)
            .join('\n\n');

        if (!finalizedRules) {
            alert('Dışa aktarılacak tamamlanmış bir kural bulunmuyor.');
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
        <div className="workbench-console-container">
            {/* DEĞİŞİKLİK: Toolbar'dan başlık kaldırıldı */}
            <div className="workbench-toolbar">
                {/* DEĞİŞİKLİK: Buton daha küçük ve ikonlu olacak şekilde değiştirildi */}
                <button onClick={handleExport} className="toolbar-button" title="Kuralları .rules dosyası olarak indir">
                    ⇩
                </button>
            </div>

            {ruleSessions.map(session => (
                <div key={session.id}>
                    {session.status === 'finalized' ? (
                        <FinalizedRule session={session} />
                    ) : (
                        <div className="active-editor-wrapper">
                            {/* DÜZELTME: Yanlışlıkla silinen aktif editörü gösteren bu satır geri eklendi */}
                            <HeaderEditor session={session} />
                        </div>
                    )}
                </div>
            ))}
            <div ref={endOfPageRef} />
        </div>
    );
};

export default Workbench;