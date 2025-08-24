// src/components/Workbench.js

import React, { useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify'; // YENİ: toast import'u

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
            // DEĞİŞİKLİK: alert() yerine toast.warn() kullanıyoruz.
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
        <div className="workbench-console-container">
            <div className="workbench-toolbar">
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