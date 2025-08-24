// src/components/Workbench.js

import React, { useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';

const Workbench = () => {
    const { ruleSessions } = useRule();
    const endOfPageRef = useRef(null);

    // Yeni bir oturum eklendiğinde sayfanın en altına kaydır
    useEffect(() => {
        endOfPageRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [ruleSessions.length]);

    return (
        <div className="workbench-console-container">
            {ruleSessions.map(session => (
                <div key={session.id}>
                    {session.status === 'finalized' ? (
                        <FinalizedRule ruleString={session.ruleString} />
                    ) : (
                        // YENİ DEĞİŞİKLİK: HeaderEditor'ı bir sarmalayıcı div içine aldık
                        <div className="active-editor-wrapper">
                            <HeaderEditor session={session} />
                        </div>
                    )}
                </div>
            ))}
            {/* Bu boş div, sayfanın en altını işaretler ve odaklanmayı sağlar */}
            <div ref={endOfPageRef} />
        </div>
    );
};

export default Workbench;