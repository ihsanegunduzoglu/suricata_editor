// src/context/RuleContext.js

import React, { createContext, useContext, useState, useEffect } from 'react';
import { generateRuleString } from '../utils/ruleGenerator';
import { v4 as uuidv4 } from 'uuid';
import { toast } from 'react-toastify';

const createNewSession = () => ({
    id: uuidv4(),
    status: 'editing',
    headerData: { 'Action': '', 'Protocol': '', 'Source IP': '', 'Source Port': '', 'Direction': '', 'Destination IP': '', 'Destination Port': '' },
    ruleOptions: [],
    ruleString: ''
});

const RuleContext = createContext();
export const useRule = () => useContext(RuleContext);

export const RuleProvider = ({ children }) => {
    const [ruleSessions, setRuleSessions] = useState(() => {
        try {
            const savedSessions = localStorage.getItem('suricataRuleSessions');
            if (savedSessions) {
                const parsed = JSON.parse(savedSessions);
                if (Array.isArray(parsed) && parsed.length > 0) {
                    return parsed;
                }
            }
        } catch (error) {
            console.error("Kaydedilmiş kurallar okunurken bir hata oluştu:", error);
        }
        return [createNewSession()];
    });
    
    const [editingSessionId, setEditingSessionId] = useState(null);

    useEffect(() => {
        localStorage.setItem('suricataRuleSessions', JSON.stringify(ruleSessions));
    }, [ruleSessions]);

    const updateHeaderData = (sessionId, newHeaderData) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, headerData: newHeaderData } : s));
    };

    const updateRuleOptions = (sessionId, newRuleOptions) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ruleOptions: newRuleOptions } : s));
    };
    
    const startEditingRule = (sessionId) => {
        setRuleSessions(prev =>
            prev
                .filter(s => {
                    const isNewAndEmpty = s.status === 'editing' && s.ruleOptions.length === 0 && s.headerData.Action === '';
                    return !isNewAndEmpty;
                })
                .map(s => ({
                    ...s,
                    status: s.id === sessionId ? 'editing' : 'finalized'
                }))
        );
    };
    
    const finalizeRule = (sessionId) => {
        const sessionToFinalize = ruleSessions.find(s => s.id === sessionId);
        if (!sessionToFinalize) return;

        if (!sessionToFinalize.ruleOptions.some(o => o.keyword === 'msg') || !sessionToFinalize.ruleOptions.some(o => o.keyword === 'sid')) {
            toast.error('Lütfen kurala en azından "msg" ve "sid" seçeneklerini ekleyin.');
            return;
        }
        
        const finalRuleString = generateRuleString(sessionToFinalize.headerData, sessionToFinalize.ruleOptions);

        setRuleSessions(prev => [
            ...prev.map(s => 
                s.id === sessionId 
                    ? { ...s, status: 'finalized', ruleString: finalRuleString } 
                    : s
            ),
            createNewSession()
        ]);
        toast.success('Kural başarıyla kaydedildi/güncellendi!');
    };

    const deleteRule = (sessionId) => {
        if (ruleSessions.length <= 1) {
            setRuleSessions([createNewSession()]);
        } else {
            setRuleSessions(prev => prev.filter(session => session.id !== sessionId));
        }
        toast.info('Kural silindi.');
    };
    
    // TAMAMEN YENİLENMİŞ duplicateRule FONKSİYONU
    const duplicateRule = (sessionToDuplicate) => {
        setRuleSessions(prev => [
            // 1. Mevcut listeden, o anki boş editörü ('editing' durumunda olanı) çıkar.
            ...prev.filter(s => s.status === 'finalized'),
            // 2. En sona, kopyalanan kuralın verileriyle yeni bir 'editing' oturumu ekle.
            {
                ...sessionToDuplicate,
                id: uuidv4(),
                status: 'editing',
                ruleString: '',
            }
        ]);
        toast.info('Kural çoğaltıldı ve yeni editöre yüklendi.');
    };

    const value = {
        ruleSessions,
        updateHeaderData,
        updateRuleOptions,
        finalizeRule,
        deleteRule,
        duplicateRule,
        startEditingRule,
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};