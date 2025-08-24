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
        const sessionToEdit = ruleSessions.find(s => s.id === sessionId);
        if (!sessionToEdit) return;

        setEditingSessionId(sessionId);
        setRuleSessions(prev => [
            ...prev.filter(s => s.status === 'finalized'),
            {
                ...sessionToEdit,
                status: 'editing'
            }
        ]);
    };
    
    const cancelEditing = () => {
        setEditingSessionId(null);
        setRuleSessions(prev => [
            ...prev.filter(s => s.status === 'finalized'),
            createNewSession()
        ]);
    };

    const finalizeCurrentRule = () => {
        const currentSession = ruleSessions[ruleSessions.length - 1];
        if (!currentSession.ruleOptions.some(o => o.keyword === 'msg') || !currentSession.ruleOptions.some(o => o.keyword === 'sid')) {
            toast.error('Lütfen kurala en azından "msg" ve "sid" seçeneklerini ekleyin.');
            return;
        }
        const finalRuleString = generateRuleString(currentSession.headerData, currentSession.ruleOptions);

        if (editingSessionId) {
            setRuleSessions(prev => {
                const updatedRule = {
                    ...currentSession,
                    id: editingSessionId,
                    status: 'finalized',
                    ruleString: finalRuleString
                };
                const sessionsWithUpdate = prev
                    .slice(0, -1)
                    .map(s => s.id === editingSessionId ? updatedRule : s);
                return [
                    ...sessionsWithUpdate,
                    createNewSession()
                ];
            });
            setEditingSessionId(null);
            toast.success('Kural başarıyla güncellendi!');
        } else {
            setRuleSessions(prev => [
                ...prev.slice(0, -1),
                { ...currentSession, status: 'finalized', ruleString: finalRuleString },
                createNewSession()
            ]);
            toast.success('Kural başarıyla kaydedildi!');
        }
    };

    const deleteRule = (sessionId) => {
        if (ruleSessions.length === 1 && ruleSessions[0].id === sessionId) {
            setRuleSessions([createNewSession()]);
        } else {
            setRuleSessions(prev => prev.filter(session => session.id !== sessionId));
        }
        toast.info('Kural silindi.');
    };
    
    const duplicateRule = (sessionToDuplicate) => {
        setRuleSessions(prev => [
            ...prev.filter(s => s.status === 'finalized'),
            {
                ...sessionToDuplicate,
                id: uuidv4(),
                status: 'editing',
                ruleString: '',
            }
        ]);
        toast.info('Kural çoğaltıldı ve editöre yüklendi.');
    };

    const value = {
        ruleSessions,
        editingSessionId,
        updateHeaderData,
        updateRuleOptions,
        finalizeCurrentRule,
        deleteRule,
        duplicateRule,
        startEditingRule,
        cancelEditing,
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};