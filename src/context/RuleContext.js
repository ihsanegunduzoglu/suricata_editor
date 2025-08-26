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
                    const finalizedOnly = parsed.filter(s => s.status === 'finalized');
                    return [...finalizedOnly, createNewSession()];
                }
            }
        } catch (error) {
            console.error("Kaydedilmiş kurallar okunurken bir hata oluştu:", error);
        }
        return [createNewSession()];
    });
    
    const [editingSourceId, setEditingSourceId] = useState(null);
    const [activeTopic, setActiveTopic] = useState(null); // YENİ STATE

    useEffect(() => {
        localStorage.setItem('suricataRuleSessions', JSON.stringify(ruleSessions));
    }, [ruleSessions]);
    
    const getEditorSession = () => ruleSessions.find(s => s.status === 'editing');

    const updateHeaderData = (sessionId, newHeaderData) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, headerData: newHeaderData } : s));
    };

    const updateRuleOptions = (sessionId, newRuleOptions) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ruleOptions: newRuleOptions } : s));
    };
    
    const startEditingRule = (sourceSessionId) => {
        const sourceRule = ruleSessions.find(s => s.id === sourceSessionId);
        const editor = getEditorSession();
        if (!sourceRule || !editor) return;

        const editorWithData = {
            ...editor,
            headerData: { ...sourceRule.headerData },
            ruleOptions: [...sourceRule.ruleOptions] 
        };

        setRuleSessions(prev => prev.map(s => s.id === editor.id ? editorWithData : s));
        setEditingSourceId(sourceSessionId);
        toast.info("Kural düzenleniyor...");
    };

    const cancelEditing = () => {
        const editor = getEditorSession();
        if (!editor) return;
        
        setRuleSessions(prev => prev.map(s => s.id === editor.id ? createNewSession() : s));
        setEditingSourceId(null);
    };
    
    const finalizeRule = (editorSessionId) => {
        const sessionToFinalize = ruleSessions.find(s => s.id === editorSessionId);
        if (!sessionToFinalize) return;

        if (!sessionToFinalize.ruleOptions.some(o => o.keyword === 'msg') || !sessionToFinalize.ruleOptions.some(o => o.keyword === 'sid')) {
            toast.error('Lütfen kurala en azından "msg" ve "sid" seçeneklerini ekleyin.');
            return;
        }
        
        const finalRuleString = generateRuleString(sessionToFinalize.headerData, sessionToFinalize.ruleOptions);

        if (editingSourceId) {
            setRuleSessions(prev => 
                prev.map(s => {
                    if (s.id === editingSourceId) {
                        return { ...sessionToFinalize, id: editingSourceId, status: 'finalized', ruleString: finalRuleString };
                    }
                    if (s.id === editorSessionId) {
                        return createNewSession();
                    }
                    return s;
                })
            );
            toast.success('Kural başarıyla güncellendi!');
        } else {
            const newFinalizedRule = { ...sessionToFinalize, status: 'finalized', ruleString: finalRuleString };
            setRuleSessions(prev => [
                ...prev.filter(s => s.id !== editorSessionId),
                newFinalizedRule,
                createNewSession()
            ]);
            toast.success('Kural başarıyla kaydedildi!');
        }
        setEditingSourceId(null);
    };

    const deleteRule = (sessionId) => {
        setRuleSessions(prev => prev.filter(session => session.id !== sessionId));
        toast.info('Kural silindi.');
    };
    
    const duplicateRule = (sessionToDuplicate) => {
        const editor = getEditorSession();
        const duplicatedDataToEditor = {
            ...editor,
            headerData: { ...sessionToDuplicate.headerData },
            ruleOptions: [...sessionToDuplicate.ruleOptions]
        };
        setRuleSessions(prev => prev.map(s => s.id === editor.id ? duplicatedDataToEditor : s));
        setEditingSourceId(null);
        toast.info('Kural çoğaltıldı ve düzenleyiciye yüklendi.');
    };

    // YENİ FONKSİYON
    const updateActiveTopic = (topic) => {
        setActiveTopic(topic);
    };

    const value = {
        ruleSessions,
        editingSourceId,
        activeTopic, // YENİ
        updateActiveTopic, // YENİ
        updateHeaderData,
        updateRuleOptions,
        finalizeRule,
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