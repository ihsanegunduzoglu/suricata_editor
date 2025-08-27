// src/context/RuleContext.js

// DEĞİŞİKLİK: 'useMemo'yu import ediyoruz
import React, { createContext, useContext, useState, useEffect, useMemo } from 'react';
import { generateRuleString } from '../utils/ruleGenerator';
import { validateRuleForFinalization } from '../utils/ruleValidator';
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
    const [activeTopic, setActiveTopic] = useState(null);
    const [optionsViewActive, setOptionsViewActive] = useState(false);
    const [modifierInfoActive, setModifierInfoActive] = useState(false);
    const [isRulesListVisible, setIsRulesListVisible] = useState(true);
    const [isInfoPanelVisible, setIsInfoPanelVisible] = useState(true);
    const [theme, setTheme] = useState('dark');

    // DEĞİŞİKLİK: activeSession'ı useMemo ile güvenli bir şekilde hesaplıyoruz.
    // ruleSessions tanımsız olsa bile ?. operatörü sayesinde hata vermez.
    const activeSession = useMemo(() => ruleSessions?.find(s => s.status === 'editing'), [ruleSessions]);

    useEffect(() => {
        localStorage.setItem('suricataRuleSessions', JSON.stringify(ruleSessions));
    }, [ruleSessions]);

    const updateHeaderData = (sessionId, newHeaderData) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, headerData: newHeaderData } : s));
    };

    const updateRuleOptions = (sessionId, newRuleOptions) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ruleOptions: newRuleOptions } : s));
    };
    
    const startEditingRule = (sourceSessionId) => {
        const sourceRule = ruleSessions.find(s => s.id === sourceSessionId);
        if (!sourceRule || !activeSession) return;
        const editorWithData = { ...activeSession, headerData: { ...sourceRule.headerData }, ruleOptions: [...sourceRule.ruleOptions] };
        setRuleSessions(prev => prev.map(s => s.id === activeSession.id ? editorWithData : s));
        setEditingSourceId(sourceSessionId);
        toast.info("Kural düzenleniyor...");
    };

    const cancelEditing = () => {
        if (!activeSession) return;
        setRuleSessions(prev => prev.map(s => s.id === activeSession.id ? createNewSession() : s));
        setEditingSourceId(null);
        updateOptionsViewActive(false);
    };
    
    const finalizeRule = (editorSessionId) => {
        const sessionToFinalize = ruleSessions.find(s => s.id === editorSessionId);
        if (!sessionToFinalize) return;

        const finalValidationError = validateRuleForFinalization(sessionToFinalize.headerData, sessionToFinalize.ruleOptions);
        if (finalValidationError) {
            toast.error(finalValidationError);
            return;
        }
        
        const finalRuleString = generateRuleString(sessionToFinalize.headerData, sessionToFinalize.ruleOptions);
        
        if (editingSourceId) {
            setRuleSessions(prev => prev.map(s => {
                if (s.id === editingSourceId) { return { ...sessionToFinalize, id: editingSourceId, status: 'finalized', ruleString: finalRuleString }; }
                if (s.id === editorSessionId) { return createNewSession(); }
                return s;
            }));
            toast.success('Kural başarıyla güncellendi!');
        } else {
            const newFinalizedRule = { ...sessionToFinalize, status: 'finalized', ruleString: finalRuleString };
            setRuleSessions(prev => [...prev.filter(s => s.id !== editorSessionId), newFinalizedRule, createNewSession()]);
            toast.success('Kural başarıyla kaydedildi!');
        }
        setEditingSourceId(null);
        updateOptionsViewActive(false);
    };

    const deleteRule = (sessionId) => {
        setRuleSessions(prev => prev.filter(session => session.id !== sessionId));
        toast.info('Kural silindi.');
    };
    
    const duplicateRule = (sessionToDuplicate) => {
        if (!activeSession) return;
        const duplicatedDataToEditor = { ...activeSession, headerData: { ...sessionToDuplicate.headerData }, ruleOptions: [...sessionToDuplicate.ruleOptions] };
        setRuleSessions(prev => prev.map(s => s.id === activeSession.id ? duplicatedDataToEditor : s));
        setEditingSourceId(null);
        toast.info('Kural çoğaltıldı ve düzenleyiciye yüklendi.');
    };

    const updateActiveTopic = (topic) => setActiveTopic(topic);
    const updateOptionsViewActive = (isActive) => setOptionsViewActive(isActive);
    const updateModifierInfoActive = (isActive) => setModifierInfoActive(isActive);
    const toggleRulesList = () => setIsRulesListVisible(prev => !prev);
    const toggleInfoPanel = () => setIsInfoPanelVisible(prev => !prev);
    const toggleTheme = () => setTheme(prevTheme => (prevTheme === 'dark' ? 'light' : 'dark'));

    const value = {
        ruleSessions,
        editingSourceId,
        activeTopic,
        optionsViewActive,
        modifierInfoActive,
        isRulesListVisible,
        isInfoPanelVisible,
        theme,
        activeSession,
        updateActiveTopic,
        updateOptionsViewActive,
        updateModifierInfoActive,
        toggleRulesList,
        toggleInfoPanel,
        toggleTheme,
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