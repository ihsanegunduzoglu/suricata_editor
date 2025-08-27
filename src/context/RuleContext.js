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
    const [activeTopic, setActiveTopic] = useState(null);
    const [optionsViewActive, setOptionsViewActive] = useState(false);
    const [modifierInfoActive, setModifierInfoActive] = useState(false); // YENİ STATE
    const [isRulesListVisible, setIsRulesListVisible] = useState(true);
    const [isInfoPanelVisible, setIsInfoPanelVisible] = useState(true);
    const [theme, setTheme] = useState('dark');
    const [selectedRuleIds, setSelectedRuleIds] = useState([]);

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
        updateOptionsViewActive(false);
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

    const updateActiveTopic = (topic) => {
        // Sadece açıkça verilen konuya ayarla; dış tıklamalar artık sıfırlamayacak
        setActiveTopic(topic);
    };

    const updateOptionsViewActive = (isActive) => {
        setOptionsViewActive(isActive);
    };

    const updateModifierInfoActive = (isActive) => {
        setModifierInfoActive(isActive);
    };

    const toggleRulesList = () => {
        setIsRulesListVisible(prev => !prev);
    };

    const toggleInfoPanel = () => {
        setIsInfoPanelVisible(prev => !prev);
    };

    const toggleTheme = () => {
        setTheme(prev => (prev === 'light' ? 'dark' : 'light'));
    };

    const appendImportedRules = (specs) => {
        if (!Array.isArray(specs) || specs.length === 0) return;
        const newFinalized = specs.map(spec => {
            const id = uuidv4();
            const status = 'finalized';
            const headerData = spec.headerData || { 'Action': '', 'Protocol': '', 'Source IP': '', 'Source Port': '', 'Direction': '', 'Destination IP': '', 'Destination Port': '' };
            const ruleOptions = Array.isArray(spec.ruleOptions) ? spec.ruleOptions : [];
            const ruleString = generateRuleString(headerData, ruleOptions);
            return { id, status, headerData, ruleOptions, ruleString };
        });
        setRuleSessions(prev => {
            const existingFinalized = prev.filter(s => s.status === 'finalized');
            const existingEditing = prev.find(s => s.status === 'editing') || createNewSession();
            return [...existingFinalized, ...newFinalized, existingEditing];
        });
        toast.success(`${specs.length} kural içe aktarıldı.`);
    };

    const toggleRuleSelected = (ruleId) => {
        setSelectedRuleIds(prev => prev.includes(ruleId)
            ? prev.filter(id => id !== ruleId)
            : [...prev, ruleId]
        );
    };

    const selectAllFinalized = () => {
        const allFinalizedIds = ruleSessions.filter(s => s.status === 'finalized').map(s => s.id);
        setSelectedRuleIds(allFinalizedIds);
    };

    const clearSelection = () => setSelectedRuleIds([]);

    const value = {
        ruleSessions,
        editingSourceId,
        activeTopic,
        optionsViewActive,
        modifierInfoActive, // YENİ
        isRulesListVisible,
        isInfoPanelVisible,
        theme,
        selectedRuleIds,
        updateActiveTopic,
        updateOptionsViewActive,
        updateModifierInfoActive, // YENİ
        toggleRulesList,
        toggleInfoPanel,
        toggleTheme,
        appendImportedRules,
        toggleRuleSelected,
        selectAllFinalized,
        clearSelection,
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