// src/context/RuleContext.js

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
        } catch (error) { console.error("Kaydedilmiş kurallar okunurken bir hata oluştu:", error); }
        return [createNewSession()];
    });
    
    // YENİ STATE: Kullanıcının kaydettiği şablonları tutar
    const [userTemplates, setUserTemplates] = useState(() => {
        try {
            const savedTemplates = localStorage.getItem('suricataUserTemplates');
            return savedTemplates ? JSON.parse(savedTemplates) : [];
        } catch (error) {
            console.error("Kullanıcı şablonları okunurken bir hata oluştu:", error);
            return [];
        }
    });

    const [editingSourceId, setEditingSourceId] = useState(null);
    const [activeTopic, setActiveTopic] = useState(null);
    const [optionsViewActive, setOptionsViewActive] = useState(false);
    const [modifierInfoActive, setModifierInfoActive] = useState(false);
    const [isRulesListVisible, setIsRulesListVisible] = useState(true);
    const [isInfoPanelVisible, setIsInfoPanelVisible] = useState(true);
    const [theme, setTheme] = useState('dark');
    const [mitreInfo, setMitreInfo] = useState(null);
    const [selectedRuleIds, setSelectedRuleIds] = useState(new Set());
    const [infoPanelTab, setInfoPanelTab] = useState('info');

    const activeSession = useMemo(() => ruleSessions?.find(s => s.status === 'editing'), [ruleSessions]);

    useEffect(() => {
        localStorage.setItem('suricataRuleSessions', JSON.stringify(ruleSessions));
    }, [ruleSessions]);

    // YENİ useEffect: Kullanıcı şablonları değiştiğinde localStorage'ı günceller
    useEffect(() => {
        localStorage.setItem('suricataUserTemplates', JSON.stringify(userTemplates));
    }, [userTemplates]);


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
        setMitreInfo(null);
        setSelectedRuleIds(new Set());
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
        setSelectedRuleIds(prev => { const newSet = new Set(prev); newSet.delete(sessionId); return newSet; });
        toast.info('Kural silindi.');
    };
    
    const duplicateRule = (sessionToDuplicate) => {
        if (!activeSession) return;
        const duplicatedDataToEditor = { ...activeSession, headerData: { ...sessionToDuplicate.headerData }, ruleOptions: [...sessionToDuplicate.ruleOptions] };
        setRuleSessions(prev => prev.map(s => s.id === activeSession.id ? duplicatedDataToEditor : s));
        setEditingSourceId(null);
        setSelectedRuleIds(new Set());
        toast.info('Kural çoğaltıldı ve düzenleyiciye yüklendi.');
    };
    
    const importRules = (rulesString) => {
        const lines = rulesString.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
        if (lines.length === 0) {
            toast.warn('İçe aktarılacak geçerli kural bulunamadı.');
            return;
        }
        const newSessions = lines.map(line => ({ id: uuidv4(), status: 'finalized', ruleString: line.trim(), headerData: {}, ruleOptions: [] }));
        setRuleSessions(prev => {
            const editing = prev.find(s => s.status === 'editing');
            const finalized = prev.filter(s => s.status === 'finalized');
            return [editing, ...newSessions, ...finalized];
        });
        toast.success(`${newSessions.length} kural başarıyla içe aktarıldı.`);
    };

    const applyTemplate = (templateData) => {
        if (!activeSession) return;
        const sessionWithTemplate = { 
            ...activeSession, 
            headerData: { ...templateData.headerData }, 
            ruleOptions: [...templateData.ruleOptions] 
        };
        setRuleSessions(prev => prev.map(s => s.id === activeSession.id ? sessionWithTemplate : s));
        setEditingSourceId(null);
        updateOptionsViewActive(false);
        setInfoPanelTab('info');
        toast.info('Şablon kural editörüne yüklendi!');
    };
    
    // YENİ FONKSİYONLAR
    const saveUserTemplate = () => {
        if (!activeSession || (!Object.values(activeSession.headerData).some(v => v) && activeSession.ruleOptions.length === 0)) {
            toast.warn("Kaydedilecek bir şablon oluşturmak için önce editörü doldurun.");
            return;
        }
        
        const name = prompt("Şablon için bir ad girin:");
        if (!name || name.trim() === '') {
            toast.error("Geçerli bir şablon adı girmelisiniz.");
            return;
        }
        
        const description = prompt("Şablon için kısa bir açıklama girin (opsiyonel):");

        const newTemplate = {
            id: uuidv4(),
            name,
            description: description || "Kullanıcı tarafından oluşturulmuş şablon.",
            isUserDefined: true,
            data: {
                headerData: { ...activeSession.headerData },
                ruleOptions: JSON.parse(JSON.stringify(activeSession.ruleOptions)) // Derin kopya
            }
        };

        setUserTemplates(prev => [...prev, newTemplate]);
        toast.success(`"${name}" şablonu başarıyla kaydedildi!`);
    };

    const deleteUserTemplate = (templateId) => {
        if (window.confirm("Bu şablonu silmek istediğinizden emin misiniz?")) {
            setUserTemplates(prev => prev.filter(t => t.id !== templateId));
            toast.info("Şablon silindi.");
        }
    };


    const updateActiveTopic = (topic) => setActiveTopic(topic);
    const updateOptionsViewActive = (isActive) => setOptionsViewActive(isActive);
    const updateModifierInfoActive = (isActive) => setModifierInfoActive(isActive);
    const updateMitreInfo = (info) => setMitreInfo(info);
    const toggleRulesList = () => setIsRulesListVisible(prev => !prev);
    const setInfoPanelVisibility = (isVisible) => setIsInfoPanelVisible(isVisible);
    const toggleInfoPanel = () => setIsInfoPanelVisible(prev => !prev);
    const toggleTheme = () => setTheme(prevTheme => (prevTheme === 'dark' ? 'light' : 'dark'));

    const value = {
        ruleSessions, userTemplates, editingSourceId, activeTopic, optionsViewActive,
        modifierInfoActive, isRulesListVisible, isInfoPanelVisible, theme,
        activeSession, mitreInfo, selectedRuleIds, setSelectedRuleIds,
        importRules, infoPanelTab, setInfoPanelTab,
        updateMitreInfo, updateActiveTopic, updateOptionsViewActive,
        updateModifierInfoActive, toggleRulesList, toggleInfoPanel,
        setInfoPanelVisibility,
        toggleTheme, updateHeaderData, updateRuleOptions, finalizeRule,
        deleteRule, duplicateRule, startEditingRule, cancelEditing,
        applyTemplate, saveUserTemplate, deleteUserTemplate,
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};