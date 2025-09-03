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
        } catch (error) {
            console.error("Kaydedilmiş kurallar okunurken bir hata oluştu:", error);
        }
        return [createNewSession()];
    });
    
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
    // Info panel sekmesi: 'info' | 'payload' | 'regex' | 'templates' | 'test_lab'
    const [infoPanelTab, setInfoPanelTab] = useState('info');

    // Odak istekleri (FinalizedRule -> Header/Options fokus için)
    const [headerFocusRequest, setHeaderFocusRequest] = useState(null);
    const [optionFocusRequest, setOptionFocusRequest] = useState(null);

    // DİZİ olarak tutuyoruz (Workbench ile uyumlu)
    const [selectedRuleIds, setSelectedRuleIds] = useState([]);
    // Test Lab entegrasyonu (ihsan2'den)
    const [ruleToTest, setRuleToTest] = useState(null);

    const activeSession = useMemo(() => ruleSessions?.find(s => s.status === 'editing'), [ruleSessions]);

    useEffect(() => {
        localStorage.setItem('suricataRuleSessions', JSON.stringify(ruleSessions));
    }, [ruleSessions]);

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
        setSelectedRuleIds([]); // dizi
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
        setSelectedRuleIds(prev => prev.filter(id => id !== sessionId)); // dizi
        toast.info('Kural silindi.');
    };
    
    const deleteRulesByIds = (ids) => {
        if (!Array.isArray(ids) || ids.length === 0) return;
        setRuleSessions(prev => prev.filter(s => !(s.status === 'finalized' && ids.includes(s.id))));
        setSelectedRuleIds(prev => prev.filter(id => !ids.includes(id))); // dizi
        toast.info(`${ids.length} kural silindi.`);
    };
    
    // Çoğalt: finalized kural olarak ekle (senin davranışın)
    const duplicateRule = (sessionToDuplicate) => {
        if (!sessionToDuplicate) return;
        const clonedHeader = { ...sessionToDuplicate.headerData };
        const clonedOptions = (sessionToDuplicate.ruleOptions || []).map(opt => ({
            ...opt,
            modifiers: opt.modifiers ? { ...opt.modifiers } : undefined,
        }));
        const newId = uuidv4();
        const newRuleString = generateRuleString(clonedHeader, clonedOptions);
        const duplicatedFinalized = {
            id: newId,
            status: 'finalized',
            headerData: clonedHeader,
            ruleOptions: clonedOptions,
            ruleString: newRuleString,
        };
        setRuleSessions(prev => {
            const finalized = prev.filter(s => s.status === 'finalized');
            const editing = prev.find(s => s.status === 'editing') || createNewSession();
            return [...finalized, duplicatedFinalized, editing];
        });
        toast.success('Kural başarıyla çoğaltıldı.');
    };
    
    // Metinden import
    const importRules = (rulesString) => {
        const lines = rulesString.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
        if (lines.length === 0) {
            toast.warn('İçe aktarılacak geçerli kural bulunamadı.');
            return;
        }
        const newSessions = lines.map(line => ({
            id: uuidv4(),
            status: 'finalized',
            ruleString: line.trim(),
            headerData: {},
            ruleOptions: [],
        }));
        
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
                ruleOptions: JSON.parse(JSON.stringify(activeSession.ruleOptions))
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
    
    const getNextSid = () => {
        const finalizedSessions = ruleSessions.filter(s => s.status === 'finalized');
        if (finalizedSessions.length === 0) {
            return 1000001;
        }

        const highestSid = finalizedSessions.reduce((maxSid, session) => {
            const match = session.ruleString.match(/sid\s*:\s*(\d+)/);
            if (match && match[1]) {
                const sid = parseInt(match[1], 10);
                return sid > maxSid ? sid : maxSid;
            }
            return maxSid;
        }, 1000000);

        return highestSid + 1;
    };

    const updateActiveTopic = (topic) => setActiveTopic(topic);
    const updateOptionsViewActive = (isActive) => setOptionsViewActive(isActive);
    const updateModifierInfoActive = (isActive) => setModifierInfoActive(isActive);
    const updateMitreInfo = (info) => setMitreInfo(info);
    const toggleRulesList = () => setIsRulesListVisible(prev => !prev);
    const toggleInfoPanel = () => setIsInfoPanelVisible(prev => !prev);
    const toggleTheme = () => setTheme(prev => (prev === 'light' ? 'dark' : 'light'));
    const setInfoPanelVisibility = (isVisible) => setIsInfoPanelVisible(isVisible);

    // Focus yardımcıları
    const focusHeaderField = (label, forceOpenSuggestions = false, initialValue = undefined) => {
        setOptionsViewActive(false);
        setHeaderFocusRequest({ label, forceOpen: !!forceOpenSuggestions, value: initialValue });
    };
    const clearHeaderFocusRequest = () => setHeaderFocusRequest(null);

    const focusOption = (keyword, expandDetails = false, preferredIndex = null) => {
        setOptionsViewActive(true);
        setOptionFocusRequest({ keyword, expandDetails: !!expandDetails, index: preferredIndex });
    };
    const clearOptionFocusRequest = () => setOptionFocusRequest(null);

    // Sunucudan parse edilen kuralların eklenmesi
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

    // Dizi tabanlı seçim yardımcıları (Workbench ile uyumlu)
    const toggleRuleSelected = (ruleId) => {
        setSelectedRuleIds(prev => (
            prev.includes(ruleId) ? prev.filter(id => id !== ruleId) : [...prev, ruleId]
        ));
    };
    const selectAllFinalized = () => {
        const allFinalizedIds = ruleSessions.filter(s => s.status === 'finalized').map(s => s.id);
        setSelectedRuleIds(allFinalizedIds);
    };
    const clearSelection = () => setSelectedRuleIds([]);

    const value = {
        ruleSessions,
        userTemplates,
        editingSourceId,
        activeTopic,
        optionsViewActive,
        modifierInfoActive,
        isRulesListVisible,
        isInfoPanelVisible,
        theme,
        selectedRuleIds,
        setSelectedRuleIds,
        headerFocusRequest,
        optionFocusRequest,
        activeSession,
        mitreInfo,
        importRules,
        updateMitreInfo,
        updateActiveTopic,
        updateOptionsViewActive,
        updateModifierInfoActive,
        toggleRulesList,
        toggleInfoPanel,
        toggleTheme,
        setInfoPanelVisibility,
        infoPanelTab,
        setInfoPanelTab,
        focusHeaderField,
        clearHeaderFocusRequest,
        focusOption,
        clearOptionFocusRequest,
        appendImportedRules,
        toggleRuleSelected,
        selectAllFinalized,
        clearSelection,
        updateHeaderData,
        updateRuleOptions,
        finalizeRule,
        deleteRule,
        deleteRulesByIds,
        duplicateRule,
        startEditingRule,
        cancelEditing,
        applyTemplate,
        saveUserTemplate,
        deleteUserTemplate,
        getNextSid,
        ruleToTest,
        setRuleToTest,
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};