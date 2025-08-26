// src/context/RuleContext.js

import React, { createContext, useContext, useState, useEffect } from 'react';
import { generateRuleString } from '../utils/ruleGenerator';
import { v4 as uuidv4 } from 'uuid';
import { toast } from 'react-toastify';

const createNewSession = () => ({
    id: uuidv4(),
    status: 'editing', // Sadece yeni, boş editör bu statüde olacak
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
                // YENİ KONTROL: Tüm kuralların 'finalized' olduğundan emin ol, bir tane 'editing' ekle
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
    
    // YENİ: Hangi kuralın düzenlendiğini ID ile takip eden state
    const [editingSourceId, setEditingSourceId] = useState(null);

    useEffect(() => {
        localStorage.setItem('suricataRuleSessions', JSON.stringify(ruleSessions));
    }, [ruleSessions]);
    
    // Aktif editör oturumunu bulmak için bir yardımcı fonksiyon
    const getEditorSession = () => ruleSessions.find(s => s.status === 'editing');

    const updateHeaderData = (sessionId, newHeaderData) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, headerData: newHeaderData } : s));
    };

    const updateRuleOptions = (sessionId, newRuleOptions) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ruleOptions: newRuleOptions } : s));
    };
    
    // YENİ MANTIK: Kuralı listeden silmez, verilerini editöre kopyalar
    const startEditingRule = (sourceSessionId) => {
        const sourceRule = ruleSessions.find(s => s.id === sourceSessionId);
        const editor = getEditorSession();
        if (!sourceRule || !editor) return;

        const editorWithData = {
            ...editor, // editor'ün kendi ID'sini koru
            headerData: { ...sourceRule.headerData },
            ruleOptions: [...sourceRule.ruleOptions] 
        };

        setRuleSessions(prev => prev.map(s => s.id === editor.id ? editorWithData : s));
        setEditingSourceId(sourceSessionId); // Hangi kuralı düzenlediğimizi işaretle
        toast.info("Kural düzenleniyor...");
    };

    // YENİ: Düzenlemeyi iptal etme fonksiyonu
    const cancelEditing = () => {
        const editor = getEditorSession();
        if (!editor) return;
        
        // Editörü temizle
        setRuleSessions(prev => prev.map(s => s.id === editor.id ? createNewSession() : s));
        setEditingSourceId(null); // Düzenleme modundan çık
    };
    
    // YENİ MANTIK: Kaydetme işlemi, yeni kural mı yoksa güncelleme mi olduğunu kontrol eder
    const finalizeRule = (editorSessionId) => {
        const sessionToFinalize = ruleSessions.find(s => s.id === editorSessionId);
        if (!sessionToFinalize) return;

        if (!sessionToFinalize.ruleOptions.some(o => o.keyword === 'msg') || !sessionToFinalize.ruleOptions.some(o => o.keyword === 'sid')) {
            toast.error('Lütfen kurala en azından "msg" ve "sid" seçeneklerini ekleyin.');
            return;
        }
        
        const finalRuleString = generateRuleString(sessionToFinalize.headerData, sessionToFinalize.ruleOptions);

        if (editingSourceId) {
            // GÜNCELLEME: Var olan kuralı güncelle
            setRuleSessions(prev => 
                prev.map(s => {
                    if (s.id === editingSourceId) { // Kaynak kuralı bul ve güncelle
                        return { ...sessionToFinalize, id: editingSourceId, status: 'finalized', ruleString: finalRuleString };
                    }
                    if (s.id === editorSessionId) { // Editörü temizle
                        return createNewSession();
                    }
                    return s;
                })
            );
            toast.success('Kural başarıyla güncellendi!');
        } else {
            // YENİ KURAL EKLEME: Eskisi gibi çalışır
            const newFinalizedRule = { ...sessionToFinalize, status: 'finalized', ruleString: finalRuleString };
            setRuleSessions(prev => [
                ...prev.filter(s => s.id !== editorSessionId), // Eski editörü çıkar
                newFinalizedRule, // Tamamlanmış kuralı ekle
                createNewSession() // Yeni boş bir editör ekle
            ]);
            toast.success('Kural başarıyla kaydedildi!');
        }
        setEditingSourceId(null); // Düzenleme modundan çık
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
        setEditingSourceId(null); // Çoğaltma, düzenleme değildir.
        toast.info('Kural çoğaltıldı ve düzenleyiciye yüklendi.');
    };

    const value = {
        ruleSessions,
        editingSourceId, // Dışarıya açıyoruz
        updateHeaderData,
        updateRuleOptions,
        finalizeRule,
        deleteRule,
        duplicateRule,
        startEditingRule,
        cancelEditing, // Dışarıya açıyoruz
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};