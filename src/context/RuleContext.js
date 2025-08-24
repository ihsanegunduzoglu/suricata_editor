// src/context/RuleContext.js

import React, { createContext, useContext, useState } from 'react';
import { generateRuleString } from '../utils/ruleGenerator';
import { v4 as uuidv4 } from 'uuid'; // Benzersiz ID için kütüphane

// Yeni bir oturum için başlangıç verisi oluşturan fonksiyon
const createNewSession = () => ({
    id: uuidv4(),
    status: 'editing', // 'editing' veya 'finalized' olabilir
    headerData: { 'Action': '', 'Protocol': '', 'Source IP': '', 'Source Port': '', 'Direction': '', 'Destination IP': '', 'Destination Port': '' },
    ruleOptions: [],
    ruleString: '' // Kural tamamlandığında doldurulacak
});

const RuleContext = createContext();
export const useRule = () => useContext(RuleContext);

export const RuleProvider = ({ children }) => {
    // Ana state: Artık tek bir kural yerine, bir oturum listesi tutuyoruz.
    const [ruleSessions, setRuleSessions] = useState([createNewSession()]);

    // Belirli bir oturumun Header verisini güncellemek için fonksiyon
    const updateHeaderData = (sessionId, newHeaderData) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, headerData: newHeaderData } : s));
    };

    // Belirli bir oturumun Options listesini güncellemek için fonksiyon
    const updateRuleOptions = (sessionId, newRuleOptions) => {
        setRuleSessions(prev => prev.map(s => s.id === sessionId ? { ...s, ruleOptions: newRuleOptions } : s));
    };

    // Mevcut (en sondaki) kuralı tamamlama ve yeni bir tane ekleme fonksiyonu
    const finalizeCurrentRule = () => {
        const currentSession = ruleSessions[ruleSessions.length - 1];

        // Kuralda en azından bir mesaj ve sid olmalı (basit bir kontrol)
        if (!currentSession.ruleOptions.some(o => o.keyword === 'msg') || !currentSession.ruleOptions.some(o => o.keyword === 'sid')) {
            alert('Lütfen kurala en azından "msg" ve "sid" seçeneklerini ekleyin.');
            return;
        }

        const finalRuleString = generateRuleString(currentSession.headerData, currentSession.ruleOptions);

        setRuleSessions(prev => [
            // Önceki tüm oturumların listesi
            ...prev.slice(0, -1),
            // Mevcut oturumun güncellenmiş, tamamlanmış hali
            { ...currentSession, status: 'finalized', ruleString: finalRuleString },
            // Ve en sona yeni, boş bir düzenleme oturumu
            createNewSession()
        ]);
    };

    const value = {
        ruleSessions,
        updateHeaderData,
        updateRuleOptions,
        finalizeCurrentRule,
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};