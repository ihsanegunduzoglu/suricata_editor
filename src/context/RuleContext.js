// src/context/RuleContext.js

import React, { createContext, useContext, useState } from 'react';

// 1. Context (İlân Panosu) oluşturuluyor
const RuleContext = createContext();

// 2. Bu Context'i kullanmak için kolay bir kısayol (custom hook) oluşturuluyor
export const useRule = () => {
    return useContext(RuleContext);
};

// 3. Tüm uygulama durumunu (state) tutacak ve dağıtacak olan ana bileşen (Provider)
export const RuleProvider = ({ children }) => {
    // HeaderEditor'da yaşayan tüm genel state'leri buraya taşıdık
    const [headerData, setHeaderData] = useState({ 'Action': '', 'Protocol': '', 'Source IP': '', 'Source Port': '', 'Direction': '', 'Destination IP': '', 'Destination Port': '' });
    const [ruleOptions, setRuleOptions] = useState([]);
    const [isHeaderComplete, setIsHeaderComplete] = useState(false);

    // Panoya asılacak olan tüm bilgiler (hem değerler hem de onları değiştiren fonksiyonlar)
    const value = {
        headerData,
        setHeaderData,
        ruleOptions,
        setRuleOptions,
        isHeaderComplete,
        setIsHeaderComplete
    };

    return (
        <RuleContext.Provider value={value}>
            {children}
        </RuleContext.Provider>
    );
};