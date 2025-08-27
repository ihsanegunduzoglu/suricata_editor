// src/components/AddOption.js

import React, { useState, useMemo } from 'react';
import { useRule } from '../context/RuleContext';
import { optionsDictionary } from '../data/optionsDictionary';
import { v4 as uuidv4 } from 'uuid';

const AddOption = React.forwardRef(({ onOptionAdd, onDeleteLastOption, session }, ref) => {
    const { finalizeRule, updateActiveTopic } = useRule(); // updateActiveTopic'i al
    const protocol = session.headerData.Protocol;
    const ruleOptions = session.ruleOptions;

    const [searchTerm, setSearchTerm] = useState('');
    
    const availableOptions = useMemo(() => {
        const addedKeywords = new Set(ruleOptions.map(o => o.keyword));
        return Object.keys(optionsDictionary).filter(keyword => {
            const optionInfo = optionsDictionary[keyword];
            if (optionInfo.isModifier) return false;
            if (optionInfo.allowMultiple === false && addedKeywords.has(keyword)) return false;
            if (optionInfo.dependsOn && !addedKeywords.has(optionInfo.dependsOn)) return false;
            if (optionInfo.dependsOnProtocol && optionInfo.dependsOnProtocol !== protocol?.toLowerCase()) {
                return false;
            }
            return true;
        });
    }, [ruleOptions, protocol]);
    
    const handleAdd = (keyword) => {
        const newOption = { id: uuidv4(), keyword: keyword, value: optionsDictionary[keyword].defaultValue };
        if (keyword === 'content') { 
            newOption.modifiers = { nocase: false, depth: '', offset: '' }; 
        }
        onOptionAdd(newOption);
        setSearchTerm('');
    };
    
    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && e.target.value === '') {
            e.preventDefault();
            finalizeRule(session.id);
            return;
        }

        if (e.key === 'Enter' && filteredOptions.length > 0) {
            e.preventDefault();
            handleAdd(filteredOptions[0]);
        }
        
        if (e.key === 'Backspace' && e.target.value === '') {
            e.preventDefault();
            onDeleteLastOption();
        }
    };
    
    const filteredOptions = searchTerm ? availableOptions.filter(opt => opt.toLowerCase().includes(searchTerm.toLowerCase())) : [];

    return (
        <div className="add-option-container"> {/* Bilgi panelini sabit tutmak için otomatik temizleme kaldırıldı */}
            <input 
                ref={ref} type="text" className="add-option-search" 
                placeholder="+ Seçenek ekle veya ara... (Boşken Enter ile kuralı kaydet/güncelle)" 
                value={searchTerm} 
                onChange={(e) => setSearchTerm(e.target.value)} 
                onKeyDown={handleKeyDown} 
                onFocus={() => {}}
            />
            {searchTerm && (
                <ul className="add-option-list">
                    {filteredOptions.map(keyword => (
                        <li 
                            key={keyword} 
                            onClick={() => handleAdd(keyword)}
                            onMouseEnter={() => updateActiveTopic(keyword)} // Fare üzerine gelince konuyu güncelle
                        >
                            {keyword}<span className='option-description'> - {optionsDictionary[keyword].description}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
});

export default AddOption;