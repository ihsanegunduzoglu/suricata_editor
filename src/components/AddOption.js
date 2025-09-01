// src/components/AddOption.js

import React, { useState, useMemo, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import { optionsDictionary } from '../data/optionsDictionary';
import { v4 as uuidv4 } from 'uuid';

const AddOption = React.forwardRef(({ onOptionAdd, onDeleteLastOption, session, onNavigateToList, onNavigateBack }, ref) => {
    const { finalizeRule, updateActiveTopic } = useRule();
    const [searchTerm, setSearchTerm] = useState('');
    const [isFocused, setIsFocused] = useState(false);
    const debounceTimeout = useRef(null);

    const protocol = session.headerData.Protocol;
    const availableOptions = useMemo(() => {
        const addedKeywords = new Set(session.ruleOptions.map(o => o.keyword));
        return Object.keys(optionsDictionary).filter(keyword => {
            const optionInfo = optionsDictionary[keyword];
            if (optionInfo.isModifier) return false;
            if (optionInfo.allowMultiple === false && addedKeywords.has(keyword)) return false;
            if (optionInfo.dependsOnProtocol && optionInfo.dependsOnProtocol !== protocol?.toLowerCase()) {
                return false;
            }
            return true;
        });
    }, [session.ruleOptions, protocol]);
    
    const filteredOptions = useMemo(() => {
        return searchTerm ? availableOptions.filter(opt => opt.toLowerCase().includes(searchTerm.toLowerCase())) : [];
    }, [searchTerm, availableOptions]);

    useEffect(() => {
        if (!isFocused) return;
        if (debounceTimeout.current) clearTimeout(debounceTimeout.current);
        debounceTimeout.current = setTimeout(() => {
            if (searchTerm && filteredOptions.length > 0) {
                updateActiveTopic(filteredOptions[0]);
            } else {
                updateActiveTopic(null);
            }
        }, 200);
        return () => { if (debounceTimeout.current) clearTimeout(debounceTimeout.current); };
    }, [searchTerm, filteredOptions, updateActiveTopic, isFocused]);

    const handleAdd = (keyword) => { 
        const newOption = { 
            id: uuidv4(), 
            keyword: keyword, 
            value: optionsDictionary[keyword].defaultValue 
        };
        if (keyword === 'content') { 
            newOption.modifiers = { nocase: false, depth: '', offset: '' };
            newOption.format = 'ascii'; 
        }
        onOptionAdd(newOption);
        setSearchTerm('');
    };
    
    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            if (e.target.value === '') {
                finalizeRule(session.id);
            } else if (filteredOptions.length > 0) {
                handleAdd(filteredOptions[0]);
            }
            return;
        }
        if (e.key === 'Backspace' && e.target.value === '') {
            e.preventDefault();
            onDeleteLastOption();
        }
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            onNavigateToList();
        }
        if (e.key === 'Escape') {
            e.preventDefault();
            onNavigateBack();
        }
    };
    
    return (
        <div className="add-option-container">
            <input 
                ref={ref} 
                type="text" 
                className="add-option-search" 
                placeholder="+ Seçenek ekle veya ara... (Boşken Enter ile kuralı kaydet)" 
                value={searchTerm} 
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyDown={handleKeyDown} 
                onFocus={() => setIsFocused(true)}
                // DEĞİŞİKLİK: Odaktan çıkınca Bilgi Panelini temizliyoruz
                onBlur={() => {
                    setIsFocused(false);
                    updateActiveTopic(null);
                }}
            />
            {searchTerm && (
                <ul className="add-option-list">
                    {filteredOptions.map(keyword => (
                        <li 
                            key={keyword} 
                            onClick={() => handleAdd(keyword)}
                            onMouseEnter={() => updateActiveTopic(keyword)}
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