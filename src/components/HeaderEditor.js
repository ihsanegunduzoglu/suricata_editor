// src/components/HeaderEditor.js

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useRule } from '../context/RuleContext';
import suggestionsData from '../data/suggestionsData';
import RuleInputBox from './RuleInputBox';
import OptionsBuilder from './OptionsBuilder';
import { toast } from 'react-toastify';
import { validateHeaderField } from '../utils/ruleValidator';

const HeaderEditor = ({ session }) => {
    // DEĞİŞİKLİK: 'cancelEditing' fonksiyonunu context'ten alıyoruz.
    const { updateHeaderData, updateActiveTopic, optionsViewActive, updateOptionsViewActive, cancelEditing } = useRule();
    
    const [activeInput, setActiveInput] = useState(null);

    const editorRef = useRef(null);
    const inputRefs = useRef([]);
    const labels = Object.keys(session.headerData);
    
    const filteredSuggestions = useMemo(() => {
        if (!activeInput || !suggestionsData[activeInput]) return [];
        const value = session.headerData[activeInput] || '';
        const allSuggestions = suggestionsData[activeInput];
        if (!value) return allSuggestions;
        return allSuggestions.filter(s => s.toLowerCase().startsWith(value.toLowerCase()));
    }, [activeInput, session.headerData]);

    const handleChange = (label, value) => {
        const newHeaderData = { ...session.headerData, [label]: value };
        updateHeaderData(session.id, newHeaderData);
    };
    
    const handleFocus = (label) => {
        setActiveInput(label);
        updateActiveTopic(label);
    };

    const handleBlur = (fieldName, value) => {
        const errorMessage = validateHeaderField(fieldName, value);
        if (errorMessage) {
            toast.warn(errorMessage);
        }
    };

    const applySuggestion = (suggestion) => {
        if (activeInput) {
            handleChange(activeInput, suggestion);
        }
    };

    const moveToNextField = (currentIndex) => {
        const nextIndex = currentIndex + 1;
        if (nextIndex < labels.length) {
            setTimeout(() => inputRefs.current[nextIndex]?.focus(), 0);
        } else {
            const isHeaderComplete = Object.values(session.headerData).every(val => val && val.trim() !== '');
            if (!isHeaderComplete) {
                toast.warn('Lütfen devam etmeden önce tüm başlık alanlarını doldurun.');
                return; 
            }
            updateOptionsViewActive(true);
        }
    };

    const moveToPrevField = (currentIndex) => {
        const prevIndex = currentIndex - 1;
        if (prevIndex >= 0) {
            inputRefs.current[prevIndex]?.focus();
        }
    };

    const handleSuggestionClick = (suggestion) => { 
        if (activeInput) {
            const currentIndex = labels.indexOf(activeInput);
            applySuggestion(suggestion);
            moveToNextField(currentIndex);
        }
    };
    
    const handleKeyDown = (e, currentIndex) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            const currentValue = e.target.value?.toLowerCase();
            const firstSuggestion = filteredSuggestions[0]?.toLowerCase();

            if (filteredSuggestions.length > 0 && currentValue !== firstSuggestion) {
                applySuggestion(filteredSuggestions[0]);
            } 
            else {
                moveToNextField(currentIndex);
            }
        }
        
        if (e.key === ' ') {
            if (e.target.value.trim() !== '') {
                e.preventDefault();
                moveToNextField(currentIndex);
            }
        }
        
        // DEĞİŞİKLİK: Escape tuşu için özel kontrol ekledik.
        if (e.key === 'Escape') {
            e.preventDefault();
            // Eğer ilk kutudaysak (currentIndex === 0) VE kutu boşsa...
            if (currentIndex === 0 && e.target.value === '') {
                // Kural oluşturmayı/düzenlemeyi iptal et.
                cancelEditing();
                toast.info("Kural işlemi iptal edildi.");
            } else {
                // Diğer tüm durumlarda bir önceki alana git.
                moveToPrevField(currentIndex);
            }
        }

        if (e.key === 'Backspace' && e.target.value === '') { 
            e.preventDefault(); 
            moveToPrevField(currentIndex);
        }
    };
    
    useEffect(() => {
        const handleClickOutside = (e) => { 
            if (editorRef.current && !editorRef.current.contains(e.target)) { 
                setActiveInput(null); 
                updateActiveTopic(null);
            } 
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [updateActiveTopic]);
    
    useEffect(() => {
        const isNewRule = !session.ruleString;
        if (!optionsViewActive) {
            if (isNewRule) {
                inputRefs.current[0]?.focus();
            } else {
                const focusTimeout = setTimeout(() => {
                    inputRefs.current[0]?.focus();
                }, 500);
                return () => clearTimeout(focusTimeout);
            }
        }
    }, [optionsViewActive, session.id, session.ruleString]);
    
    if (optionsViewActive) {
        const finalHeaderString = labels.map(label => session.headerData[label]).join(' ');
        return (
            <div className="options-view-container">
                <pre className="final-header-text">{finalHeaderString} (</pre>
                <OptionsBuilder 
                    session={session}
                    onNavigateBack={() => updateOptionsViewActive(false)}
                />
                <div className="final-header-text closing-paren">)</div>
            </div>
        );
    }

    return (
        <div className="editor-row" ref={editorRef}>
            {labels.map((label, index) => (
                <RuleInputBox 
                    key={session.id + label}
                    ref={el => inputRefs.current[index] = el} 
                    label={label} 
                    value={session.headerData[label]}
                    onChange={e => handleChange(label, e.target.value)}
                    onFocus={() => handleFocus(label)} 
                    onBlur={() => handleBlur(label, session.headerData[label])}
                    onKeyDown={e => handleKeyDown(e, index)} 
                    isActive={activeInput === label} 
                    suggestions={filteredSuggestions}
                    onSuggestionClick={handleSuggestionClick} 
                />
            ))}
        </div>
    );
};

export default HeaderEditor;