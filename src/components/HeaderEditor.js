// src/components/HeaderEditor.js

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useRule } from '../context/RuleContext';
import suggestionsData from '../data/suggestionsData';
import RuleInputBox from './RuleInputBox';
import OptionsBuilder from './OptionsBuilder';

const HeaderEditor = ({ session }) => {
    const { updateHeaderData } = useRule();
    
    // DEĞİŞİKLİK: Artık her zaman header'dan başlamak için başlangıç değeri 'false' olarak ayarlandı.
    const [isHeaderComplete, setIsHeaderComplete] = useState(false);
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
    
    const handleFocus = (label) => setActiveInput(label);

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
            setIsHeaderComplete(true);
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
        
        if (e.key === 'Escape') {
            e.preventDefault();
            moveToPrevField(currentIndex);
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
            } 
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);
    
    useEffect(() => {
        const isNewRule = !session.ruleString;
        if (!isHeaderComplete) {
            if (isNewRule) {
                inputRefs.current[0]?.focus();
            } else {
                const focusTimeout = setTimeout(() => {
                    inputRefs.current[0]?.focus();
                }, 500);
                return () => clearTimeout(focusTimeout);
            }
        }
    }, [isHeaderComplete, session.id, session.ruleString]);
    
    if (isHeaderComplete) {
        const finalHeaderString = labels.map(label => session.headerData[label]).join(' ');
        return (
            <div className="options-view-container">
                <pre className="final-header-text">{finalHeaderString} (</pre>
                <OptionsBuilder 
                    session={session}
                    onNavigateBack={() => setIsHeaderComplete(false)}
                />
                <div className="final-header-text">)</div>
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