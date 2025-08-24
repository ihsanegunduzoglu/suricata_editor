// src/components/HeaderEditor.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import suggestionsData from '../data/suggestionsData';
import RuleInputBox from './RuleInputBox';
import OptionsBuilder from './OptionsBuilder';

const HeaderEditor = ({ session }) => {
    const { updateHeaderData } = useRule();
    
    const [isHeaderComplete, setIsHeaderComplete] = useState(false);
    const [activeInput, setActiveInput] = useState(null);

    const editorRef = useRef(null);
    const inputRefs = useRef([]);
    const labels = Object.keys(session.headerData);
    
    // Değişiklikleri merkezi state'e bildiren güncellenmiş fonksiyon
    const handleChange = (label, value) => {
        const newHeaderData = { ...session.headerData, [label]: value };
        updateHeaderData(session.id, newHeaderData);
    };
    
    const handleFocus = (label) => setActiveInput(label);

    const handleSuggestionClick = (suggestion) => { 
        if (activeInput) { 
            handleChange(activeInput, suggestion); 
            const currentIndex = labels.indexOf(activeInput); 
            const nextIndex = currentIndex + 1; 
            if (nextIndex < labels.length) { 
                inputRefs.current[nextIndex]?.focus(); 
            } 
        } 
    };
    
    const handleKeyDown = (e, currentIndex) => {
        if (e.key === ' ' && e.target.value.trim() !== '') { 
            e.preventDefault(); 
            const nextIndex = currentIndex + 1; 
            if (nextIndex < labels.length) { 
                inputRefs.current[nextIndex]?.focus(); 
            } else { 
                setIsHeaderComplete(true); 
            } 
        }
        if (e.key === 'Backspace' && e.target.value === '') { 
            e.preventDefault(); 
            const prevIndex = currentIndex - 1; 
            if (prevIndex >= 0) { 
                inputRefs.current[prevIndex]?.focus(); 
            } 
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
        // İlk render'da ilk input'a odaklan
        inputRefs.current[0]?.focus();
    }, []);
    
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
                    key={session.id + label} // Key'i daha benzersiz yapalım
                    ref={el => inputRefs.current[index] = el} 
                    label={label} 
                    value={session.headerData[label]}
                    onChange={e => handleChange(label, e.target.value)}
                    onFocus={() => handleFocus(label)} 
                    onKeyDown={e => handleKeyDown(e, index)} 
                    isActive={activeInput === label} 
                    suggestions={suggestionsData[label]} 
                    onSuggestionClick={handleSuggestionClick} 
                />
            ))}
        </div>
    );
};

export default HeaderEditor;