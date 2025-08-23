import React, { useState, useEffect, useRef } from 'react';
import suggestionsData from '../data/suggestionsData';
import RuleInputBox from './RuleInputBox';
import OptionsBuilder from './OptionsBuilder';

const HeaderEditor = () => {
    const [headerData, setHeaderData] = useState({ 'Action': '', 'Protocol': '', 'Source IP': '', 'Source Port': '', 'Direction': '', 'Destination IP': '', 'Destination Port': '' });
    const [activeInput, setActiveInput] = useState(null);
    const [isHeaderComplete, setIsHeaderComplete] = useState(false);
    const [ruleOptions, setRuleOptions] = useState([]);
    const editorRef = useRef(null);
    const inputRefs = useRef([]);
    const labels = Object.keys(headerData);
    const isInitialMount = useRef(true);
    const hasBeenInOptionMode = useRef(false);
    
    const handleFocus = (label) => setActiveInput(label);
    const handleChange = (label, value) => setHeaderData(prev => ({ ...prev, [label]: value }));
    const handleSuggestionClick = (suggestion) => { 
        if (activeInput) { 
            handleChange(activeInput, suggestion); 
            const currentIndex = labels.indexOf(activeInput); 
            const nextIndex = currentIndex + 1; 
            if (nextIndex < labels.length) { 
                inputRefs.current[nextIndex].focus(); 
            } 
        } 
    };
    
    const handleKeyDown = (e, currentIndex) => {
        if (e.key === ' ' && e.target.value.trim() !== '') { 
            e.preventDefault(); 
            const nextIndex = currentIndex + 1; 
            if (nextIndex < labels.length) { 
                inputRefs.current[nextIndex].focus(); 
            } else { 
                setIsHeaderComplete(true); 
                hasBeenInOptionMode.current = true; 
            } 
        }
        if (e.key === 'Backspace' && e.target.value === '') { 
            e.preventDefault(); 
            const prevIndex = currentIndex - 1; 
            if (prevIndex >= 0) { 
                inputRefs.current[prevIndex].focus(); 
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
        if (isInitialMount.current) { 
            isInitialMount.current = false; 
            setTimeout(() => { 
                const firstInput = inputRefs.current[0]; 
                if (firstInput) { 
                    firstInput.focus(); 
                } 
            }, 0); 
        } 
        else if (!isHeaderComplete && hasBeenInOptionMode.current) { 
            setTimeout(() => { 
                const lastInput = inputRefs.current[labels.length - 1]; 
                if (lastInput) { 
                    lastInput.focus(); 
                } 
            }, 0); 
        }
    }, [isHeaderComplete, labels.length]);
    
    if (isHeaderComplete) {
        const finalHeaderString = labels.map(label => headerData[label]).join(' ');
        return (
            <div className="options-view-container">
                <pre className="final-header-text">{finalHeaderString} (</pre>
                <OptionsBuilder 
                    ruleOptions={ruleOptions} 
                    setRuleOptions={setRuleOptions} 
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
                    key={label} 
                    ref={el => inputRefs.current[index] = el} 
                    label={label} 
                    value={headerData[label]} 
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