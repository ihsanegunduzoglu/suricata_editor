// src/components/AutocompleteInput.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';

const AutocompleteInput = ({ value, onChange, onStopEditing, suggestions }) => {
    const { updateActiveTopic } = useRule();
    const [showSuggestions, setShowSuggestions] = useState(false);
    const containerRef = useRef(null);

    // DEĞİŞİKLİK: Artık nesne dizisi üzerinde filtreleme yapıyoruz
    const filteredSuggestions = suggestions.filter(s => s.name.toLowerCase().includes(value.toLowerCase()));

    const handleSelect = (suggestion) => {
        onChange(suggestion.name); // Sadece 'name' alanını geri gönderiyoruz
        setShowSuggestions(false);
        onStopEditing();
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            if (filteredSuggestions.length > 0) {
                handleSelect(filteredSuggestions[0]);
            } else {
                onStopEditing();
            }
        }
    };

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (containerRef.current && !containerRef.current.contains(event.target)) {
                setShowSuggestions(false);
                onStopEditing();
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [onStopEditing]);

    return (
        <div className="autocomplete-container" ref={containerRef} onMouseLeave={() => updateActiveTopic(null)}>
            <input type="text" className="option-value-input" value={value}
                onChange={(e) => onChange(e.target.value)} onFocus={() => setShowSuggestions(true)}
                onKeyDown={handleKeyDown} autoFocus />
            {showSuggestions && (
                <ul className="suggestions-list">
                    {filteredSuggestions.map((suggestion, index) => (
                        <li 
                            key={index} 
                            onMouseDown={() => handleSelect(suggestion)}
                            onMouseEnter={() => updateActiveTopic('flow')} // Ana konuyu (flow) göster
                        >
                            {/* DEĞİŞİKLİK: Açıklamalı görünüm */}
                            <span className="option-keyword">{suggestion.name}</span>
                            <span className='option-description'> - {suggestion.description}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

export default AutocompleteInput;