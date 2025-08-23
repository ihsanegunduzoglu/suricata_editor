import React, { useState, useEffect, useRef } from 'react';

const AutocompleteInput = ({ value, onChange, onStopEditing, suggestions }) => {
    const [showSuggestions, setShowSuggestions] = useState(false);
    const containerRef = useRef(null);
    const filteredSuggestions = suggestions.filter(s => s.toLowerCase().includes(value.toLowerCase()));

    const handleSelect = (suggestion) => {
        onChange(suggestion);
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
        <div className="autocomplete-container" ref={containerRef}>
            <input type="text" className="option-value-input" value={value}
                onChange={(e) => onChange(e.target.value)} onFocus={() => setShowSuggestions(true)}
                onKeyDown={handleKeyDown} autoFocus />
            {showSuggestions && (
                <ul className="suggestions-list">
                    {filteredSuggestions.map((suggestion, index) => (
                        <li key={index} onMouseDown={() => handleSelect(suggestion)}>
                            {suggestion}
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

export default AutocompleteInput;