import React, { useState, useRef, useEffect } from 'react';
import { useRule } from '../context/RuleContext';

const CustomSelect = ({ options, value, onChange, placeholder, disabled }) => {
    const { updateActiveTopic } = useRule();
    const [isOpen, setIsOpen] = useState(false);
    const containerRef = useRef(null);

    const selectedOption = options.find(opt => opt.id === value);

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (containerRef.current && !containerRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const handleSelect = (optionId) => {
        onChange(optionId);
        setIsOpen(false);
        updateActiveTopic(optionId);
    };

    return (
        <div className={`custom-select-container ${disabled ? 'disabled' : ''}`} ref={containerRef}>
            <button 
                type="button" 
                className="custom-select-display" 
                onClick={() => setIsOpen(!isOpen)}
                disabled={disabled}
            >
                {selectedOption ? selectedOption.name : placeholder}
                <span className="custom-select-arrow">▼</span>
            </button>
            {isOpen && (
                <ul className="custom-select-options" onMouseLeave={() => updateActiveTopic(null)}>
                    {options.map(option => (
                        <li 
                            key={option.id}
                            onClick={() => handleSelect(option.id)}
                            onMouseEnter={() => updateActiveTopic(option.id)}
                        >
                            {option.name} ({option.id})
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

export default CustomSelect;