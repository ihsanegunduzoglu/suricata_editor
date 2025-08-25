// src/components/OptionsBuilder.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import OptionRow from './OptionRow';
import AddOption from './AddOption';

const OptionsBuilder = ({ session, onNavigateBack }) => {
    const { updateRuleOptions } = useRule();
    
    const [editingIndex, setEditingIndex] = useState(null);
    const addOptionInputRef = useRef(null);
    
    useEffect(() => {
        if (editingIndex === null) {
            setTimeout(() => {
                addOptionInputRef.current?.focus();
            }, 0);
        }
    }, [editingIndex]);
    
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape') {
                onNavigateBack();
            }
        };

        document.addEventListener('keydown', handleKeyDown);

        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [onNavigateBack]);

    const handleValueChange = (index, newValue) => {
        const updatedOptions = [...session.ruleOptions];
        const targetOption = updatedOptions[index];

        if (targetOption) {
            if (typeof newValue === 'object' && newValue !== null) {
                targetOption.value = newValue.value;
                targetOption.modifiers = newValue.modifiers;
            } else {
                targetOption.value = newValue;
            }
            updateRuleOptions(session.id, updatedOptions);
        }
    };

    const handleDeleteLastOption = () => {
        if (session.ruleOptions.length > 0) {
            const newRuleOptions = session.ruleOptions.slice(0, -1);
            updateRuleOptions(session.id, newRuleOptions);
        }
    };
    
    const handleAddOption = (newOption) => { 
        const newRuleOptions = [...session.ruleOptions, newOption];
        updateRuleOptions(session.id, newRuleOptions);
        setEditingIndex(newRuleOptions.length - 1);
    };
    
    const handleStopEditing = () => { 
        setEditingIndex(null); 
    };
    
    return (
        <div className="options-builder">
            {/* Header'a Geri Dön Butonu ve toolbar'ı buradan kaldırıldı */}
            <div className="added-options-list">
                {session.ruleOptions.map((option, index) => (
                    <OptionRow 
                        key={option.id}
                        option={option} 
                        isEditing={index === editingIndex} 
                        onStartEditing={() => setEditingIndex(index)} 
                        onStopEditing={handleStopEditing} 
                        onValueChange={(newValue) => handleValueChange(index, newValue)} 
                    />
                ))}
            </div>
            <AddOption 
                ref={addOptionInputRef} 
                onOptionAdd={handleAddOption} 
                onDeleteLastOption={handleDeleteLastOption} 
                session={session}
            />
        </div>
    );
};

export default OptionsBuilder;