// src/components/OptionsBuilder.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import OptionRow from './OptionRow';
import AddOption from './AddOption';
import OptionGroupRow from './OptionGroupRow';

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
    
    const handleValueChange = (index, newValue) => {
        const updatedOptions = [...session.ruleOptions];
        if (updatedOptions[index]) {
            if (typeof newValue === 'object' && newValue !== null) {
                updatedOptions[index].value = newValue.value;
                updatedOptions[index].modifiers = newValue.modifiers;
            } else {
                updatedOptions[index].value = newValue;
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
            <div className="added-options-list">
                {session.ruleOptions.map((option, index) => {
                    if (index === editingIndex) {
                        return <OptionRow key={index} option={option} isEditing={true} onStartEditing={() => setEditingIndex(index)} onStopEditing={handleStopEditing} onValueChange={(newValue) => handleValueChange(index, newValue)} />;
                    }
                    if (option.keyword === 'content') {
                        return <OptionGroupRow key={index} option={option} onStartEditing={() => setEditingIndex(index)} />;
                    } else {
                        return <OptionRow key={index} option={option} isEditing={false} onStartEditing={() => setEditingIndex(index)} onStopEditing={handleStopEditing} onValueChange={(newValue) => handleValueChange(index, newValue)} />;
                    }
                })}
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