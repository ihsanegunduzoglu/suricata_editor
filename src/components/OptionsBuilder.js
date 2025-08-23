import React, { useState, useEffect, useRef } from 'react';
import OptionRow from './OptionRow';
import AddOption from './AddOption';

const OptionsBuilder = ({ ruleOptions, setRuleOptions, onNavigateBack }) => {
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
        const handleGlobalKeyDown = (e) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                onNavigateBack();
            }
        };
        document.addEventListener('keydown', handleGlobalKeyDown);
        return () => {
            document.removeEventListener('keydown', handleGlobalKeyDown);
        };
    }, [onNavigateBack]);
    
    const handleValueChange = (index, newValue) => {
        const updatedOptions = [...ruleOptions];
        if (updatedOptions[index]) {
            if (typeof newValue === 'object' && newValue !== null) {
                updatedOptions[index].value = newValue.value;
                updatedOptions[index].modifiers = newValue.modifiers;
            } else {
                updatedOptions[index].value = newValue;
            }
            setRuleOptions(updatedOptions);
        }
    };

    const handleDeleteLastOption = () => {
        if (ruleOptions.length > 0) {
            setRuleOptions(prev => prev.slice(0, -1));
        }
    };
    
    const handleAddOption = (newOption) => { 
        setRuleOptions(prev => {
            const newOpts = [...prev, newOption];
            setEditingIndex(newOpts.length - 1);
            return newOpts;
        }); 
    };
    
    const handleStopEditing = () => { 
        setEditingIndex(null); 
    };
    
    return (
        <div className="options-builder">
            <div className="added-options-list">
                {ruleOptions.map((option, index) => (
                    <OptionRow 
                        key={index} 
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
                ruleOptions={ruleOptions} 
            />
        </div>
    );
};

export default OptionsBuilder;