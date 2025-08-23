// src/components/OptionsBuilder.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import OptionRow from './OptionRow';
import AddOption from './AddOption';
import OptionGroupRow from './OptionGroupRow';

const OptionsBuilder = () => {
    const { ruleOptions, setRuleOptions, setIsHeaderComplete } = useRule();
    
    // editingIndex, bu bileşenin kendi içindeki bir durum olduğu için burada kalıyor.
    const [editingIndex, setEditingIndex] = useState(null);
    const addOptionInputRef = useRef(null);

    const onNavigateBack = () => setIsHeaderComplete(false);
    
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
    }, []); // onNavigateBack artık context'ten geldiği için bağımlılığa gerek yok
    
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
                {ruleOptions.map((option, index) => {
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
            {/* Bu handler'lar bu bileşende tanımlandığı için prop olarak geçmeye devam ediyor */}
            <AddOption 
                ref={addOptionInputRef} 
                onOptionAdd={handleAddOption} 
                onDeleteLastOption={handleDeleteLastOption} 
            />
        </div>
    );
};

export default OptionsBuilder;