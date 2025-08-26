// src/components/OptionsBuilder.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import OptionRow from './OptionRow';
import AddOption from './AddOption';

const OptionsBuilder = ({ session, onNavigateBack }) => {
    const { updateRuleOptions, updateActiveTopic } = useRule();
    
    const [editingIndex, setEditingIndex] = useState(null);
    const addOptionInputRef = useRef(null);
    
    useEffect(() => {
        if (editingIndex === null) {
            updateActiveTopic(null);
            setTimeout(() => {
                addOptionInputRef.current?.focus();
            }, 0);
        }
    }, [editingIndex, updateActiveTopic]);
    
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === 'Escape') {
                onNavigateBack();
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [onNavigateBack]);

    // BU FONKSİYON ÇOK ÖNEMLİ
    const handleValueChange = (index, newValue) => {
        const updatedOptions = [...session.ruleOptions];
        const targetOption = updatedOptions[index];

        if (targetOption) {
            // ContentEditor'dan gelen veri bir nesnedir ({ value, modifiers })
            // Diğer inputlardan gelen veri ise bir string'dir.
            // Bu kontrol, iki durumu da doğru şekilde yönetmemizi sağlar.
            if (typeof newValue === 'object' && newValue !== null && newValue.hasOwnProperty('modifiers')) {
                targetOption.value = newValue.value;
                targetOption.modifiers = newValue.modifiers; // Modifiers'ı burada güncelliyoruz
            } else {
                targetOption.value = newValue; // Diğer seçeneklerin sadece değerini güncelliyoruz
            }
            updateRuleOptions(session.id, updatedOptions);
        }
    };
    
    const handleStartEditing = (keyword, index) => {
        setEditingIndex(index);
        updateActiveTopic(keyword);
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
        handleStartEditing(newOption.keyword, newRuleOptions.length - 1);
    };
    
    const handleStopEditing = () => { 
        setEditingIndex(null); 
    };
    
    return (
        <div className="options-builder">
            <div className="added-options-list">
                {session.ruleOptions.map((option, index) => (
                    <OptionRow 
                        key={option.id}
                        option={option} 
                        isEditing={index === editingIndex} 
                        onStartEditing={(keyword) => handleStartEditing(keyword, index)}
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