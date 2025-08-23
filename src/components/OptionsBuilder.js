import React, { useState, useEffect, useRef } from 'react';
import OptionRow from './OptionRow';
import AddOption from './AddOption';
import OptionGroupRow from './OptionGroupRow';

const OptionsBuilder = ({ ruleOptions, setRuleOptions, onNavigateBack, protocol }) => {
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
                {ruleOptions.map((option, index) => {
                    // Eğer bu seçenek düzenleniyorsa, her zamanki gibi OptionRow'u kullan.
                    // OptionRow, ContentEditor'ı açma mantığını zaten biliyor.
                    if (index === editingIndex) {
                        return (
                            <OptionRow 
                                key={index} 
                                option={option} 
                                isEditing={true} 
                                onStartEditing={() => setEditingIndex(index)} 
                                onStopEditing={handleStopEditing} 
                                onValueChange={(newValue) => handleValueChange(index, newValue)} 
                            />
                        );
                    }

                    // EĞER DÜZENLENMİYORSA:
                    // Seçenek 'content' ise, yeni grup bileşenimizi kullan.
                    if (option.keyword === 'content') {
                        return (
                            <OptionGroupRow 
                                key={index}
                                option={option}
                                onStartEditing={() => setEditingIndex(index)}
                            />
                        );
                    } else {
                    // Diğer tüm seçenekler için standart OptionRow'u kullanmaya devam et.
                        return (
                            <OptionRow 
                                key={index} 
                                option={option} 
                                isEditing={false} 
                                onStartEditing={() => setEditingIndex(index)} 
                                onStopEditing={handleStopEditing} 
                                onValueChange={(newValue) => handleValueChange(index, newValue)} 
                            />
                        );
                    }
                })}
            </div>
            <AddOption 
                ref={addOptionInputRef} 
                onOptionAdd={handleAddOption} 
                onDeleteLastOption={handleDeleteLastOption} 
                ruleOptions={ruleOptions} 
                protocol={protocol}
            />
        </div>
    );
};

export default OptionsBuilder;