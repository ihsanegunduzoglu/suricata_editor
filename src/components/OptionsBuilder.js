// src/components/OptionsBuilder.js

import React, { useState, useEffect, useRef } from 'react';
import { useRule } from '../context/RuleContext';
import OptionRow from './OptionRow';
import AddOption from './AddOption';
import { toast } from 'react-toastify';

const OptionsBuilder = ({ session, onNavigateBack }) => {
    const { updateRuleOptions, updateActiveTopic, optionFocusRequest, clearOptionFocusRequest } = useRule();
    
    const [editingIndex, setEditingIndex] = useState(null);
    const [selectedIndex, setSelectedIndex] = useState(null);
    const addOptionInputRef = useRef(null);
    const containerRef = useRef(null);

    useEffect(() => {
        // Yeni bir kurala başlandığında veya düzenleme bittiğinde imlecin seçenek ekleme alanına odaklanmasını sağlar
        if (editingIndex === null && selectedIndex === null) {
             setTimeout(() => {
                addOptionInputRef.current?.focus();
            }, 0);
        }
    }, [editingIndex, selectedIndex]);

    useEffect(() => {
        const activeIndex = editingIndex ?? selectedIndex;
        if (activeIndex !== null) {
            const activeKeyword = session.ruleOptions[activeIndex]?.keyword;
            if (activeKeyword && activeKeyword !== 'content' && activeKeyword !== 'metadata') {
                updateActiveTopic(activeKeyword);
            }
        } else {
             updateActiveTopic(null);
        }
    }, [editingIndex, selectedIndex, session.ruleOptions, updateActiveTopic]);

    useEffect(() => {
        const handleKeyDown = (e) => {
            if (editingIndex !== null || document.activeElement === addOptionInputRef.current) {
                return;
            }

            const optionsCount = session.ruleOptions.length;
            
            switch (e.key) {
                case 'ArrowDown':
                    e.preventDefault();
                    if (optionsCount > 0) {
                        if (selectedIndex === null) {
                            setSelectedIndex(0);
                        } 
                        else if (selectedIndex < optionsCount - 1) {
                            setSelectedIndex(prev => prev + 1);
                        } else {
                            containerRef.current?.focus();
                        }
                    }
                    break;
                case 'ArrowUp':
                    e.preventDefault();
                    if (optionsCount > 0) {
                         if (selectedIndex === 0) {
                            // En üstteyiz, daha fazla yukarı gitme.
                            // Hiçbir şey yapmadan fonksiyondan çıkıyoruz.
                            return; 
                        }

                        if (selectedIndex === null) {
                            setSelectedIndex(optionsCount - 1);
                        }
                        else {
                            setSelectedIndex(prev => prev - 1);
                        }
                    }
                    break;
                case 'Escape':
                    e.preventDefault();
                    setSelectedIndex(null);
                    onNavigateBack();
                    break;
                case 'Enter':
                    if (selectedIndex !== null) {
                        e.preventDefault();
                        setEditingIndex(selectedIndex);
                    }
                    break;
                case 'Backspace':
                case 'Delete':
                    if (selectedIndex !== null) {
                        e.preventDefault();
                        handleDeleteOption(selectedIndex);
                    }
                    break;
                default:
                    break;
            }
        };

        const container = containerRef.current;
        container?.addEventListener('keydown', handleKeyDown);
        return () => container?.removeEventListener('keydown', handleKeyDown);

    }, [editingIndex, selectedIndex, session.ruleOptions, onNavigateBack]);

    useEffect(() => {
        if (selectedIndex !== null && editingIndex === null && containerRef.current) {
            const row = containerRef.current.querySelector(`.option-row[data-index="${selectedIndex}"]`);
            row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
    }, [selectedIndex, editingIndex]);
    

    // Dışarıdan gelen option odak isteğini uygula
    useEffect(() => {
        if (!optionFocusRequest) return;
        const { keyword, index } = optionFocusRequest;
        let targetIndex = index;
        if (typeof targetIndex !== 'number') {
            targetIndex = session.ruleOptions.findIndex(o => o.keyword === keyword);
        }
        if (targetIndex >= 0) {
            setEditingIndex(targetIndex);
            updateActiveTopic(keyword);
        }
        clearOptionFocusRequest();
    // eslint-disable-next-line
    }, [optionFocusRequest]);

    // BU FONKSİYON ÇOK ÖNEMLİ

    const handleValueChange = (index, newValue) => {
        const updatedOptions = [...session.ruleOptions];
        const targetOption = updatedOptions[index];
        if (targetOption) {
            if (typeof newValue === 'object' && newValue !== null && newValue.hasOwnProperty('modifiers')) {
                Object.assign(targetOption, newValue);
            } else {
                targetOption.value = newValue;
            }
            updateRuleOptions(session.id, updatedOptions);
        }
    };

    const handleStartEditing = (index) => {
        setSelectedIndex(index);
        setEditingIndex(index);
    };

    const handleStopEditing = () => {
        setEditingIndex(null);
        setSelectedIndex(null);
        setTimeout(() => addOptionInputRef.current?.focus(), 0);
    };

    const handleDeleteOption = (indexToDelete) => {
        const newRuleOptions = session.ruleOptions.filter((_, i) => i !== indexToDelete);
        updateRuleOptions(session.id, newRuleOptions);
        toast.info('Seçenek silindi.');
        setSelectedIndex(null);
        addOptionInputRef.current?.focus();
    };
    
    const handleAddOption = (newOption) => { 
        const newRuleOptions = [...session.ruleOptions, newOption];
        updateRuleOptions(session.id, newRuleOptions);
        
        // DÜZELTME: Yeni eklenen seçeneği otomatik olarak düzenleme moduna alan satır geri eklendi.
        handleStartEditing(newRuleOptions.length - 1);
    };

    const handleNavigateToList = () => {
        const lastIndex = session.ruleOptions.length - 1;
        if (lastIndex >= 0) {
            setSelectedIndex(lastIndex);
            containerRef.current?.focus();
        }
    };

    return (
        <div ref={containerRef} tabIndex={-1} className="options-builder">
            <div className="added-options-list">
                {session.ruleOptions.map((option, index) => (
                    <OptionRow 
                        key={option.id}
                        option={option}
                        index={index}
                        isSelected={index === selectedIndex && editingIndex === null}
                        isEditing={index === editingIndex} 
                        onStartEditing={() => handleStartEditing(index)}
                        onStopEditing={handleStopEditing} 
                        onValueChange={(newValue) => handleValueChange(index, newValue)}
                        onDelete={() => handleDeleteOption(index)}
                    />
                ))}
            </div>
            <AddOption 
                ref={addOptionInputRef} 
                onOptionAdd={handleAddOption} 
                onDeleteLastOption={() => session.ruleOptions.length > 0 && handleDeleteOption(session.ruleOptions.length - 1)} 
                session={session}
                onNavigateToList={handleNavigateToList}
                onNavigateBack={onNavigateBack}
            />
        </div>
    );
};

export default OptionsBuilder;