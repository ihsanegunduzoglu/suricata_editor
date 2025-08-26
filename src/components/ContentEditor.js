// src/components/ContentEditor.js

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { optionsDictionary } from '../data/optionsDictionary';
import { useRule } from '../context/RuleContext';
import { infoData } from '../data/infoData';

const ContentEditor = ({ option, onValueChange, onStopEditing }) => {
    const { updateActiveTopic, updateModifierInfoActive } = useRule();
    const [command, setCommand] = useState('');
    const [isValueConfirmed, setIsValueConfirmed] = useState(false);
    const commandInputRef = useRef(null);
    const valueInputRef = useRef(null);
    const modifierInputs = {
        depth: useRef(null),
        offset: useRef(null),
    };

    const availableModifiers = useMemo(() => Object.keys(optionsDictionary).filter(k => optionsDictionary[k].isModifier), []);
    const filteredModifiers = command ? availableModifiers.filter(m => m.startsWith(command.toLowerCase())) : [];

    const handleModifierChange = (modifierKey, modifierValue) => {
        const newModifiers = { ...(option.modifiers || {}), [modifierKey]: modifierValue };
        onValueChange(option.value, newModifiers);
    };
    
    const handleMainValueChange = (e) => {
        onValueChange(e.target.value, option.modifiers);
    };
    
    const handleMainValueKeyDown = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            updateActiveTopic(null);
            setIsValueConfirmed(true);
        }
    };

    useEffect(() => {
        if (isValueConfirmed && commandInputRef.current) {
            commandInputRef.current.focus();
        }
    }, [isValueConfirmed]);

    const handleStopEditing = () => {
        updateModifierInfoActive(false);
        onStopEditing();
    };
    
    const handleModifierInputKeyDown = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            e.stopPropagation();
            commandInputRef.current?.focus();
        }
    };

    const handleCommandKeyDown = (e) => {
        if (e.key === 'Escape') {
            handleStopEditing();
            return;
        }
        if (e.key === 'Enter') {
            e.preventDefault();
            if (command === '' && document.activeElement === commandInputRef.current) {
                handleStopEditing();
                return;
            }
            const targetModifier = filteredModifiers[0];
            if (targetModifier) {
                const modifierInfo = optionsDictionary[targetModifier];
                if (modifierInfo.inputType === 'flag') {
                    handleModifierChange(targetModifier, !option.modifiers?.[targetModifier]);
                } else if (modifierInputs[targetModifier]?.current) {
                    modifierInputs[targetModifier].current.focus();
                }
            }
            setCommand('');
        }
    };

    return (
        <div 
            className="option-row-editing-card" 
            onKeyDown={handleCommandKeyDown} 
            onMouseLeave={() => {
                if (document.activeElement !== commandInputRef.current) {
                    updateActiveTopic(option.keyword);
                }
            }}
        >
            <div className="content-value-row">
                <span className="option-keyword">{option.keyword}:</span>
                <input
                    ref={valueInputRef}
                    type="text"
                    className="option-value-input"
                    value={option.value}
                    onChange={handleMainValueChange}
                    onKeyDown={handleMainValueKeyDown}
                    placeholder=""
                    autoFocus
                />
            </div>
            
            {isValueConfirmed && (
                <>
                    <div className="modifiers-grid">
                        <div className="modifier-item">
                            <input 
                                type="checkbox" 
                                id={`nocase-${option.value}`} 
                                checked={!!option.modifiers?.nocase} 
                                onChange={(e) => handleModifierChange('nocase', e.target.checked)} 
                                onFocus={() => updateActiveTopic('nocase')}
                            />
                            <label htmlFor={`nocase-${option.value}`}>nocase</label>
                        </div>
                        <div className="modifier-item">
                            <label htmlFor={`depth-${option.value}`}>depth:</label>
                            <input 
                                type="number" 
                                id={`depth-${option.value}`} 
                                ref={modifierInputs.depth} 
                                value={option.modifiers?.depth || ''}
                                onChange={(e) => handleModifierChange('depth', e.target.value)}
                                onKeyDown={handleModifierInputKeyDown}
                                onFocus={() => updateActiveTopic('depth')}
                            />
                        </div>
                        <div className="modifier-item">
                            <label htmlFor={`offset-${option.value}`}>offset:</label>
                            <input 
                                type="number" 
                                id={`offset-${option.value}`} 
                                ref={modifierInputs.offset} 
                                value={option.modifiers?.offset || ''}
                                onChange={(e) => handleModifierChange('offset', e.target.value)}
                                onKeyDown={handleModifierInputKeyDown}
                                onFocus={() => updateActiveTopic('offset')}
                            />
                        </div>
                    </div>
                    <div className="add-option-container">
                        <input 
                            type="text" 
                            className="add-option-search" 
                            placeholder="+ Değiştirici ekle (veya Esc/Enter ile bitir)"
                            ref={commandInputRef} 
                            value={command} 
                            onChange={e => setCommand(e.target.value)}
                            onFocus={() => {
                                updateModifierInfoActive(true);
                                updateActiveTopic(null); // Spesifik konuyu temizle
                            }}
                            onBlur={() => {
                                // Gecikmeli onBlur, listedeki bir öğeye tıklamak için zaman tanır
                                setTimeout(() => {
                                    // Sadece odak başka bir yere kaybolduysa paneli kapat
                                    if (!commandInputRef.current?.parentElement?.contains(document.activeElement)) {
                                        updateModifierInfoActive(false);
                                    }
                                }, 150);
                            }}
                        />
                        {command && (
                            <ul className="add-option-list" onMouseLeave={() => updateModifierInfoActive(true)}>
                                {filteredModifiers.map(k => (
                                    <li 
                                        key={k} 
                                        onMouseDown={() => { setCommand(k); handleCommandKeyDown({ key: 'Enter', preventDefault: () => { } }); }}
                                        onMouseEnter={() => updateActiveTopic(k)}
                                    >
                                        <span className="option-keyword">{k}</span>
                                        <span className='option-description'> - {infoData[k]?.summary || ''}</span>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </>
            )}
        </div>
    );
};

export default ContentEditor;