// src/components/ContentEditor.js

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { optionsDictionary } from '../data/optionsDictionary';
import { useRule } from '../context/RuleContext';
import { infoData } from '../data/infoData';
import { Pipette } from 'lucide-react';

const ContentEditor = ({ option, onValueChange, onStopEditing }) => {

    const { updateActiveTopic, updateModifierInfoActive, optionFocusRequest } = useRule();

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

    const handleStopEditing = () => {
        updateModifierInfoActive(false);
        onStopEditing();
    };

    const handleModifierChange = (modifierKey, modifierValue) => {
        const newModifiers = { ...(option.modifiers || {}), [modifierKey]: modifierValue };
        onValueChange({ value: option.value, modifiers: newModifiers, format: option.format });
    };
    
    const handleMainValueChange = (e) => {
        onValueChange({ value: e.target.value, modifiers: option.modifiers, format: option.format });
    };

    const handleFormatChange = (newFormat) => {
        onValueChange({ value: option.value, modifiers: option.modifiers, format: newFormat });
        valueInputRef.current?.focus();
    };
    
    const handleMainValueKeyDown = (e) => {
        if (e.key === 'Enter' || e.key === 'Escape') {
            e.preventDefault();
            setIsValueConfirmed(true);
        }
    };

    useEffect(() => {
        if (isValueConfirmed && commandInputRef.current) {
            commandInputRef.current.focus();
        }
    }, [isValueConfirmed]);
    
    const handleModifierInputKeyDown = (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            e.stopPropagation();
            commandInputRef.current?.focus();
        }
        if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            handleStopEditing();
        }
    };

    const handleCommandKeyDown = (e) => {
        if (e.key === 'Escape' || (e.key === 'Enter' && command === '')) {
            handleStopEditing();
            return;
        }
        if (e.key === 'Enter') {
            e.preventDefault();
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

    // Dışarıdan gelen "expandDetails" isteği varsa, content için ana değeri onaylayıp modifier alanlarını göster
    useEffect(() => {
        if (!optionFocusRequest) return;
        if (optionFocusRequest.keyword !== 'content') return;
        if (optionFocusRequest.expandDetails && !isValueConfirmed) {
            setIsValueConfirmed(true);
            setTimeout(() => {
                commandInputRef.current?.focus();
            }, 0);
        }
    }, [optionFocusRequest, isValueConfirmed]);

    return (
        <div className="option-row-editing-card">
            <div className="content-editor-main-row">
                <div className="content-value-row">
                    <span className="option-keyword">{option.keyword}:</span>
                    <div className="input-with-format-selector">
                        <input
                            ref={valueInputRef}
                            type="text"
                            className="option-value-input"
                            value={option.value}
                            onChange={handleMainValueChange}
                            onKeyDown={handleMainValueKeyDown}
                            placeholder="Örn: 'evil.exe' veya '|FF D8 FF E0|'"
                            autoFocus
                        />
                        <div className="content-format-inline-selector">
                            <button onClick={() => setInfoPanelTab('payload')} className="pv-open-btn" title="Payload Analiz Aracını Aç">
                                <Pipette size={16} />
                            </button>
                            <span 
                                className={`format-option-inline ${option.format === 'ascii' ? 'active' : ''}`}
                                onClick={() => handleFormatChange('ascii')}
                            >
                                ASCII
                            </span>
                            <span className="format-divider-inline">|</span>
                            <span 
                                className={`format-option-inline ${option.format === 'hex' ? 'active' : ''}`}
                                onClick={() => handleFormatChange('hex')}
                            >
                                HEX
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            
            {isValueConfirmed && (
                <>
                    <div className="modifiers-grid">
                        <div className="modifier-item modifier-toggle">
                            <label htmlFor={`nocase-${option.id}`}>
                                <span>nocase</span>
                                <input 
                                    type="checkbox" 
                                    id={`nocase-${option.id}`} 
                                    checked={!!option.modifiers?.nocase} 
                                    onChange={(e) => handleModifierChange('nocase', e.target.checked)} 
                                    onFocus={() => updateActiveTopic('nocase')}
                                />
                                <span className="toggle-switch"></span>
                            </label>
                        </div>
                        <div className="modifier-item">
                            <label htmlFor={`depth-${option.id}`}>depth</label>
                            <input 
                                type="number" 
                                id={`depth-${option.id}`} 
                                ref={modifierInputs.depth} 
                                value={option.modifiers?.depth || ''}
                                onChange={(e) => handleModifierChange('depth', e.target.value)}
                                onKeyDown={handleModifierInputKeyDown}
                                onFocus={() => updateActiveTopic('depth')}
                                placeholder="Değer girin..."
                            />
                        </div>
                        <div className="modifier-item">
                            <label htmlFor={`offset-${option.id}`}>offset</label>
                            <input 
                                type="number" 
                                id={`offset-${option.id}`} 
                                ref={modifierInputs.offset} 
                                value={option.modifiers?.offset || ''}
                                onChange={(e) => handleModifierChange('offset', e.target.value)}
                                onKeyDown={handleModifierInputKeyDown}
                                onFocus={() => updateActiveTopic('offset')}
                                placeholder="Değer girin..."
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
                            onKeyDown={handleCommandKeyDown}
                            onFocus={() => { updateModifierInfoActive(true); updateActiveTopic(null); }}
                            onBlur={() => { setTimeout(() => { if (!commandInputRef.current?.parentElement?.contains(document.activeElement)) { updateModifierInfoActive(false); } }, 150); }}
                        />
                        {command && (
                            <ul className="add-option-list">
                                {filteredModifiers.map(k => (
                                    <li 
                                        key={k} 
                                        onMouseDown={() => { setCommand(k); handleCommandKeyDown({ key: 'Enter', preventDefault: () => {} }); }}
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