// src/components/OptionRow.js

import React, { useRef, useEffect, useState } from 'react';
import { optionsDictionary } from '../data/optionsDictionary';
import ContentEditor from './ContentEditor';
import AutocompleteInput from './AutocompleteInput';
import { toast } from 'react-toastify';
import { validateOptionField } from '../utils/ruleValidator';
import MitreEditor from './MitreEditor';
import { useRule } from '../context/RuleContext';

const MetadataEditor = ({ option, onValueChange, onStopEditing, handleKeyDown }) => {
    const { updateMitreInfo } = useRule();
    const [showMitre, setShowMitre] = useState(false);
    const editorRef = useRef(null);

    const [tactics, setTactics] = useState([]);
    const [techniques, setTechniques] = useState([]);
    const [subtechniques, setSubtechniques] = useState([]);
    const [selectedTacticId, setSelectedTacticId] = useState('');
    const [selectedTechnique, setSelectedTechnique] = useState(null); 
    const [selectedSubtechniqueId, setSelectedSubtechniqueId] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        if (showMitre && tactics.length === 0) {
            setIsLoading(true);
            fetch('http://127.0.0.1:5000/api/tactics')
                .then(res => res.json())
                .then(data => {
                    setTactics(data);
                    setIsLoading(false);
                })
                .catch(err => {
                    console.error("Taktikler yüklenemedi", err);
                    setIsLoading(false);
                });
        }
    }, [showMitre, tactics.length]);

    useEffect(() => {
        if (selectedTacticId) {
            setIsLoading(true);
            setTechniques([]); setSubtechniques([]); setSelectedTechnique(null); setSelectedSubtechniqueId('');
            fetch(`http://127.0.0.1:5000/api/techniques/${selectedTacticId}`)
                .then(res => res.json()).then(data => { setTechniques(data); setIsLoading(false); });
        }
    }, [selectedTacticId]);

    useEffect(() => {
        if (selectedTechnique && selectedTechnique.has_subtechniques) {
            setIsLoading(true);
            setSubtechniques([]); setSelectedSubtechniqueId('');
            fetch(`http://127.0.0.1:5000/api/subtechniques/${selectedTechnique.id}`)
                .then(res => res.json()).then(data => { setSubtechniques(data); setIsLoading(false); });
        } else {
            setSubtechniques([]);
        }
    }, [selectedTechnique]);

    const handleMappingAdd = (mappingString) => {
        const currentValue = option.value || '';
        if (currentValue.includes('attack_id')) {
            toast.warn("Bir kurala sadece bir MITRE eşlemesi eklenebilir.");
            return;
        }
        const separator = currentValue.trim() === '' ? '' : ', ';
        onValueChange(currentValue + separator + mappingString);
        
        updateMitreInfo(null);
        onStopEditing();
    };

    return (
        <div className="option-row-editing-card" ref={editorRef}>
            <div className="option-row">
                <span className="option-keyword">{option.keyword}:</span>
                <input 
                    type="text"
                    className="option-value-input" 
                    value={option.value} 
                    onChange={(e) => onValueChange(e.target.value)}
                    onKeyDown={handleKeyDown}
                    autoFocus 
                    placeholder="Örn: author Emre, attack_id T1059.001..."
                />
                <span className="option-semicolon">;</span>
            </div>
            <div className="metadata-toolbar">
                <button onClick={() => setShowMitre(!showMitre)} className="mitre-toggle-btn">
                    {showMitre ? 'MITRE Editörünü Gizle' : 'MITRE ATT&CK Ekle'}
                </button>
            </div>
            {showMitre && <MitreEditor 
                onMappingAdd={handleMappingAdd} 
                tactics={tactics}
                techniques={techniques}
                subtechniques={subtechniques}
                selectedTacticId={selectedTacticId}
                setSelectedTacticId={setSelectedTacticId}
                selectedTechnique={selectedTechnique}
                setSelectedTechnique={setSelectedTechnique}
                selectedSubtechniqueId={selectedSubtechniqueId}
                setSelectedSubtechniqueId={setSelectedSubtechniqueId}
                isLoading={isLoading}
            />}
        </div>
    );
};

const OptionRow = ({ option, isEditing, onStartEditing, onStopEditing, onValueChange }) => {
    const optionInfo = optionsDictionary[option.keyword];
    
    const handleBlur = () => {
        const errorMessage = validateOptionField(option.keyword, option.value);
        if (errorMessage) {
            toast.warn(errorMessage);
        }
        onStopEditing();
    };

    const handleKeyDown = (e) => { 
        if (e.key === 'Enter' && e.target.tagName.toLowerCase() !== 'textarea') {
            e.preventDefault();
            onStopEditing();
        }
    };

    const handleNumericChange = (e) => {
        const value = e.target.value;
        if (value === '' || /^\d+$/.test(value)) {
            onValueChange(value);
        }
    };

    if (isEditing && optionInfo.inputType !== 'flag') {
        if (option.keyword === 'content') {
            return (
                <ContentEditor 
                    option={option} 
                    // DÜZELTME BURADA: ContentEditor'dan gelen yeni nesneyi
                    // doğrudan bir üst bileşene iletiyoruz.
                    onValueChange={onValueChange} 
                    onStopEditing={onStopEditing} 
                />
            );
        }

        if (option.keyword === 'metadata') {
            return <MetadataEditor 
                option={option}
                onValueChange={onValueChange}
                onStopEditing={onStopEditing}
                handleKeyDown={handleKeyDown}
            />;
        }

        const isNumericOnly = ['sid', 'rev', 'priority'].includes(option.keyword);
        const changeHandler = isNumericOnly ? handleNumericChange : (e) => onValueChange(e.target.value);

        return (
            <div className="option-row">
                <span className="option-keyword">{option.keyword}:</span>
                {optionInfo.inputType === 'autocomplete' ? (
                    <AutocompleteInput 
                        suggestions={optionInfo.suggestions} 
                        value={option.value} 
                        onChange={onValueChange} 
                        onStopEditing={handleBlur}
                    />
                ) : (
                    <input 
                        type="text" 
                        className="option-value-input" 
                        value={option.value} 
                        onChange={changeHandler}
                        onBlur={handleBlur}
                        onKeyDown={handleKeyDown} 
                        autoFocus 
                    />
                )}
                <span className="option-semicolon">;</span>
            </div>
        );
    }

    return (
        <div className="option-row" onClick={optionInfo.inputType !== 'flag' ? () => onStartEditing(option.keyword) : undefined}>
            {optionInfo.inputType === 'flag' ? (
                <span className="option-keyword">{option.keyword}</span>
            ) : (
                <>
                    <span className="option-keyword">{option.keyword}:</span>
                    <span className="option-value">{optionInfo.format(option.value, option.modifiers)}</span>
                </>
            )}
            <span className="option-semicolon">;</span>
        </div>
    );
};

export default OptionRow;