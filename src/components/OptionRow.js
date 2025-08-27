// src/components/OptionRow.js

import React from 'react';
import { optionsDictionary } from '../data/optionsDictionary';
import ContentEditor from './ContentEditor';
import AutocompleteInput from './AutocompleteInput';
import { toast } from 'react-toastify';
import { validateOptionField } from '../utils/ruleValidator';

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
        if (e.key === 'Enter') {
            e.preventDefault();
            handleBlur();
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
            // DEĞİŞİKLİK: position:relative sarmalayıcısını kaldırdık
            return (
                <ContentEditor 
                    option={option} 
                    onValueChange={(value, modifiers) => onValueChange({ value, modifiers })} 
                    onStopEditing={onStopEditing} 
                />
            );
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