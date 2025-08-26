// src/components/OptionRow.js

import React from 'react';
import { optionsDictionary } from '../data/optionsDictionary';
import ContentEditor from './ContentEditor';
import AutocompleteInput from './AutocompleteInput';

const OptionRow = ({ option, isEditing, onStartEditing, onStopEditing, onValueChange }) => {
    const optionInfo = optionsDictionary[option.keyword];
    const handleKeyDown = (e) => { if (e.key === 'Enter') onStopEditing(); };

    if (isEditing && optionInfo.inputType !== 'flag') {
        // ContentEditor özel durumu: Gelen (value, modifiers) ikilisini tek bir nesneye çevirip yukarı gönderir.
        if (option.keyword === 'content') {
            return <ContentEditor 
                option={option} 
                onValueChange={(value, modifiers) => onValueChange({ value, modifiers })} 
                onStopEditing={onStopEditing} 
            />;
        }
        // Diğer input'lar (autocomplete dahil) doğrudan tek bir değer gönderir.
        return (
            <div className="option-row">
                <span className="option-keyword">{option.keyword}:</span>
                {optionInfo.inputType === 'autocomplete' ? (
                    <AutocompleteInput 
                        suggestions={optionInfo.suggestions} 
                        value={option.value} 
                        onChange={onValueChange} 
                        onStopEditing={onStopEditing} 
                    />
                ) : (
                    <input 
                        type={optionInfo.inputType === 'number' ? 'number' : 'text'} 
                        className="option-value-input" 
                        value={option.value} 
                        onChange={(e) => onValueChange(e.target.value)} 
                        onBlur={onStopEditing} 
                        onKeyDown={handleKeyDown} 
                        autoFocus 
                    />
                )}
                <span className="option-semicolon">;</span>
            </div>
        );
    }

    // GÖRÜNÜM MODU: Değiştiricileri göstermek için option.modifiers'ı format fonksiyonuna gönderir.
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