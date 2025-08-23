// src/components/OptionGroupRow.js

import React from 'react';

// Bu bileşen, content ve değiştiricilerini tek bir satırda gösterir.
const OptionGroupRow = ({ option, onStartEditing }) => {
    
    // Gösterilecek değiştiricileri bir diziye dönüştürelim
    const modifiersToDisplay = [];
    if (option.modifiers) {
        if (option.modifiers.nocase) {
            modifiersToDisplay.push({ keyword: 'nocase' });
        }
        if (option.modifiers.depth && option.modifiers.depth !== '') {
            modifiersToDisplay.push({ keyword: 'depth', value: option.modifiers.depth });
        }
        if (option.modifiers.offset && option.modifiers.offset !== '') {
            modifiersToDisplay.push({ keyword: 'offset', value: option.modifiers.offset });
        }
    }

    return (
        <div className="option-group-row" onClick={onStartEditing}>
            {/* Ana content seçeneği */}
            <div className="option-group-item">
                <span className="option-keyword">{option.keyword}:</span>
                <span className="option-value">"{option.value}"</span>
                <span className="option-semicolon">;</span>
            </div>
            
            {/* Diğer değiştiriciler */}
            {modifiersToDisplay.map((mod, index) => (
                <div key={index} className="option-group-item">
                    <span className="option-keyword">{mod.keyword}</span>
                    {mod.value && <span className="option-value">:{mod.value}</span>}
                    <span className="option-semicolon">;</span>
                </div>
            ))}
        </div>
    );
};

export default OptionGroupRow;