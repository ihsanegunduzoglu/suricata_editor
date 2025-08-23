import React, { useState, useMemo } from 'react';
import { optionsDictionary } from '../data/optionsDictionary';

const AddOption = React.forwardRef(({ onOptionAdd, onDeleteLastOption, ruleOptions, protocol }, ref) => {
    const [searchTerm, setSearchTerm] = useState('');
    const availableOptions = useMemo(() => {
        const addedKeywords = new Set(ruleOptions.map(o => o.keyword));
        return Object.keys(optionsDictionary).filter(keyword => {
            const optionInfo = optionsDictionary[keyword];
            if (optionInfo.isModifier) return false;
            if (optionInfo.allowMultiple === false && addedKeywords.has(keyword)) return false;
            if (optionInfo.dependsOn && !addedKeywords.has(optionInfo.dependsOn)) return false;
            
            if (optionInfo.dependsOnProtocol && optionInfo.dependsOnProtocol !== protocol?.toLowerCase()) {
                return false;
            }
            return true;
        });
    }, [ruleOptions, protocol]);
    
    const filteredOptions = searchTerm ? availableOptions.filter(opt => opt.toLowerCase().includes(searchTerm.toLowerCase())) : [];
    
    const handleAdd = (keyword) => {
        const newOption = { keyword: keyword, value: optionsDictionary[keyword].defaultValue };
        if (keyword === 'content') { 
            newOption.modifiers = { nocase: false, depth: '', offset: '' }; 
        }
        onOptionAdd(newOption);
        setSearchTerm('');
    };
    
    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && filteredOptions.length > 0) {
            e.preventDefault();
            handleAdd(filteredOptions[0]);
        }
        if (e.key === 'Backspace' && e.target.value === '') {
            e.preventDefault();
            onDeleteLastOption();
        }
    };
    
    return (
        <div className="add-option-container">
            <input 
                ref={ref} type="text" className="add-option-search" 
                placeholder="+ Seçenek ekle veya ara... (Boşken Backspace ile sil, Esc ile geri dön)" 
                value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} onKeyDown={handleKeyDown} 
            />
            {searchTerm && (
                <ul className="add-option-list">
                    {filteredOptions.map(keyword => (
                        <li key={keyword} onClick={() => handleAdd(keyword)}>
                            {keyword}<span className='option-description'> - {optionsDictionary[keyword].description}</span>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
});

export default AddOption;