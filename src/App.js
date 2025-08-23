// BU KOD BLOGUNUN TAMAMINI src/App.js DOSYASINA YAPIŞTIR

import React, { useState, useEffect, useRef, useMemo } from 'react';
import './App.css';

// --- VERILER ---

const suggestionsData = {
  Action: ['alert', 'pass', 'drop', 'reject'],
  Protocol: ['tcp', 'udp', 'icmp', 'ip', 'http', 'tls', 'smb'],
  Direction: ['->', '<>'],
  'Source Port': ['any', '80', '443', '53'],
  'Destination Port': ['any', '80', '443', '53'],
  'Source IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
  'Destination IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
};

// --- YARDIMCI FONKSIYONLAR ---
const formatModifiersForDisplay = (modifiers) => {
    if (!modifiers) return '';
    let str = '';
    if (modifiers.nocase) str += ' nocase';
    if (modifiers.depth && modifiers.depth !== '') str += ` depth:${modifiers.depth}`;
    if (modifiers.offset && modifiers.offset !== '') str += ` offset:${modifiers.offset}`;
    return str;
};

const optionsDictionary = {
  'msg': { description: 'Kural mesaji', inputType: 'text', defaultValue: '', format: (val) => `"${val}"` },
  'sid': { description: 'Kural ID', inputType: 'number', defaultValue: '', format: (val) => val, allowMultiple: false },
  'rev': { description: 'Revizyon numarasi', inputType: 'number', defaultValue: '1', format: (val) => val, allowMultiple: false },
  'flow': { description: 'Baglanti durumu', inputType: 'autocomplete', suggestions: ['established', 'to_client', 'from_server', 'not_established', 'only_stream', 'no_stream'], defaultValue: '', format: (val) => val },
  'content': { description: 'Aranacak icerik', inputType: 'text', defaultValue: '', format: (val, mods) => `"${val}"${formatModifiersForDisplay(mods)}` },
  // Degistiriciler (Modifiers)
  'nocase': { description: 'Buyuk/kucuk harf duyarsiz arama', inputType: 'flag', defaultValue: false, isModifier: true, dependsOn: 'content' },
  'depth': { description: 'Aramanin baslayacagi byte sayisi', inputType: 'number', defaultValue: '', isModifier: true, dependsOn: 'content' },
  'offset': { description: 'Paket basindan itibaren aramanin baslayacagi ofset', inputType: 'number', defaultValue: '', isModifier: true, dependsOn: 'content' },
};

// --- BİLEŞENLER ---

const SuggestionsList = ({ suggestions, onSuggestionClick }) => {
  if (!suggestions || suggestions.length === 0) return null;
  return (
    <ul className="suggestions-list">
      {suggestions.map((suggestion, index) => (
        <li key={index} onMouseDown={(e) => { e.preventDefault(); onSuggestionClick(suggestion); }}>
          {suggestion}
        </li>
      ))}
    </ul>
  );
};

const RuleInputBox = React.forwardRef(({ label, value, onChange, onFocus, onKeyDown, isActive, suggestions, onSuggestionClick }, ref) => (
  <div className="input-group">
    <label>{label}</label>
    <input ref={ref} type="text" value={value} onChange={onChange} onFocus={onFocus} onKeyDown={onKeyDown} placeholder="..." />
    {isActive && <SuggestionsList suggestions={suggestions} onSuggestionClick={onSuggestionClick} />}
  </div>
));

const AutocompleteInput = ({ value, onChange, onStopEditing, suggestions }) => {
    const [showSuggestions, setShowSuggestions] = useState(false);
    const containerRef = useRef(null);
    const filteredSuggestions = suggestions.filter(s => s.toLowerCase().includes(value.toLowerCase()));

    const handleSelect = (suggestion) => {
        onChange(suggestion);
        setShowSuggestions(false);
        onStopEditing();
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            if (filteredSuggestions.length > 0) {
                handleSelect(filteredSuggestions[0]);
            } else {
                onStopEditing();
            }
        }
    };

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (containerRef.current && !containerRef.current.contains(event.target)) {
                setShowSuggestions(false);
                onStopEditing();
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [onStopEditing]);

    return (
        <div className="autocomplete-container" ref={containerRef}>
            <input type="text" className="option-value-input" value={value}
                onChange={(e) => onChange(e.target.value)} onFocus={() => setShowSuggestions(true)}
                onKeyDown={handleKeyDown} autoFocus />
            {showSuggestions && (
                <ul className="suggestions-list">
                    {filteredSuggestions.map((suggestion, index) => (
                        <li key={index} onMouseDown={() => handleSelect(suggestion)}>
                            {suggestion}
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};

const ContentEditor = ({ option, onValueChange, onStopEditing }) => {
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
    };

    const handleCommandKeyDown = (e) => {
        if (e.key === 'Escape') {
            onStopEditing();
            return;
        }
        if (e.key === 'Enter') {
            e.preventDefault();
            if (command === '' && document.activeElement === commandInputRef.current) {
                onStopEditing();
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
        <div className="option-row-editing-card" onKeyDown={handleCommandKeyDown}>
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
                            <input type="checkbox" id={`nocase-${option.value}`} checked={!!option.modifiers?.nocase} 
                                   onChange={(e) => handleModifierChange('nocase', e.target.checked)} />
                            <label htmlFor={`nocase-${option.value}`}>nocase</label>
                        </div>
                        <div className="modifier-item">
                            <label htmlFor={`depth-${option.value}`}>depth:</label>
                            <input type="number" id={`depth-${option.value}`} ref={modifierInputs.depth} value={option.modifiers?.depth || ''}
                                   onChange={(e) => handleModifierChange('depth', e.target.value)}
                                   onKeyDown={handleModifierInputKeyDown}
                            />
                        </div>
                        <div className="modifier-item">
                            <label htmlFor={`offset-${option.value}`}>offset:</label>
                            <input type="number" id={`offset-${option.value}`} ref={modifierInputs.offset} value={option.modifiers?.offset || ''}
                                   onChange={(e) => handleModifierChange('offset', e.target.value)}
                                   onKeyDown={handleModifierInputKeyDown}
                            />
                        </div>
                    </div>
                    <div className="add-option-container">
                        <input type="text" className="add-option-search" placeholder="+ Değiştirici ekle (veya Esc/Enter ile bitir)"
                               ref={commandInputRef} value={command} onChange={e => setCommand(e.target.value)} />
                        {command && <ul className="add-option-list">{filteredModifiers.map(k => <li key={k} onMouseDown={() => { setCommand(k); handleCommandKeyDown({ key: 'Enter', preventDefault: () => { } }); }}>{k}</li>)}</ul>}
                    </div>
                </>
            )}
        </div>
    );
};

const OptionRow = ({ option, isEditing, onStartEditing, onStopEditing, onValueChange }) => {
    const optionInfo = optionsDictionary[option.keyword];
    const handleKeyDown = (e) => { if (e.key === 'Enter') onStopEditing(); };

    if (isEditing && optionInfo.inputType !== 'flag') {
        if (option.keyword === 'content') {
            return <ContentEditor 
                option={option} 
                onValueChange={(value, modifiers) => onValueChange({ value, modifiers })} 
                onStopEditing={onStopEditing} 
            />;
        }
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

    return (
        <div className="option-row" onClick={optionInfo.inputType !== 'flag' ? onStartEditing : undefined}>
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

const AddOption = React.forwardRef(({ onOptionAdd, onDeleteLastOption, ruleOptions }, ref) => {
    const [searchTerm, setSearchTerm] = useState('');
    const availableOptions = useMemo(() => {
        const addedKeywords = new Set(ruleOptions.map(o => o.keyword));
        return Object.keys(optionsDictionary).filter(keyword => {
            const optionInfo = optionsDictionary[keyword];
            if (optionInfo.isModifier) return false;
            if (optionInfo.allowMultiple === false && addedKeywords.has(keyword)) return false;
            if (optionInfo.dependsOn && !addedKeywords.has(optionInfo.dependsOn)) return false;
            return true;
        });
    }, [ruleOptions]);
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

const OptionsBuilder = ({ ruleOptions, setRuleOptions, onNavigateBack }) => {
    const [editingIndex, setEditingIndex] = useState(null);
    const addOptionInputRef = useRef(null);
    
    // DEĞİŞİKLİK 1: Odaklanma yönetimi basitleştirildi.
    // Bu useEffect artık sadece `editingIndex` durumunu izliyor.
    useEffect(() => {
        // Eğer hiçbir seçenek düzenlenmiyorsa, alttaki ana input'a odaklan.
        if (editingIndex === null) {
            // setTimeout, diğer DOM olayları bittikten sonra focus işleminin
            // güvenilir bir şekilde yapılmasını sağlar.
            setTimeout(() => {
                addOptionInputRef.current?.focus();
            }, 0);
        }
        // `editingIndex` null değilse, bir seçenek düzenleniyor demektir.
        // Bu durumda ilgili OptionRow içindeki input'un `autoFocus` özelliği
        // odaklanmayı kendisi halledecektir. Buradan müdahale etmiyoruz.
    }, [editingIndex]);
    
    // Escape tuşuyla geri dönme işlevi ayrı bir useEffect'e taşındı.
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
    
    // DEĞİŞİKLİK 2: handleAddOption fonksiyonu eski, basit ve atomik haline geri döndürüldü.
    const handleAddOption = (newOption) => { 
        setRuleOptions(prev => {
            const newOpts = [...prev, newOption];
            // Yeni seçeneği ekle ve hemen ardından düzenleme indeksini ayarla.
            setEditingIndex(newOpts.length - 1);
            return newOpts;
        }); 
    };
    
    // DEĞİŞİKLİK 3: handleStopEditing basitleştirildi. Sadece indeksi null yapıyor.
    // Odaklanma işini yukarıdaki useEffect hallediyor.
    const handleStopEditing = () => { 
        setEditingIndex(null); 
    };
    
    return (
        <div className="options-builder">
            <div className="added-options-list">
                {ruleOptions.map((option, index) => (
                    <OptionRow 
                        key={index} 
                        option={option} 
                        isEditing={index === editingIndex} 
                        onStartEditing={() => setEditingIndex(index)} 
                        onStopEditing={handleStopEditing} 
                        onValueChange={(newValue) => handleValueChange(index, newValue)} 
                    />
                ))}
            </div>
            <AddOption 
                ref={addOptionInputRef} 
                onOptionAdd={handleAddOption} 
                onDeleteLastOption={handleDeleteLastOption} 
                ruleOptions={ruleOptions} 
            />
        </div>
    );
};

const HeaderEditor = () => {
    const [headerData, setHeaderData] = useState({ 'Action': '', 'Protocol': '', 'Source IP': '', 'Source Port': '', 'Direction': '', 'Destination IP': '', 'Destination Port': '' });
    const [activeInput, setActiveInput] = useState(null);
    const [isHeaderComplete, setIsHeaderComplete] = useState(false);
    const [ruleOptions, setRuleOptions] = useState([]);
    const editorRef = useRef(null);
    const inputRefs = useRef([]);
    const labels = Object.keys(headerData);
    const isInitialMount = useRef(true);
    const hasBeenInOptionMode = useRef(false);
    
    const handleFocus = (label) => setActiveInput(label);
    const handleChange = (label, value) => setHeaderData(prev => ({ ...prev, [label]: value }));
    const handleSuggestionClick = (suggestion) => { 
        if (activeInput) { 
            handleChange(activeInput, suggestion); 
            const currentIndex = labels.indexOf(activeInput); 
            const nextIndex = currentIndex + 1; 
            if (nextIndex < labels.length) { 
                inputRefs.current[nextIndex].focus(); 
            } 
        } 
    };
    
    const handleKeyDown = (e, currentIndex) => {
        if (e.key === ' ' && e.target.value.trim() !== '') { 
            e.preventDefault(); 
            const nextIndex = currentIndex + 1; 
            if (nextIndex < labels.length) { 
                inputRefs.current[nextIndex].focus(); 
            } else { 
                setIsHeaderComplete(true); 
                hasBeenInOptionMode.current = true; 
            } 
        }
        if (e.key === 'Backspace' && e.target.value === '') { 
            e.preventDefault(); 
            const prevIndex = currentIndex - 1; 
            if (prevIndex >= 0) { 
                inputRefs.current[prevIndex].focus(); 
            } 
        }
    };
    
    useEffect(() => {
        const handleClickOutside = (e) => { 
            if (editorRef.current && !editorRef.current.contains(e.target)) { 
                setActiveInput(null); 
            } 
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);
    
    useEffect(() => {
        if (isInitialMount.current) { 
            isInitialMount.current = false; 
            setTimeout(() => { 
                const firstInput = inputRefs.current[0]; 
                if (firstInput) { 
                    firstInput.focus(); 
                } 
            }, 0); 
        } 
        else if (!isHeaderComplete && hasBeenInOptionMode.current) { 
            setTimeout(() => { 
                const lastInput = inputRefs.current[labels.length - 1]; 
                if (lastInput) { 
                    lastInput.focus(); 
                } 
            }, 0); 
        }
    }, [isHeaderComplete, labels.length]);
    
    if (isHeaderComplete) {
        const finalHeaderString = labels.map(label => headerData[label]).join(' ');
        return (
            <div className="options-view-container">
                <pre className="final-header-text">{finalHeaderString} (</pre>
                <OptionsBuilder 
                    ruleOptions={ruleOptions} 
                    setRuleOptions={setRuleOptions} 
                    onNavigateBack={() => setIsHeaderComplete(false)} 
                />
                <div className="final-header-text">)</div>
            </div>
        );
    }

    return (
        <div className="editor-row" ref={editorRef}>
            {labels.map((label, index) => (
                <RuleInputBox 
                    key={label} 
                    ref={el => inputRefs.current[index] = el} 
                    label={label} 
                    value={headerData[label]} 
                    onChange={e => handleChange(label, e.target.value)} 
                    onFocus={() => handleFocus(label)} 
                    onKeyDown={e => handleKeyDown(e, index)} 
                    isActive={activeInput === label} 
                    suggestions={suggestionsData[label]} 
                    onSuggestionClick={handleSuggestionClick} 
                />
            ))}
        </div>
    );
};

function App() { 
    return (
        <div className="app-container">
            <HeaderEditor />
        </div>
    ); 
}

export default App;