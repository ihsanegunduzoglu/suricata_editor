// BU KOD BLOĞUNUN TAMAMINI src/App.js DOSYASINA YAPIŞTİR

import React, { useState, useEffect, useRef, useMemo } from 'react';
import './App.css';

// --- VERİLER ---

// Header kutucukları için öneriler
const suggestionsData = {
  Action: ['alert', 'pass', 'drop', 'reject'],
  Protocol: ['tcp', 'udp', 'icmp', 'ip', 'http', 'tls', 'smb'],
  Direction: ['->', '<>'],
  'Source Port': ['any', '80', '443', '53'],
  'Destination Port': ['any', '80', '443', '53'],
  'Source IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
  'Destination IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
};

// Options (kural seçenekleri) için "sözlük"
const optionsDictionary = {
  'msg': { 
    description: 'Kural mesajı', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val) => `"${val}"` 
  },
  'sid': { 
    description: 'Kural ID', 
    inputType: 'number', 
    defaultValue: '', 
    format: (val) => val ,
    allowMultiple: false
  },
  'rev': { 
    description: 'Revizyon numarası', 
    inputType: 'number', 
    defaultValue: '', 
    format: (val) => val 
  },
  'flow': { 
    description: 'Bağlantı durumu', 
    inputType: 'autocomplete', 
    suggestions: ['established', 'to_client', 'from_server', 'not_established', 'only_stream', 'no_stream'],
    defaultValue: '', 
    format: (val) => val 
  },
  'content': { 
    description: 'Aranacak içerik', 
    inputType: 'text', 
    defaultValue: '', 
    format: (val) => `"${val}"` 
  },
  'nocase': { 
    description: 'Büyük/küçük harf duyarsız arama', 
    inputType: 'flag', 
    defaultValue: '', 
    format: () => '' ,
    allowMultiple : false,
    dependsOn : 'content'
  },
};


// --- BİLEŞENLER ---

const SuggestionsList = ({ suggestions, onSuggestionClick }) => {
  if (!suggestions || suggestions.length === 0) {
    return null;
  }
  return (
    <ul className="suggestions-list">
      {suggestions.map((suggestion, index) => (
        <li
          key={index}
          onMouseDown={(e) => { e.preventDefault(); onSuggestionClick(suggestion); }}
        >
          {suggestion}
        </li>
      ))}
    </ul>
  );
};

const RuleInputBox = React.forwardRef(({ label, value, onChange, onFocus, onKeyDown, isActive, suggestions, onSuggestionClick }, ref) => {
  return (
    <div className="input-group">
      <label>{label}</label>
      <input ref={ref} type="text" value={value} onChange={onChange} onFocus={onFocus} onKeyDown={onKeyDown} placeholder="..." />
      {isActive && <SuggestionsList suggestions={suggestions} onSuggestionClick={onSuggestionClick} />}
    </div>
  );
});

const AutocompleteInput = ({ value, onChange, onStopEditing, suggestions }) => {
    const [showSuggestions, setShowSuggestions] = useState(false);
    const containerRef = useRef(null);

    const filteredSuggestions = suggestions.filter(s => 
        s.toLowerCase().includes(value.toLowerCase())
    );

    const handleSelect = (suggestion) => {
        onChange(suggestion);
        setShowSuggestions(false);
        onStopEditing();
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            if(filteredSuggestions.length > 0) {
                handleSelect(filteredSuggestions[0]);
            } else {
                onStopEditing();
            }
        }
    };

    // Dışarı tıklandığında menüyü kapatmak için
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
            <input
                type="text"
                className="option-value-input"
                value={value}
                onChange={(e) => onChange(e.target.value)}
                onFocus={() => setShowSuggestions(true)}
                onKeyDown={handleKeyDown}
                autoFocus
            />
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

const OptionRow = ({ option, isEditing, onStartEditing, onStopEditing, onValueChange }) => {
  const optionInfo = optionsDictionary[option.keyword];

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      onStopEditing();
    }
  };

  if (isEditing && optionInfo.inputType !== 'flag') {
    return (
      <div className="option-row">
            <span className="option-keyword">{option.keyword}:</span>

            {/* YENİ KOŞULLU MANTIK BURADA */}
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
                <span className="option-value">{optionInfo.format(option.value)}</span>
            </>
        )}
        <span className="option-semicolon">;</span>
    </div>
  );
};

const AddOption = React.forwardRef(({ onOptionAdd, onNavigateBack, ruleOptions }, ref) => {
    const [searchTerm, setSearchTerm] = useState('');
    const availableOptions = useMemo(() => {
        const addedKeywords = new Set(ruleOptions.map(o => o.keyword));

        return Object.keys(optionsDictionary).filter(keyword => {
            const optionInfo = optionsDictionary[keyword];

            // Kural 1: Eğer çoklu kullanıma izin verilmiyorsa ve zaten eklenmişse, gösterme.
            if (optionInfo.allowMultiple === false && addedKeywords.has(keyword)) {
                return false;
            }

            // Kural 2: Eğer bir şeye bağımlıysa ve o şey eklenmemişse, gösterme.
            if (optionInfo.dependsOn && !addedKeywords.has(optionInfo.dependsOn)) {
                return false;
            }

            return true;
        });
    }, [ruleOptions]);

    const filteredOptions = searchTerm
        ? availableOptions.filter(opt => opt.toLowerCase().includes(searchTerm.toLowerCase()))
        : [];
    
    const handleAdd = (keyword) => {
        onOptionAdd({ keyword: keyword, value: optionsDictionary[keyword].defaultValue });
        setSearchTerm('');
    };
    
    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && filteredOptions.length > 0) {
            e.preventDefault();
            handleAdd(filteredOptions[0]);
        }
        if (e.key === 'Backspace' && e.target.value === '') {
            e.preventDefault();
            onNavigateBack();
        }
    };

    return (
        <div className="add-option-container">
            <input 
                ref={ref} 
                type="text" 
                className="add-option-search" 
                placeholder="+ Seçenek ekle veya ara... (Boşken Backspace ile geri dön)" 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)} 
                onKeyDown={handleKeyDown} 
            />
            {searchTerm && (
                <ul className="add-option-list">
                    {filteredOptions.map(keyword => (
                        <li key={keyword} onClick={() => handleAdd(keyword)}>
                            {keyword}
                            <span className='option-description'> - {optionsDictionary[keyword].description}</span>
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

    useEffect(() => {
        if (addOptionInputRef.current) {
            addOptionInputRef.current.focus();
        }
    }, []); 

    const handleValueChange = (newValue) => {
        const updatedOptions = [...ruleOptions];
        if (updatedOptions[editingIndex]) {
            updatedOptions[editingIndex].value = newValue;
            setRuleOptions(updatedOptions);
        }
    };
    
    const handleAddOption = (newOption) => {
        setRuleOptions(prevOptions => {
            const newOptions = [...prevOptions, newOption];
            setEditingIndex(newOptions.length - 1);
            return newOptions;
        });
    };

    const handleStopEditing = () => {
        setEditingIndex(null);
        setTimeout(() => {
            if (addOptionInputRef.current) {
                addOptionInputRef.current.focus();
            }
        }, 0);
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
                        onValueChange={handleValueChange}
                    />
                ))}
            </div>
            <AddOption ref={addOptionInputRef} onOptionAdd={handleAddOption} onNavigateBack={onNavigateBack} ruleOptions={ruleOptions} />
        </div>
    );
};

const HeaderEditor = () => {
  const [headerData, setHeaderData] = useState({'Action':'','Protocol':'','Source IP':'','Source Port':'','Direction':'','Destination IP':'','Destination Port':''});
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

  // HATA DÜZELTMESİ: İlk odaklanma için setTimeout eklendi
  useEffect(() => {
      if (isInitialMount.current) {
          isInitialMount.current = false;
          setTimeout(() => {
            const firstInput = inputRefs.current[0];
            if (firstInput) {
                firstInput.focus();
            }
          }, 0);
      } else if (!isHeaderComplete && hasBeenInOptionMode.current) {
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