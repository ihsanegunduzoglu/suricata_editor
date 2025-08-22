// BU KOD BLOĞUNUN TAMAMINI src/App.js DOSYASINA YAPIŞTIR

import React, { useState, useEffect, useRef } from 'react';
import './App.css';

// --- VERİ ---
const suggestionsData = {
  Action: ['alert', 'pass', 'drop', 'reject'],
  Protocol: ['tcp', 'udp', 'icmp', 'ip', 'http', 'tls', 'smb'],
  Direction: ['->', '<>'],
  'Source Port': ['any', '80', '443', '53'],
  'Destination Port': ['any', '80', '443', '53'],
  'Source IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
  'Destination IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
};

// --- BİLEŞENLER ---

const SuggestionsList = ({ suggestions, onSuggestionClick }) => {
  if (!suggestions || suggestions.length === 0) return null;
  return (
    <ul className="suggestions-list">
      {suggestions.map((suggestion, index) => (
        <li
          key={index}
          className="suggestion-item"
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
      <input
        ref={ref}
        type="text"
        value={value}
        onChange={onChange}
        onFocus={onFocus}
        onKeyDown={onKeyDown}
        placeholder="..."
      />
      {isActive && <SuggestionsList suggestions={suggestions} onSuggestionClick={onSuggestionClick} />}
    </div>
  );
});

const HeaderEditor = () => {
  const [headerData, setHeaderData] = useState({
    Action: '', Protocol: '', 'Source IP': '', 'Source Port': '',
    Direction: '', 'Destination IP': '', 'Destination Port': '',
  });
  const [activeInput, setActiveInput] = useState(null);
  const [isHeaderComplete, setIsHeaderComplete] = useState(false);

  const editorRef = useRef(null);
  const inputRefs = useRef([]);
  const labels = ['Action', 'Protocol', 'Source IP', 'Source Port', 'Direction', 'Destination IP', 'Destination Port'];

  const handleFocus = (label) => setActiveInput(label);
  const handleChange = (label, value) => setHeaderData(prev => ({ ...prev, [label]: value }));
  const handleSuggestionClick = (suggestion) => {
    if (activeInput) {
      setHeaderData(prev => ({ ...prev, [activeInput]: suggestion }));
      const currentIndex = labels.indexOf(activeInput);
      const nextIndex = currentIndex + 1;
      if (nextIndex < labels.length) {
          inputRefs.current[nextIndex].focus();
      }
    }
  };
  
  // YENİ DEĞİŞİKLİK: handleKeyDown artık Backspace'i de kontrol ediyor
  const handleKeyDown = (event, currentIndex) => {
    // Space tuşu ile ileri gitme
    if (event.key === ' ' && event.target.value.trim() !== '') {
      event.preventDefault();
      const nextIndex = currentIndex + 1;
      if (nextIndex < labels.length) {
        inputRefs.current[nextIndex].focus();
      } else {
        setIsHeaderComplete(true);
      }
    }

    // Backspace tuşu ile geri gitme
    if (event.key === 'Backspace' && event.target.value === '') {
      event.preventDefault();
      const prevIndex = currentIndex - 1;
      if (prevIndex >= 0) {
        inputRefs.current[prevIndex].focus();
      }
    }
  };

  const handleOptionsKeyDown = (event) => {
    if (event.key === 'Backspace' && event.target.value === '') {
      event.preventDefault();
      setIsHeaderComplete(false);
    }
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (editorRef.current && !editorRef.current.contains(event.target)) setActiveInput(null);
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (!isHeaderComplete && inputRefs.current.length > 0) {
      setTimeout(() => {
        const lastInput = inputRefs.current[labels.length - 1];
        if (lastInput) lastInput.focus();
      }, 0);
    }
  }, [isHeaderComplete]);

  if (isHeaderComplete) {
    const finalHeaderString = labels.map(label => headerData[label]).join(' ');
    return (
      <div className="options-view-container">
        <pre className="final-header-text">{finalHeaderString} (</pre>
        <textarea
          className="options-textarea"
          placeholder='(Boşken "Backspace" tuşuna basarak geri dönebilirsin)'
          autoFocus
          onKeyDown={handleOptionsKeyDown}
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
          onChange={(e) => handleChange(label, e.target.value)}
          onFocus={() => handleFocus(label)}
          onKeyDown={(e) => handleKeyDown(e, index)}
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