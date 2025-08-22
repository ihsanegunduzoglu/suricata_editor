// BU KOD BLOĞUNUN TAMAMINI src/App.js DOSYASINA YAPIŞTIR

import React, { useState, useEffect, useRef } from 'react';
import './App.css';

// --- VERİ ---
// Her kutu için gösterilecek seçenekleri burada tanımlıyoruz
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

// BİLEŞEN 1: Öneri Listesi
const SuggestionsList = ({ suggestions, onSuggestionClick }) => {
  if (!suggestions || suggestions.length === 0) {
    return null;
  }

  return (
    <ul className="suggestions-list">
      {suggestions.map((suggestion, index) => (
        <li
          key={index}
          className="suggestion-item"
          onMouseDown={(e) => {
            e.preventDefault(); // Input'un blur olmasını engelle
            onSuggestionClick(suggestion);
          }}
        >
          {suggestion}
        </li>
      ))}
    </ul>
  );
};

// BİLEŞEN 2: Tek bir giriş kutusu
const RuleInputBox = ({ label, value, onChange, onFocus, isActive, suggestions, onSuggestionClick }) => {
  return (
    <div className="input-group">
      <label>{label}</label>
      <input
        type="text"
        value={value}
        onChange={onChange}
        onFocus={onFocus}
        placeholder="..."
      />
      {isActive && <SuggestionsList suggestions={suggestions} onSuggestionClick={onSuggestionClick} />}
    </div>
  );
};

// BİLEŞEN 3: Tüm giriş kutularını bir araya getiren ana editör alanı
const HeaderEditor = () => {
  const [headerData, setHeaderData] = useState({
    Action: 'alert',
    Protocol: 'tcp',
    'Source IP': '$HOME_NET',
    'Source Port': 'any',
    Direction: '->',
    'Destination IP': 'any',
    'Destination Port': 'any',
  });

  const [activeInput, setActiveInput] = useState(null);
  const editorRef = useRef(null);

  const handleFocus = (label) => {
    setActiveInput(label);
  };

  const handleChange = (label, value) => {
    setHeaderData((prevData) => ({
      ...prevData,
      [label]: value,
    }));
  };

  const handleSuggestionClick = (suggestion) => {
    if (activeInput) {
      setHeaderData((prevData) => ({
        ...prevData,
        [activeInput]: suggestion,
      }));
      setActiveInput(null); // Seçimden sonra listeyi kapat
    }
  };

  // Dışarı tıklandığında listeyi kapatmak için
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (editorRef.current && !editorRef.current.contains(event.target)) {
        setActiveInput(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const labels = ['Action', 'Protocol', 'Source IP', 'Source Port', 'Direction', 'Destination IP', 'Destination Port'];

  return (
    <div className="editor-row" ref={editorRef}>
      {labels.map(label => (
        <RuleInputBox
          key={label}
          label={label}
          value={headerData[label]}
          onChange={(e) => handleChange(label, e.target.value)}
          onFocus={() => handleFocus(label)}
          isActive={activeInput === label}
          suggestions={suggestionsData[label]}
          onSuggestionClick={handleSuggestionClick}
        />
      ))}
    </div>
  );
};


// BİLEŞEN 4: Ana Uygulama
function App() {
  return (
    <div className="app-container">
      <HeaderEditor />
    </div>
  );
}

export default App;