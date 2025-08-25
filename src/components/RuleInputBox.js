// src/components/RuleInputBox.js

import React from 'react';
import SuggestionsList from './SuggestionsList';

// DEĞİŞİKLİK: Bu bileşen artık filtreleme yapmıyor, sadece hazır 'suggestions' listesini alıyor.
const RuleInputBox = React.forwardRef(({ label, value, onChange, onFocus, onKeyDown, isActive, suggestions, onSuggestionClick }, ref) => (
  <div className="input-group">
    <label>{label}</label>
    <input ref={ref} type="text" value={value} onChange={onChange} onFocus={onFocus} onKeyDown={onKeyDown} placeholder="..." />
    {isActive && <SuggestionsList suggestions={suggestions} onSuggestionClick={onSuggestionClick} />}
  </div>
));

export default RuleInputBox;