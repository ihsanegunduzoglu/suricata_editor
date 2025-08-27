// src/components/RuleInputBox.js

import React from 'react';
import SuggestionsList from './SuggestionsList';

// onBlur prop'unu ekliyoruz
const RuleInputBox = React.forwardRef(({ label, value, onChange, onFocus, onBlur, onKeyDown, isActive, suggestions, onSuggestionClick }, ref) => (
  <div className="input-group">
    <label>{label}</label>
    <input 
        ref={ref} 
        type="text" 
        value={value} 
        onChange={onChange} 
        onFocus={onFocus} 
        onBlur={onBlur} // onBlur olayını input'a bağlıyoruz
        onKeyDown={onKeyDown} 
        placeholder="..." 
    />
    {isActive && <SuggestionsList suggestions={suggestions} onSuggestionClick={onSuggestionClick} />}
  </div>
));

export default RuleInputBox;