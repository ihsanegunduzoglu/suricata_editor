import React from 'react';

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

export default SuggestionsList;