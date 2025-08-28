// src/components/ValidationPanel.js

import React from 'react';
import { useRule } from '../context/RuleContext';

const ValidationPanel = () => {
    const { validationErrors } = useRule();

    // Eğer gösterilecek bir hata veya uyarı yoksa, hiçbir şey gösterme.
    if (!validationErrors || validationErrors.length === 0) {
        return null;
    }

    return (
        <div className="validation-panel">
            <ul className="validation-list">
                {validationErrors.map((error) => (
                    <li key={error.id} className={`validation-item ${error.type}`}>
                        <span className="validation-icon">
                            {error.type === 'error' ? '✖' : '⚠️'}
                        </span>
                        <span className="validation-message">
                            {error.message}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default ValidationPanel; 