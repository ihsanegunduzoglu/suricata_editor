// src/components/ValidationPanel.js
import React from 'react';
import { useRule } from '../context/RuleContext';
import { AlertTriangle, XCircle } from 'lucide-react';

const ValidationPanel = () => {
    const { validationErrors } = useRule();
    if (!validationErrors || validationErrors.length === 0) {
        return null;
    }

    return (
        <div className="validation-panel">
            <ul className="validation-list">
                {validationErrors.map((error) => (
                    <li key={error.id} className={`validation-item ${error.type}`}>
                        <span className="validation-icon">
                            {error.type === 'error' ? <XCircle size={16} /> : <AlertTriangle size={16} />}
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