// src/components/FinalizedRule.js

import React from 'react';

const FinalizedRule = ({ ruleString }) => {
    return (
        <div className="finalized-rule-container">
            <pre className="finalized-rule-text">{ruleString}</pre>
        </div>
    );
};

export default FinalizedRule;