// src/App.js

import React from 'react';
import './App.css';
import HeaderEditor from './components/HeaderEditor';
import { RuleProvider } from './context/RuleContext'; // Provider'ı import et

function App() { 
    return (
        <RuleProvider>
            <div className="app-container">
                <HeaderEditor />
            </div>
        </RuleProvider>
    ); 
}

export default App;