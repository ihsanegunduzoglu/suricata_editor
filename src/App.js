// src/App.js

import React from 'react';
import './App.css';
import { RuleProvider } from './context/RuleContext';
import Workbench from './components/Workbench';

function App() { 
    return (
        <RuleProvider>
            <Workbench />
        </RuleProvider>
    ); 
}

export default App;