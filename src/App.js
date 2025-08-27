// src/App.js

import React from 'react';
import './App.css';
// DEĞİŞİKLİK BURADA: Dosya yolu './' ile düzeltildi
import { RuleProvider, useRule } from './context/RuleContext';
import Workbench from './components/Workbench';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const ThemedApp = () => {
    const { theme } = useRule();
    const toastTheme = theme === 'light' ? 'light' : 'dark';

    return (
        <div className={`theme-wrapper ${theme === 'light' ? 'theme-light' : 'theme-dark'}`}>
            <Workbench />
            <ToastContainer
                position="bottom-right"
                autoClose={5000}
                hideProgressBar={false}
                newestOnTop={false}
                closeOnClick
                rtl={false}
                pauseOnFocusLoss
                draggable
                pauseOnHover
                theme={toastTheme}
            />
        </div>
    );
};

function App() { 
    return (
        <RuleProvider>
            <ThemedApp />
        </RuleProvider>
    ); 
}

export default App;