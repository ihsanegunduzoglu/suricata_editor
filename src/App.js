// src/App.js

import React from 'react';
import './App.css';
import { RuleProvider } from './context/RuleContext';
import Workbench from './components/Workbench';

// YENİ: react-toastify importları
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

function App() { 
    return (
        <RuleProvider>
            <Workbench />
            {/* YENİ: ToastContainer'ı uygulamamızın en üst seviyesine ekliyoruz.
              Tüm bildirimler burada görünecek. theme="dark" ile karanlık temamıza uyumlu hale getiriyoruz.
            */}
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
                theme="dark"
            />
        </RuleProvider>
    ); 
}

export default App;