// src/components/TopMenuBar.js

import React, { useState, useRef, useEffect } from 'react';
import { useRule } from '../context/RuleContext';

const ThemeSwitcher = () => {
    const { theme, toggleTheme } = useRule();
    const isLightMode = theme === 'light';

    return (
        <div className="theme-switcher">
            <span role="img" aria-label="dark mode icon">🌙</span>
            <label className="switch">
                <input 
                    type="checkbox" 
                    checked={isLightMode} 
                    onChange={toggleTheme} 
                />
                <span className="slider round"></span>
            </label>
            <span role="img" aria-label="light mode icon">☀️</span>
        </div>
    );
};



const TopMenuBar = () => {
    const { 
        isRulesListVisible, 
        toggleRulesList, 
        isInfoPanelVisible, 
        toggleInfoPanel 
    } = useRule();

    const [isMenuOpen, setIsMenuOpen] = useState(false);
    const menuRef = useRef(null);

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (menuRef.current && !menuRef.current.contains(event.target)) {
                setIsMenuOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    return (
        <nav className="top-menu-bar">
            <div className="menu-left">
                <div className="menu-item" ref={menuRef}>
                    <button onClick={() => setIsMenuOpen(!isMenuOpen)}>Görünüm</button>
                    {isMenuOpen && (
                        <ul className="dropdown-menu">
                            <li onClick={() => { toggleRulesList(); setIsMenuOpen(false); }}>
                                Kural Listesi {isRulesListVisible ? 'Gizle' : 'Göster'}
                            </li>
                            <li onClick={() => { toggleInfoPanel(); setIsMenuOpen(false); }}>
                                Bilgi Paneli {isInfoPanelVisible ? 'Gizle' : 'Göster'}
                            </li>
                        </ul>
                    )}
                </div>
            </div>
            <div className="menu-right">
                <ThemeSwitcher />
            </div>
        </nav>
    );
};

export default TopMenuBar;