// src/components/RegexTester.js

import React, { useState, useMemo } from 'react';
import { TestTube2 } from 'lucide-react';

const RegexTester = () => {
    const [pattern, setPattern] = useState('');
    const [testString, setTestString] = useState('');
    const [result, setResult] = useState(null);

    const handleTest = () => {
        if (!pattern || !testString) {
            setResult({ error: 'Lütfen bir Regex deseni ve test metni girin.' });
            return;
        }
        try {
            const match = pattern.match(new RegExp('^/(.*?)/([gimyus]*)$'));
            const pcrePattern = match ? match[1] : pattern;
            let pcreFlags = match ? match[2] : '';
            if (!pcreFlags.includes('g')) {
                pcreFlags += 'g';
            }

            const regex = new RegExp(pcrePattern, pcreFlags);
            const matches = [...testString.matchAll(regex)];
            
            const processedMatches = matches.map((matchData, index) => ({
                id: index,
                fullMatch: matchData[0],
                groups: matchData.slice(1),
                index: matchData.index
            }));
            
            setResult({ matches: processedMatches });

        } catch (e) {
            setResult({ error: `Geçersiz Regex Deseni: ${e.message}` });
        }
    };

    const renderedResult = useMemo(() => {
        if (!result || !result.matches || result.matches.length === 0) {
            return testString;
        }

        let lastIndex = 0;
        const parts = [];
        
        result.matches.forEach((match) => {
            if (match.index > lastIndex) {
                parts.push(testString.substring(lastIndex, match.index));
            }
            parts.push(<strong key={match.id} className="rt-match">{match.fullMatch}</strong>);
            lastIndex = match.index + match.fullMatch.length;
        });

        if (lastIndex < testString.length) {
            parts.push(testString.substring(lastIndex));
        }

        return parts;
    }, [result, testString]);

    return (
        <div className="regex-tester-panel">
            <div className="rt-grid">
                <div className="rt-inputs">
                    <div className="info-panel-section">
                        <h4 className="info-panel-section-header">PCRE Deseni</h4>
                        <input
                            type="text"
                            value={pattern}
                            onChange={(e) => setPattern(e.target.value)}
                            placeholder="/(windows|chrome|safari)/gi"
                            className="rt-input"
                        />
                    </div>
                    <div className="info-panel-section">
                        <h4 className="info-panel-section-header">Test Edilecek Metin (Payload)</h4>
                        <textarea
                            value={testString}
                            onChange={(e) => setTestString(e.target.value)}
                            placeholder="Regex desenini test etmek için metni buraya yapıştırın..."
                            rows={12}
                        />
                    </div>
                    <button onClick={handleTest} className="pv-analyze-btn">
                        Regex'i Test Et
                    </button>
                </div>

                <div className="rt-results">
                    {result?.error && <div className="pv-error">{result.error}</div>}
                    {!result && (
                         <div className="info-panel-section">
                             <div className="panel-placeholder">
                                <TestTube2 size={48} strokeWidth={1} />
                                <p>Test sonuçları burada görünecektir.</p>
                            </div>
                         </div>
                    )}
                    {result && !result.error && (
                        <div className="info-panel-section">
                             <div className="rt-summary">
                                <strong>{result.matches.length}</strong> adet eşleşme bulundu.
                            </div>
                            <pre className="info-panel-output-box">
                                {result.matches.length > 0 ? renderedResult : <span style={{opacity: 0.6}}>Eşleşme bulunamadı.</span>}
                            </pre>
                            {result.matches.length > 0 && (
                                <div className="rt-match-list-container">
                                    <label>Eşleşme Grupları</label>
                                    <ul className="rt-match-list">
                                        {result.matches.map(match => (
                                            <li key={match.id} className="rt-match-item">
                                                <div className="rt-full-match">
                                                    <span>Tam Eşleşme</span> {match.fullMatch}
                                                </div>
                                                {match.groups.map((group, i) => (
                                                    <div key={i} className="rt-capture-group">
                                                        <span>Grup {i + 1}</span> {group}
                                                    </div>
                                                ))}
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default RegexTester;