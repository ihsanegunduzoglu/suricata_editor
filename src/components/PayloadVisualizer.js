// src/components/PayloadVisualizer.js

import React, { useState } from 'react';
import analyzePayload from '../utils/payloadAnalyzer';
import { v4 as uuidv4 } from 'uuid';
import { Plus, Trash2, Copy, SearchCode, ClipboardCopy } from 'lucide-react';
import { toast } from 'react-toastify';

const PayloadVisualizer = () => {
    const [rawPayload, setRawPayload] = useState('');
    const [contentMatchers, setContentMatchers] = useState([{ id: uuidv4(), value: '' }, { id: uuidv4(), value: '' }]);
    const [analysisResult, setAnalysisResult] = useState(null);

    const handleAddMatcher = () => setContentMatchers([...contentMatchers, { id: uuidv4(), value: '' }]);
    const handleRemoveMatcher = (id) => setContentMatchers(contentMatchers.filter(m => m.id !== id));
    const handleMatcherChange = (id, value) => {
        setContentMatchers(contentMatchers.map(m => m.id === id ? { ...m, value } : m));
    };
    const handleAnalyze = () => {
        const matcherValues = contentMatchers.map(m => m.value).filter(v => v);
        const result = analyzePayload(rawPayload, matcherValues);
        setAnalysisResult(result);
    };
    const handleCopyToClipboard = (textToCopy, message) => {
        navigator.clipboard.writeText(textToCopy);
        toast.success(message);
    };

    // YENİ: Görselleştirmeyi renklendiren fonksiyon
    const renderVisualization = () => {
        if (!analysisResult?.visualization) return null;

        const contentValues = new Set(analysisResult.results.filter(r => r.found).map(r => r.value));
        const parts = [];
        let lastIndex = 0;

        analysisResult.results.forEach(match => {
            if (match.found) {
                // Eşleşmeden önceki kısım (noktalar)
                if (match.start > lastIndex) {
                    parts.push(<span key={`pre-${match.start}`}>{'.'.repeat(match.start - lastIndex)}</span>);
                }
                // Eşleşen kısım (renkli)
                parts.push(<span key={match.start} className="pv-viz-match">{match.value}</span>);
                lastIndex = match.end + 1;
            }
        });

        // Sondaki kısım (noktalar)
        if (lastIndex < analysisResult.visualization.length) {
            parts.push(<span key="post">{'.'.repeat(analysisResult.visualization.length - lastIndex)}</span>);
        }

        return parts;
    };

    return (
        <div className="payload-visualizer-panel">
            <div className="pv-grid">
                <div className="pv-inputs">
                    <div className="pv-section">
                        <label>Örnek Payload (Metin veya Hex)</label>
                        <textarea
                            value={rawPayload}
                            onChange={(e) => setRawPayload(e.target.value)}
                            placeholder="Payload verisini buraya yapıştırın..."
                            rows={8}
                        />
                    </div>
                    <div className="pv-section">
                        <label>Aranacak Content'ler (Sırasıyla)</label>
                        <div className="pv-matchers-list">
                            {contentMatchers.map((matcher, index) => (
                                <div key={matcher.id} className="pv-matcher-item">
                                    <span>{index + 1}.</span>
                                    <input
                                        type="text"
                                        value={matcher.value}
                                        onChange={(e) => handleMatcherChange(matcher.id, e.target.value)}
                                        placeholder={`Content #${index + 1}`}
                                    />
                                    <button onClick={() => handleRemoveMatcher(matcher.id)} className="pv-matcher-action-btn" disabled={contentMatchers.length <= 1}>
                                        <Trash2 size={16}/>
                                    </button>
                                </div>
                            ))}
                        </div>
                        <button onClick={handleAddMatcher} className="pv-add-matcher-btn">
                            <Plus size={16}/> Content Ekle
                        </button>
                    </div>
                    <button onClick={handleAnalyze} className="pv-analyze-btn">Analiz Et</button>
                </div>

                <div className="pv-results">
                    {analysisResult ? (
                        <>
                            {analysisResult.error && <div className="pv-error">{analysisResult.error}</div>}
                            {analysisResult.visualization && (
                                 <div className="pv-section">
                                    <div className="pv-section-header">
                                        <label>Görselleştirme</label>
                                        <button onClick={() => handleCopyToClipboard(analysisResult.payload, "Payload kopyalandı!")} className="pv-copy-btn" title="Payload'ı Kopyala">
                                            <ClipboardCopy size={14} />
                                        </button>
                                    </div>
                                    <pre className="pv-visualization">{renderVisualization()}</pre>
                                 </div>
                            )}
                            {analysisResult.results?.filter(r => r.found).length > 1 && (
                                <div className="pv-section">
                                    <label>Hesaplanan Değerler</label>
                                    <div className="pv-calculations">
                                        {analysisResult.results.map((result, index) => {
                                            if (index === 0 || !result.found) return null;
                                            const prevResult = analysisResult.results[index-1];
                                            const distanceString = `distance: ${result.distance};`;
                                            const withinString = `within: ${result.within};`;
                                            return (
                                                <div key={index} className="pv-calc-item">
                                                    <div className="pv-calc-header">
                                                        <span><strong>{`"${prevResult.value}"`}</strong> &#8594; <strong>{`"${result.value}"`}</strong></span>
                                                    </div>
                                                    <div className="pv-calc-values">
                                                        <div className="pv-calc-value">
                                                            <span>{distanceString}</span>
                                                            <button onClick={() => handleCopyToClipboard(distanceString, "Distance kopyalandı!")} title="Kopyala">
                                                                <Copy size={14}/>
                                                            </button>
                                                        </div>
                                                        <div className="pv-calc-value">
                                                            <span>{withinString}</span>
                                                            <button onClick={() => handleCopyToClipboard(withinString, "Within kopyalandı!")} title="Kopyala">
                                                                <Copy size={14}/>
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            )
                                        })}
                                    </div>
                                </div>
                            )}
                        </>
                    ) : (
                        <div className="pv-placeholder">
                            <SearchCode size={48} strokeWidth={1} />
                            <p>Analiz sonuçları burada görünecektir.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default PayloadVisualizer;