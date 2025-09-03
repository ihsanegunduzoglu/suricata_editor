// src/components/RuleTesterPanel.js

import React, { useState, useRef, useEffect } from 'react';
import { useRule } from '../context/RuleContext';
import { TestTube2, UploadCloud, LoaderCircle, FileText, Edit, AlertTriangle, ChevronRight } from 'lucide-react';
import { toast } from 'react-toastify';
import { generateRuleString } from '../utils/ruleGenerator';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus, vs } from 'react-syntax-highlighter/dist/esm/styles/prism';

// Yeni, daha detaylı alarm görüntüleme bileşeni
const AlertsDisplay = ({ result, theme }) => {
    if (!result) {
        return <div className="rt-placeholder-text">Test sonuçları burada görünecek.</div>;
    }

    if (result.error) {
        return (
            <div className="rt-error-container">
                <p className="rt-error-title">HATA: {result.error}</p>
                {result.details && <>
                    <p className="rt-error-details-label">Detaylar:</p>
                    <pre className="rt-error-details">{result.details}</pre>
                </>}
            </div>
        );
    }

    if (result.alert_count === 0) {
        return (
            <div className="rt-no-alerts">
                <AlertTriangle size={24} />
                <p>Test tamamlandı, ancak hiçbir alarm üretilmedi.</p>
            </div>
        );
    }

    return (
        <div className="rt-alerts-list">
            {result.alerts.map((alert, index) => (
                <div key={index} className="rt-alert-card">
                    <div className="rt-alert-header">
                        <span className="rt-alert-severity" data-severity={alert.severity}>
                            Önem Düzeyi: {alert.severity}
                        </span>
                        <span className="rt-alert-signature">#{alert.signature_id}: {alert.signature}</span>
                    </div>
                    <div className="rt-alert-details">
                        <p><strong>Zaman:</strong> {new Date(alert.timestamp).toLocaleString()}</p>
                        <p><strong>Kategori:</strong> {alert.category}</p>
                        <p className="rt-alert-flow">
                            <strong>Akış:</strong> {alert.src_ip}:{alert.src_port} <ChevronRight size={14}/> {alert.dest_ip}:{alert.dest_port} ({alert.protocol})
                        </p>
                        {alert.http?.hostname && <p><strong>Hostname:</strong> {alert.http.hostname}</p>}
                        {alert.http?.url && <p><strong>URL:</strong> {alert.http.url}</p>}
                        {alert.http?.user_agent && <p><strong>User-Agent:</strong> {alert.http.user_agent}</p>}
                    </div>
                    {alert.payload && (
                        <div className="rt-alert-payload">
                            <label>Eşleşen Veri (Payload)</label>
                            <pre>{alert.payload}</pre>
                        </div>
                    )}
                </div>
            ))}
        </div>
    );
};


const RuleTesterPanel = () => {
    const { theme, activeSession, ruleToTest, setRuleToTest } = useRule();
    const [pcapFile, setPcapFile] = useState(null);
    const [rulesFile, setRulesFile] = useState(null);
    const [testMode, setTestMode] = useState('active_rule');
    const [isLoading, setIsLoading] = useState(false);
    const [testResult, setTestResult] = useState(null);
    const pcapInputRef = useRef(null);
    const rulesInputRef = useRef(null);
    const syntaxTheme = theme === 'light' ? vs : vscDarkPlus;

    useEffect(() => {
        const currentRuleInEditor = (activeSession.headerData.Action && activeSession.headerData.Protocol)
            ? generateRuleString(activeSession.headerData, activeSession.ruleOptions)
            : '';
        if (testMode === 'active_rule' || !ruleToTest) {
             setRuleToTest(currentRuleInEditor);
        }
    }, [activeSession, testMode, setRuleToTest, ruleToTest]);


    const handlePcapFileChange = (event) => {
        const file = event.target.files[0];
        if (file && (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng'))) {
            setPcapFile(file);
        } else {
            if(file) toast.warn("Lütfen .pcap veya .pcapng uzantılı bir dosya seçin.");
            setPcapFile(null);
            if(pcapInputRef.current) pcapInputRef.current.value = null;
        }
    };

    const handleRulesFileChange = (event) => {
        const file = event.target.files[0];
        if (file && file.name.endsWith('.rules')) {
            setRulesFile(file);
        } else {
            if(file) toast.warn("Lütfen .rules uzantılı bir dosya seçin.");
            setRulesFile(null);
            if(rulesInputRef.current) rulesInputRef.current.value = null;
        }
    };
    
    const handlePcapUploadClick = () => {
        if (pcapInputRef.current) pcapInputRef.current.value = null;
        pcapInputRef.current.click();
    };
    
    const handleRulesUploadClick = () => {
        if (rulesInputRef.current) rulesInputRef.current.value = null;
        rulesInputRef.current.click();
    };

    const handleTestRule = async () => {
        if (!pcapFile) {
            toast.error("Lütfen önce bir PCAP dosyası seçin.");
            return;
        }

        const formData = new FormData();
        formData.append('pcap_file', pcapFile);

        if (testMode === 'active_rule') {
            if (!ruleToTest || !ruleToTest.trim()) {
                toast.error("Test edilecek geçerli bir kural bulunmuyor.");
                return;
            }
            formData.append('rule_string', ruleToTest);
        } else if (testMode === 'rules_file') {
            if (!rulesFile) {
                toast.error("Lütfen önce bir .rules dosyası seçin.");
                return;
            }
            formData.append('rules_file', rulesFile);
        }
        
        setIsLoading(true);
        setTestResult(null);

        try {
            const response = await fetch('http://127.0.0.1:5000/api/test-rule', {
                method: 'POST',
                body: formData,
            });
            const data = await response.json();
            if (!response.ok) {
                 const errorData = {
                    error: data.error || 'Bilinmeyen bir sunucu hatası oluştu.',
                    details: data.details || 'Ek detay bulunmuyor.'
                };
                throw errorData;
            }
            
            setTestResult(data);
            if (data.alert_count > 0) {
                toast.success(`Test tamamlandı! ${data.alert_count} alarm bulundu.`);
            } else {
                toast.info("Test tamamlandı, alarm bulunamadı.");
            }
        } catch (error) {
            setTestResult({ error: error.error, details: error.details });
            toast.error(`Test sırasında bir hata oluştu: ${error.error}`);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="rule-tester-panel">
            <div className="rt-setup-section">
                <h3><TestTube2 size={20} /> Test Kurulumu</h3>
                
                <div className="rt-section">
                    <label>1. Test Edilecek Kural(lar)</label>
                    <div className="rt-mode-selector">
                        <button 
                            className={`rt-mode-btn ${testMode === 'active_rule' ? 'active' : ''}`}
                            onClick={() => setTestMode('active_rule')}>
                            <Edit size={14}/> Aktif/Seçili Kural
                        </button>
                        <button 
                            className={`rt-mode-btn ${testMode === 'rules_file' ? 'active' : ''}`}
                            onClick={() => setTestMode('rules_file')}>
                            <FileText size={14}/> Kural Dosyası
                        </button>
                    </div>

                    {testMode === 'active_rule' ? (
                        <div className="rt-active-rule-display syntax-highlight-container">
                             <SyntaxHighlighter language="bash" style={syntaxTheme} customStyle={{ margin: 0, padding: '1em', backgroundColor: 'transparent' }}>
                                {ruleToTest || "Test edilecek aktif kural yok."}
                            </SyntaxHighlighter>
                        </div>
                    ) : (
                        <div className="rt-file-upload-area standalone">
                            <input type="file" accept=".rules" onChange={handleRulesFileChange} ref={rulesInputRef} style={{ display: 'none' }}/>
                            <button className="rt-upload-btn" onClick={handleRulesUploadClick} disabled={isLoading}>
                                <UploadCloud size={18} /> .rules Dosyası Yükle
                            </button>
                            {rulesFile && <span className="rt-file-name">{rulesFile.name}</span>}
                        </div>
                    )}
                </div>

                <div className="rt-section">
                    <label>2. Test Trafiği</label>
                    <div className="rt-file-upload-area standalone">
                        <input type="file" accept=".pcap,.pcapng" onChange={handlePcapFileChange} ref={pcapInputRef} style={{ display: 'none' }}/>
                        <button className="rt-upload-btn" onClick={handlePcapUploadClick} disabled={isLoading}>
                            <UploadCloud size={18} /> PCAP Dosyası Yükle
                        </button>
                        {pcapFile && <span className="rt-file-name">{pcapFile.name}</span>}
                    </div>
                </div>

                 <button onClick={handleTestRule} className="pv-analyze-btn rt-start-btn" disabled={isLoading}>
                    {isLoading ? <LoaderCircle size={20} className="rt-spinner" /> : "Testi Başlat"}
                </button>
            </div>
            
            <div className="rt-results-section">
                <h3>Sonuçlar</h3>
                <div className="rt-results-output">
                    <AlertsDisplay result={testResult} theme={theme} />
                </div>
            </div>
        </div>
    );
};

export default RuleTesterPanel;