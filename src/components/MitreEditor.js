// src/components/MitreEditor.js

import React, { useEffect } from 'react';
import { toast } from 'react-toastify';
import { useRule } from '../context/RuleContext';

const MitreEditor = ({ 
    onMappingAdd, 
    tactics, 
    techniques, 
    subtechniques,
    selectedTacticId, 
    setSelectedTacticId,
    selectedTechnique, 
    setSelectedTechnique,
    selectedSubtechniqueId, 
    setSelectedSubtechniqueId,
    isLoading
}) => {
    const { updateMitreInfo, updateActiveTopic } = useRule();

    useEffect(() => {
        updateMitreInfo({ type: 'tactic_list' });
        return () => { 
            updateMitreInfo(null); 
        };
    }, [updateMitreInfo]);

    useEffect(() => {
        if (selectedTacticId) {
            updateMitreInfo({ type: 'technique_list', tacticId: selectedTacticId });
        } else {
            updateMitreInfo({ type: 'tactic_list' });
        }
    }, [selectedTacticId, updateMitreInfo]);

    useEffect(() => {
        if (selectedTechnique && selectedTechnique.has_subtechniques) {
            updateMitreInfo({ type: 'subtechnique_list', techniqueId: selectedTechnique.id });
        } else if (selectedTechnique) {
            updateMitreInfo({ type: 'technique_list', tacticId: selectedTacticId });
        }
    }, [selectedTechnique, selectedTacticId, updateMitreInfo]);

    const handleTechniqueChange = (e) => {
        const techniqueId = e.target.value;
        const techniqueObject = techniques.find(t => t.id === techniqueId) || null;
        setSelectedTechnique(techniqueObject);
    };

    const handleAddClick = () => {
        if (!selectedTacticId || !selectedTechnique) {
            toast.warn('Lütfen en az bir Taktik ve Teknik seçin.');
            return;
        }
        const attackId = selectedSubtechniqueId || selectedTechnique.id;
        const mappingString = `attack_id ${attackId}, tactic ${selectedTacticId}`;
        
        onMappingAdd(mappingString);
        
        // Eşleme eklenince seçimleri sıfırla ve vurguyu temizle
        setSelectedTacticId(''); // Taktik seçimi de sıfırlandı
        setSelectedTechnique(null);
        setSelectedSubtechniqueId('');
        updateActiveTopic(null); 
    };
    
    const getSubtechniquePlaceholder = () => {
        if (!selectedTechnique) return "-- Önce Teknik Seçin --";
        if (isLoading) return "-- Yükleniyor... --";
        if (!selectedTechnique.has_subtechniques) return "-- Alt-Teknik Yok --";
        return "-- (Opsiyonel) Alt-Teknik Seçin --";
    };

    return (
        <div className="mitre-editor-card">
            <h4>MITRE ATT&CK Eşlemesi Ekle {isLoading && <span className="loader">(Yükleniyor...)</span>}</h4>
            <div className="mitre-selectors" onMouseLeave={() => updateActiveTopic(null)}> {/* Toplu vurgu temizleme */}
                <select 
                    value={selectedTacticId} 
                    onChange={e => setSelectedTacticId(e.target.value)} 
                    disabled={isLoading || tactics.length === 0}
                >
                    <option value="" onMouseEnter={() => updateActiveTopic(null)}>-- Taktik Seçin --</option>
                    {tactics.map(tactic => (
                        <option 
                            key={tactic.id} 
                            value={tactic.id} 
                            onMouseEnter={() => updateActiveTopic(tactic.id)} /* DEĞİŞİKLİK */
                        >
                            {tactic.name} ({tactic.id})
                        </option>
                    ))}
                </select>
                <select 
                    value={selectedTechnique?.id || ''} 
                    onChange={handleTechniqueChange} 
                    disabled={!selectedTacticId || isLoading}
                >
                    <option value="" onMouseEnter={() => updateActiveTopic(null)}>-- Teknik Seçin --</option>
                    {techniques.map(tech => (
                        <option 
                            key={tech.id} 
                            value={tech.id} 
                            onMouseEnter={() => updateActiveTopic(tech.id)} /* DEĞİŞİKLİK */
                        >
                            {tech.name} ({tech.id})
                        </option>
                    ))}
                </select>
                <select 
                    value={selectedSubtechniqueId} 
                    onChange={e => setSelectedSubtechniqueId(e.target.value)} 
                    disabled={!selectedTechnique || !selectedTechnique.has_subtechniques || isLoading}
                >
                    <option value="" onMouseEnter={() => updateActiveTopic(null)}>{getSubtechniquePlaceholder()}</option>
                    {subtechniques.map(sub => (
                        <option 
                            key={sub.id} 
                            value={sub.id} 
                            onMouseEnter={() => updateActiveTopic(sub.id)} /* DEĞİŞİKLİK */
                        >
                            {sub.name} ({sub.id})
                        </option>
                    ))}
                </select>
            </div>
            <button onClick={handleAddClick} className="mitre-add-btn" disabled={!selectedTechnique || isLoading}>Eşlemeyi Ekle</button>
        </div>
    );
};

export default MitreEditor;