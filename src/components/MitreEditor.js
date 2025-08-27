// src/components/MitreEditor.js

import React, { useEffect } from 'react';
import { toast } from 'react-toastify';
import { useRule } from '../context/RuleContext';
import CustomSelect from './CustomSelect'; // Yeni bileşeni import ediyoruz

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
    const { updateMitreInfo } = useRule();

    useEffect(() => {
        updateMitreInfo({ type: 'tactic_list' });
        return () => { updateMitreInfo(null); };
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

    const handleTechniqueChange = (techniqueId) => {
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
        setSelectedTacticId('');
        setSelectedTechnique(null);
        setSelectedSubtechniqueId('');
    };
    
    const getSubtechniquePlaceholder = () => {
        if (!selectedTechnique) return "Önce Teknik Seçin";
        if (isLoading) return "Yükleniyor...";
        if (!selectedTechnique.has_subtechniques) return "Alt-Teknik Yok";
        return "(Opsiyonel) Alt-Teknik Seçin";
    };

    return (
        <div className="mitre-editor-card">
            <h4>MITRE ATT&CK Eşlemesi Ekle {isLoading && <span className="loader">(Yükleniyor...)</span>}</h4>
            <div className="mitre-selectors">
                <CustomSelect
                    placeholder="-- Taktik Seçin --"
                    options={tactics}
                    value={selectedTacticId}
                    onChange={(id) => setSelectedTacticId(id)}
                    disabled={isLoading || tactics.length === 0}
                />
                <CustomSelect
                    placeholder="-- Teknik Seçin --"
                    options={techniques}
                    value={selectedTechnique?.id}
                    onChange={handleTechniqueChange}
                    disabled={!selectedTacticId || isLoading}
                />
                <CustomSelect
                    placeholder={getSubtechniquePlaceholder()}
                    options={subtechniques}
                    value={selectedSubtechniqueId}
                    onChange={(id) => setSelectedSubtechniqueId(id)}
                    disabled={!selectedTechnique || !selectedTechnique.has_subtechniques || isLoading}
                />
            </div>
            <button onClick={handleAddClick} className="mitre-add-btn" disabled={!selectedTechnique || isLoading}>Eşlemeyi Ekle</button>
        </div>
    );
};

export default MitreEditor;