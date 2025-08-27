import React, { useRef, useEffect } from 'react'; // useEffect'i import ediyoruz
import { optionsDictionary } from '../data/optionsDictionary';
import ContentEditor from './ContentEditor';
import AutocompleteInput from './AutocompleteInput';
import { toast } from 'react-toastify';
import { validateOptionField } from '../utils/ruleValidator';
import MitreEditor from './MitreEditor';

const OptionRow = ({ option, isEditing, onStartEditing, onStopEditing, onValueChange }) => {
    const optionInfo = optionsDictionary[option.keyword];
    
    const handleBlur = () => {
        const errorMessage = validateOptionField(option.keyword, option.value);
        if (errorMessage) {
            toast.warn(errorMessage);
        }
        onStopEditing();
    };

    const handleKeyDown = (e) => { 
        if (e.key === 'Enter' && e.target.tagName.toLowerCase() !== 'textarea') {
            e.preventDefault();
            handleBlur();
        }
    };

    const handleNumericChange = (e) => {
        const value = e.target.value;
        if (value === '' || /^\d+$/.test(value)) {
            onValueChange(value);
        }
    };

    const MetadataEditor = () => {
        const [showMitre, setShowMitre] = React.useState(false);
        const editorRef = useRef(null);

        const handleMappingAdd = (mappingString) => {
            const currentValue = option.value || '';
            const separator = currentValue.trim() === '' ? '' : ', ';
            onValueChange(currentValue + separator + mappingString);
            setShowMitre(false);
        };
        
        // YENİ "DIŞARI TIKLAMA" KONTROLÜ
        useEffect(() => {
            const handleClickOutside = (event) => {
                // Eğer referans tanımlıysa VE tıklanan yer referansın (yani kartın) içinde değilse...
                if (editorRef.current && !editorRef.current.contains(event.target)) {
                    onStopEditing(); // Editörü kapat.
                }
            };
            // Kullanıcı fareye bastığında bu fonksiyonu dinle
            document.addEventListener("mousedown", handleClickOutside);
            return () => {
                // Bileşen ekrandan kaldırıldığında dinleyiciyi temizle (hafıza sızıntısını önler)
                document.removeEventListener("mousedown", handleClickOutside);
            };
        }, [editorRef]); // Bu effect sadece bir kere çalışacak

        return (
            // onBlur olayını tamamen kaldırıyoruz.
            <div className="option-row-editing-card" ref={editorRef}>
                <div className="option-row">
                    <span className="option-keyword">{option.keyword}:</span>
                    <textarea 
                        className="option-value-input" 
                        value={option.value} 
                        onChange={(e) => onValueChange(e.target.value)}
                        autoFocus 
                        placeholder="Örn: author Emre, created_at 2025_08_27"
                        rows={2}
                    />
                    <span className="option-semicolon">;</span>
                </div>
                <div className="metadata-toolbar" style={{textAlign: 'right', marginTop: '10px'}}>
                    <button onClick={() => setShowMitre(!showMitre)} style={{cursor: 'pointer'}}>
                        {showMitre ? 'MITRE Editörünü Gizle' : 'MITRE ATT&CK Ekle'}
                    </button>
                </div>
                {showMitre && <MitreEditor onMappingAdd={handleMappingAdd} />}
            </div>
        );
    };

    if (isEditing && optionInfo.inputType !== 'flag') {
        if (option.keyword === 'content') {
            return (
                <ContentEditor 
                    option={option} 
                    onValueChange={(value, modifiers) => onValueChange({ value, modifiers })} 
                    onStopEditing={onStopEditing} 
                />
            );
        }

        if (option.keyword === 'metadata') {
            return <MetadataEditor />;
        }

        const isNumericOnly = ['sid', 'rev', 'priority'].includes(option.keyword);
        const changeHandler = isNumericOnly ? handleNumericChange : (e) => onValueChange(e.target.value);

        return (
            <div className="option-row">
                <span className="option-keyword">{option.keyword}:</span>
                {optionInfo.inputType === 'autocomplete' ? (
                    <AutocompleteInput 
                        suggestions={optionInfo.suggestions} 
                        value={option.value} 
                        onChange={onValueChange} 
                        onStopEditing={handleBlur}
                    />
                ) : (
                    <input 
                        type="text" 
                        className="option-value-input" 
                        value={option.value} 
                        onChange={changeHandler}
                        onBlur={handleBlur}
                        onKeyDown={handleKeyDown} 
                        autoFocus 
                    />
                )}
                <span className="option-semicolon">;</span>
            </div>
        );
    }

    return (
        <div className="option-row" onClick={optionInfo.inputType !== 'flag' ? () => onStartEditing(option.keyword) : undefined}>
            {optionInfo.inputType === 'flag' ? (
                <span className="option-keyword">{option.keyword}</span>
            ) : (
                <>
                    <span className="option-keyword">{option.keyword}:</span>
                    <span className="option-value">{optionInfo.format(option.value, option.modifiers)}</span>
                </>
            )}
            <span className="option-semicolon">;</span>
        </div>
    );
};

export default OptionRow;