import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify'; // YENİ EKLENEN SATIR: Hata bu satırın eksikliğinden kaynaklanıyordu.

const MitreEditor = ({ onMappingAdd }) => {
    // API'den gelen verileri tutacak state'ler
    const [tactics, setTactics] = useState([]);
    const [techniques, setTechniques] = useState([]);
    const [subtechniques, setSubtechniques] = useState([]);

    // Kullanıcının dropdown'lardan seçtiği değerleri tutacak state'ler
    const [selectedTacticId, setSelectedTacticId] = useState('');
    const [selectedTechniqueId, setSelectedTechniqueId] = useState('');
    const [selectedSubtechniqueId, setSelectedSubtechniqueId] = useState('');
    
    // Veri çekilirken arayüzün kilitlenmesi için loading state'i
    const [isLoading, setIsLoading] = useState(false);

    // 1. Bileşen ilk yüklendiğinde taktik listesini API'den bir kere çek
    useEffect(() => {
        setIsLoading(true);
        fetch('http://127.0.0.1:5000/api/tactics')
            .then(res => res.json())
            .then(data => {
                setTactics(data);
                setIsLoading(false);
            })
            .catch(error => {
                console.error("HATA: Taktikler alınamadı. Python API sunucusunun çalıştığından emin olun.", error);
                setIsLoading(false);
            });
    }, []);

    // 2. Kullanıcı bir taktik seçtiğinde, o taktiğe ait teknikleri çek
    useEffect(() => {
        // `selectedTacticId` boş değilse bu bloğu çalıştır
        if (selectedTacticId) {
            setIsLoading(true);
            // Yeni bir taktik seçildiğinde alt seçimleri temizle
            setTechniques([]);
            setSubtechniques([]);
            setSelectedTechniqueId('');
            setSelectedSubtechniqueId('');

            fetch(`http://127.0.0.1:5000/api/techniques/${selectedTacticId}`)
                .then(res => res.json())
                .then(data => {
                    setTechniques(data);
                    setIsLoading(false);
                });
        }
    }, [selectedTacticId]);

    // 3. Kullanıcı bir teknik seçtiğinde, o tekniğe ait alt-teknikleri çek
    useEffect(() => {
        // `selectedTechniqueId` boş değilse bu bloğu çalıştır
        if (selectedTechniqueId) {
            setIsLoading(true);
            setSubtechniques([]);
            setSelectedSubtechniqueId('');

            fetch(`http://127.0.0.1:5000/api/subtechniques/${selectedTechniqueId}`)
                .then(res => res.json())
                .then(data => {
                    setSubtechniques(data);
                    setIsLoading(false);
                });
        }
    }, [selectedTechniqueId]);

    // "Eşlemeyi Ekle" butonuna tıklandığında çalışacak fonksiyon
    const handleAddClick = () => {
        if (!selectedTacticId || !selectedTechniqueId) {
            toast.warn('Lütfen en az bir Taktik ve Teknik seçin.');
            return;
        }

        // Eğer alt-teknik seçilmişse onu, değilse ana tekniği kullan
        const attackId = selectedSubtechniqueId || selectedTechniqueId;
        // metadata için standart formattaki string'i oluştur
        const mappingString = `attack_id ${attackId}, tactic ${selectedTacticId}`;
        
        // Bu string'i ana bileşene (MetadataEditor -> OptionRow) gönder
        onMappingAdd(mappingString);

        // Kullanıcının aynı taktikten başka teknikler eklemesini kolaylaştırmak için
        // sadece teknik ve alt-teknik seçimini sıfırla.
        setSelectedTechniqueId('');
        setSelectedSubtechniqueId('');
    };

    return (
        <div className="mitre-editor-card">
            <h4>MITRE ATT&CK Eşlemesi Ekle {isLoading && <span className="loader">(Yükleniyor...)</span>}</h4>
            <div className="mitre-selectors">
                <select value={selectedTacticId} onChange={e => setSelectedTacticId(e.target.value)} disabled={isLoading || tactics.length === 0}>
                    <option value="">-- Taktik Seçin --</option>
                    {tactics.map(tactic => (
                        <option key={tactic.id} value={tactic.id}>{tactic.name} ({tactic.id})</option>
                    ))}
                </select>

                <select value={selectedTechniqueId} onChange={e => setSelectedTechniqueId(e.target.value)} disabled={!selectedTacticId || isLoading}>
                    <option value="">-- Teknik Seçin --</option>
                    {techniques.map(tech => (
                        <option key={tech.id} value={tech.id}>{tech.name} ({tech.id})</option>
                    ))}
                </select>
                
                <select value={selectedSubtechniqueId} onChange={e => setSelectedSubtechniqueId(e.target.value)} disabled={!selectedTechniqueId || subtechniques.length === 0 || isLoading}>
                    <option value="">-- (Opsiyonel) Alt-Teknik Seçin --</option>
                    {subtechniques.map(sub => (
                        <option key={sub.id} value={sub.id}>{sub.name} ({sub.id})</option>
                    ))}
                </select>
            </div>
            <button onClick={handleAddClick} className="mitre-add-btn" disabled={!selectedTechniqueId || isLoading}>Eşlemeyi Ekle</button>
        </div>
    );
};

export default MitreEditor;