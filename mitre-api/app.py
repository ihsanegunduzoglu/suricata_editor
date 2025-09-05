# app.py
import os
import requests
from flask import Flask, jsonify
from flask_cors import CORS
from mitreattack.stix20 import MitreAttackData

# --- Veri Yükleme ve Önbellekleme ---
def load_mitre_data():
    STIX_FILE = "enterprise-attack.json"
    STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    if not os.path.exists(STIX_FILE):
        print(f"'{STIX_FILE}' bulunamadı, indiriliyor...")
        try:
            response = requests.get(STIX_URL, stream=True)
            response.raise_for_status()
            with open(STIX_FILE, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192): f.write(chunk)
            print(f"'{STIX_FILE}' başarıyla indirildi.")
        except requests.exceptions.RequestException as e:
            print(f"HATA: MITRE verisi indirilemedi. Detay: {e}")
            exit()
    print(f"'{STIX_FILE}' yükleniyor...")
    mitre_attack_data = MitreAttackData(STIX_FILE)
    print("Veri başarıyla yüklendi.")
    return mitre_attack_data

mitre_data = load_mitre_data()

# --- PERFORMANS OPTİMİZASYONU: Sub-teknik haritasını başlangıçta oluştur ---
def build_subtechnique_map():
    """Ana tekniklerin STIX ID'lerini, alt-tekniklerin STIX ID listelerine haritalar."""
    print("Sub-teknik haritası oluşturuluyor...")
    subtechnique_map = {}
    all_relationships = mitre_data.get_objects_by_type('relationship', remove_revoked_deprecated=True)
    for rel in all_relationships:
        if rel.get('relationship_type') == 'subtechnique-of':
            parent_id = rel.get('target_ref')
            child_id = rel.get('source_ref')
            if parent_id and child_id:
                if parent_id not in subtechnique_map:
                    subtechnique_map[parent_id] = []
                subtechnique_map[parent_id].append(child_id)
    print("Sub-teknik haritası tamamlandı.")
    return subtechnique_map

SUBTECHNIQUE_MAP = build_subtechnique_map()
# --- Bitti ---

app = Flask(__name__)
CORS(app)

def shorten_description(description):
    if not isinstance(description, str): return 'Açıklama mevcut değil.'
    first_sentence_end = description.find('. ')
    if first_sentence_end != -1: return description[:first_sentence_end] + '.'
    if len(description) > 250: return description[:250] + '...'
    return description

@app.route('/api/tactics', methods=['GET'])
def get_tactics():
    tactics = mitre_data.get_tactics(remove_revoked_deprecated=True)
    results = []
    for tactic in tactics:
        ext_refs = tactic.get('external_references', [])
        if ext_refs:
            results.append({
                "id": ext_refs[0]['external_id'],
                "name": tactic['name'],
                "description": shorten_description(tactic.get('description'))
            })
    return jsonify(results)

@app.route('/api/techniques/<tactic_id>', methods=['GET'])
def get_techniques_for_tactic(tactic_id):
    tactic_object = mitre_data.get_object_by_attack_id(tactic_id, 'x-mitre-tactic')
    if not tactic_object: return jsonify([])
    tactic_shortname = tactic_object['x_mitre_shortname']
    all_techniques = mitre_data.get_techniques(remove_revoked_deprecated=True)
    techniques_for_tactic = []
    for tech in all_techniques:
        if tech.get('kill_chain_phases'):
            for phase in tech['kill_chain_phases']:
                if phase['phase_name'] == tactic_shortname:
                    techniques_for_tactic.append(tech)
                    break
    results = []
    for tech in techniques_for_tactic:
        tech_id = tech.get('id')
        ext_refs = tech.get('external_references', [])
        if tech_id and ext_refs:
            # PERFORMANS: Artık haritadan anında okuyoruz
            subtechniques_list = SUBTECHNIQUE_MAP.get(tech_id, [])
            results.append({
                "id": ext_refs[0]['external_id'], 
                "name": tech['name'],
                "description": shorten_description(tech.get('description')),
                "has_subtechniques": len(subtechniques_list) > 0
            })
    return jsonify(results)

@app.route('/api/subtechniques/<technique_id>', methods=['GET'])
def get_subtechniques_for_technique(technique_id):
    main_technique_object = mitre_data.get_object_by_attack_id(technique_id, 'attack-pattern')
    if not main_technique_object: return jsonify([])
    main_technique_stix_id = main_technique_object['id']

    # PERFORMANS: Artık haritadan anında okuyoruz
    found_subtechnique_ids = SUBTECHNIQUE_MAP.get(main_technique_stix_id, [])
    
    subtechnique_objects = [mitre_data.src.get(stix_id) for stix_id in found_subtechnique_ids]
    results = []
    for sub in subtechnique_objects:
        if not sub: continue
        ext_refs = sub.get('external_references', [])
        if ext_refs:
            results.append({
                "id": ext_refs[0]['external_id'], 
                "name": sub['name'],
                "description": shorten_description(sub.get('description'))
            })
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)