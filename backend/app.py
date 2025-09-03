# backend/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import uuid
import subprocess
import shutil
import json

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'test_runs'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/api/test-rule', methods=['POST'])
def test_rule():
    if 'pcap_file' not in request.files:
        return jsonify({"error": "PCAP dosyası bulunamadı"}), 400

    pcap_file = request.files['pcap_file']
    rule_string = request.form.get('rule_string', None)
    rules_file = request.files.get('rules_file', None)

    if not rule_string and not rules_file:
        return jsonify({"error": "Test edilecek kural metni veya dosyası bulunamadı"}), 400

    if pcap_file.filename == '':
        return jsonify({"error": "PCAP dosyası seçilmedi"}), 400

    run_id = str(uuid.uuid4())
    run_path = os.path.join(app.config['UPLOAD_FOLDER'], run_id)
    os.makedirs(run_path)
    logs_path = os.path.join(run_path, 'logs')
    os.makedirs(logs_path)

    try:
        pcap_filepath = os.path.join(run_path, pcap_file.filename)
        pcap_file.save(pcap_filepath)

        rules_filepath = os.path.join(run_path, 'test.rules')
        with open(rules_filepath, 'w', encoding='utf-8') as f:
            if rules_file:
                rules_content = rules_file.read().decode('utf-8')
                f.write(rules_content)
            else:
                f.write(rule_string)
        
        command = [
            'docker', 'run', '--rm',
            '-v', f'{os.path.abspath(run_path)}:/data',
            'jasonish/suricata:7.0.5',
            '-S', '/data/test.rules',
            '-r', f'/data/{pcap_file.filename}',
            '-l', '/data/logs',
            '-k', 'none'
        ]

        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')

        if result.returncode != 0 and "alerts: 0" not in result.stderr:
            return jsonify({"error": "Suricata çalıştırılırken hata oluştu.", "details": result.stderr}), 500

        alerts = []
        eve_log_path = os.path.join(logs_path, 'eve.json')
        if os.path.exists(eve_log_path):
            with open(eve_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line)
                        if log_entry.get('event_type') == 'alert':
                            alert_info = log_entry.get('alert', {})
                            http_info = log_entry.get('http', {}) # HTTP bilgisini al
                            
                            # Payload'ı base64'ten çözerek al
                            payload_printable = ""
                            if 'payload_printable' in log_entry:
                                payload_printable = log_entry.get('payload_printable', "")
                            
                            alerts.append({
                                "timestamp": log_entry.get('timestamp'),
                                "signature": alert_info.get('signature'),
                                "signature_id": alert_info.get('signature_id'),
                                "category": alert_info.get('category'),
                                "severity": alert_info.get('severity'),
                                "src_ip": log_entry.get('src_ip'),
                                "src_port": log_entry.get('src_port'),
                                "dest_ip": log_entry.get('dest_ip'),
                                "dest_port": log_entry.get('dest_port'),
                                "protocol": log_entry.get('proto'),
                                "http": http_info, # HTTP objesini ekle
                                "payload": payload_printable # Eşleşen payload'ı ekle
                            })
                    except json.JSONDecodeError:
                        continue

        response = {
            "message": "Test tamamlandı!",
            "status": "COMPLETED",
            "alert_count": len(alerts),
            "alerts": alerts
        }
        
        return jsonify(response), 200

    finally:
        if os.path.exists(run_path):
            shutil.rmtree(run_path)

if __name__ == '__main__':
    app.run(debug=True, port=5000)