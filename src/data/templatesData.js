// src/data/templatesData.js
import { v4 as uuidv4 } from 'uuid';

export const templatesData = [
  {
    id: uuidv4(),
    name: 'Gelen Tehdidi Engelle (Inbound Block)',
    description: "Dış ağdan gelen bilinen kötü amaçlı bir IP'yi engeller. Sadece Kaynak IP'yi doldurun.",
    data: {
      headerData: { 
        'Action': 'drop', 
        'Protocol': 'tcp', 
        'Source IP': '', // Kullanıcı dolduracak
        'Source Port': 'any', 
        'Direction': '->', 
        'Destination IP': '$HOME_NET', 
        'Destination Port': 'any' 
      },
      ruleOptions: [
        { id: uuidv4(), keyword: 'msg', value: '"ET POLICY Inbound malicious IP detected"' },
        { id: uuidv4(), keyword: 'sid', value: '1000101' },
        { id: uuidv4(), keyword: 'rev', value: '1' },
      ]
    }
  },
  {
    id: uuidv4(),
    name: 'Giden Bağlantıyı Engelle (Outbound Block)',
    description: "İç ağdan bilinen bir C2 sunucusuna giden bağlantıyı keser. Sadece Hedef IP'yi doldurun.",
    data: {
      headerData: { 
        'Action': 'drop', 
        'Protocol': 'tcp', 
        'Source IP': '$HOME_NET', 
        'Source Port': 'any', 
        'Direction': '->', 
        'Destination IP': '', // Kullanıcı dolduracak
        'Destination Port': 'any' 
      },
      ruleOptions: [
        { id: uuidv4(), keyword: 'msg', value: '"ET POLICY Outbound C2 connection attempt detected"' },
        { id: uuidv4(), keyword: 'sid', value: '1000102' },
        { id: uuidv4(), keyword: 'rev', value: '1' },
      ]
    }
  },
  {
    id: uuidv4(),
    name: 'Zararlı Dosya İndirme Tespiti',
    description: "HTTP trafiğinde belirli bir dosya adının indirilmesini tespit eder. 'content' değerini doldurun.",
    data: {
      headerData: { 
        'Action': 'alert', 
        'Protocol': 'http', 
        'Source IP': '$EXTERNAL_NET', 
        'Source Port': 'any', 
        'Direction': '->', 
        'Destination IP': '$HOME_NET', 
        'Destination Port': 'any' 
      },
      ruleOptions: [
        { id: uuidv4(), keyword: 'msg', value: '"ET MALWARE Known Malware Download Attempt"' },
        { id: uuidv4(), keyword: 'sid', value: '1000201' },
        { id: uuidv4(), keyword: 'rev', value: '1' },
        { id: uuidv4(), keyword: 'flow', value: 'established,to_client' },
        { id: uuidv4(), keyword: 'http.uri', value: true },
        { id: uuidv4(), keyword: 'content', value: '"evil.exe"', modifiers: { nocase: true, depth: '', offset: '' }, format: 'ascii' },
      ]
    }
  },
  {
    id: uuidv4(),
    name: 'Şüpheli User-Agent Tespiti',
    description: "Bilinen botnet veya tarama araçlarına ait User-Agent başlıklarını arar. 'content' değerini doldurun.",
    data: {
      headerData: { 
        'Action': 'alert', 
        'Protocol': 'http', 
        'Source IP': '$EXTERNAL_NET', 
        'Source Port': 'any', 
        'Direction': '->', 
        'Destination IP': '$HOME_NET', 
        'Destination Port': 'any' 
      },
      ruleOptions: [
        { id: uuidv4(), keyword: 'msg', value: '"ET POLICY Suspicious User-Agent Detected"' },
        { id: uuidv4(), keyword: 'sid', value: '1000301' },
        { id: uuidv4(), keyword: 'rev', value: '1' },
        { id: uuidv4(), keyword: 'flow', value: 'established,to_server' },
        { id: uuidv4(), keyword: 'http.user_agent', value: true },
        { id: uuidv4(), keyword: 'content', value: '"Nikto"', modifiers: { nocase: true, depth: '', offset: '' }, format: 'ascii' },
      ]
    }
  },
  {
    id: uuidv4(),
    name: 'Belirli Servise Erişimi İzleme',
    description: "Hassas bir sunucuya yapılan tüm erişim denemelerini loglar. IP ve Port'u doldurun.",
    data: {
      headerData: { 
        'Action': 'alert', 
        'Protocol': 'tcp', 
        'Source IP': 'any', 
        'Source Port': 'any', 
        'Direction': '->', 
        'Destination IP': '', // Kullanıcı dolduracak
        'Destination Port': ''  // Kullanıcı dolduracak
      },
      ruleOptions: [
        { id: uuidv4(), keyword: 'msg', value: '"ET POLICY Access to Critical Server"' },
        { id: uuidv4(), keyword: 'sid', value: '1000401' },
        { id: uuidv4(), keyword: 'rev', value: '1' },
      ]
    }
  },
];