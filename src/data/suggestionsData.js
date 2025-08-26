// src/data/suggestionsData.js

const suggestionsData = {
  Action: ['alert', 'pass', 'drop', 'reject', 'rejectsrc', 'rejectdst'],
  Protocol: [
    'tcp', 
    'udp', 
    'icmp', 
    'ip', 
    'http', 
    'tls', 
    'smb', 
    'dns', 
    'ftp', 
    'ssh',
    'smtp',
    'dhcp'
  ],
  Direction: ['->', '<>'],
  'Source Port': [
    'any', 
    '$HTTP_PORTS', 
    '$HTTPS_PORTS', 
    '80', 
    '443', 
    '53', 
    '21', 
    '22', 
    '25',
    '3306'
  ],
  'Destination Port': [
    'any', 
    '$HTTP_PORTS', 
    '$HTTPS_PORTS', 
    '80', 
    '443', 
    '53', 
    '21', 
    '22', 
    '25',
    '3306'
  ],
  'Source IP': [
    '$HOME_NET', 
    '$EXTERNAL_NET', 
    'any',
    '$HTTP_SERVERS',
    '$DNS_SERVERS',
    '$SMTP_SERVERS',
    '$SQL_SERVERS'
  ],
  'Destination IP': [
    '$HOME_NET', 
    '$EXTERNAL_NET', 
    'any',
    '$HTTP_SERVERS',
    '$DNS_SERVERS',
    '$SMTP_SERVERS',
    '$SQL_SERVERS'
  ],
};

export default suggestionsData;