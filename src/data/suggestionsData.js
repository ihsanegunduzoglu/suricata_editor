// src/data/suggestionsData.js

const suggestionsData = {
  Action: ['alert', 'pass', 'drop', 'reject'],
  Protocol: ['tcp', 'udp', 'icmp', 'ip', 'http', 'tls', 'smb'],
  Direction: ['->', '<>'],
  'Source Port': ['any', '80', '443', '53'],
  'Destination Port': ['any', '80', '443', '53'],
  'Source IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
  'Destination IP': ['$HOME_NET', '$EXTERNAL_NET', 'any'],
};

export default suggestionsData;