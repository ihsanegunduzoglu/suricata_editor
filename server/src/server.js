const express = require('express');
const cors = require('cors');

const rulesRouter = require('./routes/rules.routes');
const { getNextSid } = require('./controllers/rules.controller');

const app = express();

app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.use('/rules', rulesRouter);
app.post('/sid/next', getNextSid);

const PORT = Number(process.env.PORT) || 4100;
app.listen(PORT, () => {
  console.log(`Suricata Editor API listening on port ${PORT}`);
});


