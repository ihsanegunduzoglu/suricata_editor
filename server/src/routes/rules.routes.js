const express = require('express');
const multer = require('multer');
const { validateRule, formatRule, getNextSid, parseRulesFile } = require('../controllers/rules.controller');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/validate', validateRule);
router.post('/format', formatRule);
router.post('/sid/next', getNextSid);
router.post('/parse', upload.single('file'), parseRulesFile);

module.exports = router;


