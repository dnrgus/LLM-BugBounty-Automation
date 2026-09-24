const express = require('express');
const multer = require('multer');

const app = express();
const upload = multer();

app.get('/api/invoices/:invoiceId', (req, res) => {
  res.json({ id: req.params.invoiceId });
});

app.post('/api/invoices', (req, res) => {
  const { amount, currency } = req.body;
  res.status(201).json({ amount, currency });
});

app.patch('/api/invoices/:invoiceId', (req, res) => {
  const note = req.body.note;
  res.json({ note });
});

app.delete('/api/invoices/:invoiceId', (req, res) => {
  res.status(204).end();
});

app.post('/api/receipts', upload.single('receipt'), (req, res) => {
  res.json({ name: req.file.originalname });
});

app.get('/api/search', (req, res) => {
  res.json({ q: req.query.q });
});

module.exports = app;
