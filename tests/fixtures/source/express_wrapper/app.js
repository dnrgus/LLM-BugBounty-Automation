const express = require('express');
const child_process = require('child_process');

const app = express();

function runReport(name) {
  child_process.exec('make-report ' + name);
}

app.get('/api/report', (req, res) => {
  runReport(req.query.name);
  res.send('ok');
});

app.get('/api/direct', (req, res) => {
  const target = req.query.target;
  child_process.exec('ping ' + target);
  res.send('ok');
});

module.exports = app;
