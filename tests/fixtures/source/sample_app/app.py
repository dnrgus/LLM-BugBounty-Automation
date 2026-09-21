import os

import openai
from flask import Flask, request

app = Flask(__name__)

# Fixture-only placeholder key (not a real credential) for secret-detector tests.
API_KEY = "AKIAABCDEFGHIJKLMNOP"


@app.route("/api/chat", methods=["POST"])
def chat():
    message = request.json.get("message")
    response = openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": message}])
    return {"reply": response}


@app.route("/api/admin/run", methods=["POST"])
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "ok"
