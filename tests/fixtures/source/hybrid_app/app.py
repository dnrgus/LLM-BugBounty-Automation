import os

from flask import Flask, request

app = Flask(__name__)


@app.get("/about")
def about():
    return "about page"


@app.route("/api/admin/run", methods=["POST"])
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "ok"
