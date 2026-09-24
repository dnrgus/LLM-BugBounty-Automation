from flask import Flask, request

from app.services import reports
from app.services.notes import find_notes, render_note

app = Flask(__name__)


@app.get("/notes/search")
def search_notes():
    term = request.args.get("q")
    return {"notes": find_notes(term)}


@app.get("/notes/preview")
def preview_note():
    return render_note(request.args.get("body"))


@app.post("/reports/export")
def export_report():
    name = request.json.get("name")
    return reports.export(name)


@app.get("/health")
def health():
    return find_notes("static-term")
