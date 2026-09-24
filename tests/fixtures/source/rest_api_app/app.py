from flask import Flask, jsonify, request

app = Flask(__name__)

NOTES = {}


@app.get("/api/notes/<int:note_id>")
def get_note(note_id):
    return jsonify(NOTES.get(note_id, {}))


@app.route("/api/notes", methods=["POST"])
def create_note():
    payload = request.get_json()
    title = payload["title"]
    body = request.json.get("body")
    return jsonify({"title": title, "body": body}), 201


@app.put("/api/notes/<int:note_id>")
def update_note(note_id):
    title = request.json["title"]
    return jsonify({"id": note_id, "title": title})


@app.delete("/api/notes/<int:note_id>")
def delete_note(note_id):
    NOTES.pop(note_id, None)
    return "", 204


@app.route("/api/profile", methods=["GET", "PATCH"])
def profile():
    display_name = request.form.get("display_name")
    return jsonify({"display_name": display_name})


@app.post("/api/avatar")
def upload_avatar():
    upload = request.files["avatar"]
    return jsonify({"name": upload.filename})


@app.get("/api/search")
def search():
    term = request.args.get("q")
    return jsonify({"q": term})
