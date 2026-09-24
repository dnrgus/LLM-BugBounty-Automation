from flask import render_template_string

from app.db.repo import run_query


def _build_filter(term):
    return f"title LIKE '%{term}%'"


def find_notes(term):
    where = _build_filter(term)
    return run_query(where)


def render_note(body):
    return render_template_string(body)
