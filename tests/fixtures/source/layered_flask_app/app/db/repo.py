import sqlite3


def run_query(where):
    conn = sqlite3.connect("notes.db")
    return conn.execute("SELECT * FROM notes WHERE " + where).fetchall()
