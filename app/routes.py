from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from . import models

bp = Blueprint("main", __name__)

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return models.get_user_by_id(user_id)

@bp.route("/")
def index():
    if not current_user():
        return redirect(url_for("main.login"))
    return redirect(url_for("main.notes_list"))

@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        models.create_user(request.form["username"], request.form["password"])
        flash("Account created. Please log in.")
        return redirect(url_for("main.login"))
    return render_template("register.html")

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = models.verify_credentials(request.form["username"], request.form["password"])
        if user:
            session["user_id"] = user["id"]
            return redirect(url_for("main.notes_list"))
        flash("Invalid credentials.")
    return render_template("login.html")

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))

@bp.route("/notes", methods=["GET", "POST"])
def notes_list():
    user = current_user()
    if not user:
        return redirect(url_for("main.login"))
    if request.method == "POST":
        models.create_note(user["id"], request.form["title"], request.form["content"])
        return redirect(url_for("main.notes_list"))
    notes = models.get_notes_for_user(user["id"])
    return render_template("notes_list.html", notes=notes, user=user)

@bp.route("/notes/<int:note_id>")
def note_view(note_id):
    user = current_user()
    if not user:
        return redirect(url_for("main.login"))
    note = models.get_note_for_owner(note_id, user["id"])
    if note is None:
        return "Note not found", 404
    return render_template("note_view.html", note=note)
