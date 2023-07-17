from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db
import logging

bp = Blueprint('password', __name__)

@bp.route('/')
def index():
    db = get_db()
    passwords = db.execute(
        'SELECT p.PasswordID, p.Title as Title, p.Username as Username, p.UpdatedAt as UpdatedAt, p.FK_UserID'
        ' FROM Password p JOIN User u ON p.FK_UserID = u.UserID'
        ' ORDER BY p.Title DESC'
    ).fetchall()

    return render_template('password/index.html', passwords=passwords)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        Title = request.form['Title']
        Username = request.form['Username']
        EncryptedPassword = request.form['EncryptedPassword']
        error = None

        if not Title:
            error = 'Title is required.'
        elif not Username:
            error = 'Username is required.'
        elif not EncryptedPassword:
            error = 'Password is required.'
    

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO Password (Title, Username, EncryptedPassword, FK_UserID)'
                ' VALUES (?, ?, ?, ?)',
                (Title, Username, EncryptedPassword, g.user['UserID'])
            )
            db.commit()
            return redirect(url_for('password.index'))

    return render_template('password/create.html')

def get_password(PasswordID, check_author=True):
    password = get_db().execute(
        'SELECT p.PasswordID, p.Title as Title, p.Username as Username, p.UpdatedAt as UpdatedAt, p.FK_UserID'
        ' FROM Password p JOIN User u ON p.FK_UserID = u.UserID'
        ' WHERE p.PasswordID = ?',
        (PasswordID,)
    ).fetchone()

    if password is None:
        abort(404, f"Password id {PasswordID} doesn't exist.")

    if check_author and password['FK_UserID'] != g.user['UserID']:
        abort(403)

    return password

@bp.route('/<int:PasswordID>/update', methods=('GET', 'POST'))
@login_required
def update(PasswordID):
    password = get_password(PasswordID)

    if request.method == 'POST':
        Title = request.form['Title']
        Username = request.form['Username']
        EncryptedPassword = request.form['EncryptedPassword']
        error = None

        if not Title:
            error = 'Title is required.'
        elif not Username:
            error = 'Username is required.'
        elif not EncryptedPassword:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE password SET Title = ?, Username = ?, EncryptedPassword = ?'
                ' WHERE PasswordID = ?',
                (Title, Username, EncryptedPassword, PasswordID)
            )
            db.commit()
            return redirect(url_for('password.index'))

    return render_template('password/update.html', password=password)

@bp.route('/<int:PasswordID>/delete', methods=('POST',))
@login_required
def delete(PasswordID):
    get_password(PasswordID)
    db = get_db()
    db.execute('DELETE FROM password WHERE PasswordID = ?', (PasswordID,))
    db.commit()
    return redirect(url_for('password.index'))