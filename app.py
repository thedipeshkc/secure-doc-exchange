from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
KEY_FILE = 'secret.key'

def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    with open(KEY_FILE, 'rb') as f:
        return f.read()

encryption_key = load_or_create_key()
fernet = Fernet(encryption_key)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ─── USER MODEL ───────────────────────────────────────────
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    encrypted_filename = db.Column(db.String(200), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    uploaded_at = db.Column(db.DateTime, default=db.func.now())

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    performed_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship('User', foreign_keys=[user_id])


# ─── ROUTES ───────────────────────────────────────────────
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'error')

    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        receiver_email = request.form['receiver_email']
        file = request.files['file']

        # find receiver
        receiver = User.query.filter_by(email=receiver_email).first()
        if not receiver:
            flash('No user found with that email.', 'error')
            return redirect(url_for('upload'))

        if receiver.id == current_user.id:
            flash('You cannot send a document to yourself.', 'error')
            return redirect(url_for('upload'))

        # read and encrypt file
        file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)

        # save encrypted file
        original_filename = file.filename
        encrypted_filename = 'enc_' + str(current_user.id) + '_' + original_filename

        with open(os.path.join('uploads', encrypted_filename), 'wb') as f:
            f.write(encrypted_data)

        # save to database
        new_doc = Document(
            filename=original_filename,
            encrypted_filename=encrypted_filename,
            sender_id=current_user.id,
            receiver_id=receiver.id,
            status='Pending'
        )
        db.session.add(new_doc)
        db.session.commit()

        flash('Document encrypted and sent successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/document/<int:doc_id>')
@login_required
def view_document(doc_id):
    document = Document.query.get_or_404(doc_id)

    # only sender or receiver can view
    if current_user.id != document.sender_id and current_user.id != document.receiver_id:
        flash('You do not have permission to view this document.', 'error')
        return redirect(url_for('dashboard'))

    # log the view action
    if current_user.id == document.receiver_id and document.status == 'Pending':
        document.status = 'Viewed'
        log = AuditLog(
            document_id=document.id,
            user_id=current_user.id,
            action='Document viewed by receiver'
        )
        db.session.add(log)
        db.session.commit()

    audit_logs = AuditLog.query.filter_by(document_id=doc_id).all()
    return render_template('document.html', document=document, audit_logs=audit_logs)


@app.route('/document/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)

    # only receiver can download
    if current_user.id != document.receiver_id:
        flash('You do not have permission to download this document.', 'error')
        return redirect(url_for('dashboard'))

    # read and decrypt file
    encrypted_path = os.path.join('uploads', document.encrypted_filename)
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    # log the download
    log = AuditLog(
        document_id=document.id,
        user_id=current_user.id,
        action='Document downloaded by receiver'
    )
    db.session.add(log)
    db.session.commit()

    # send decrypted file to browser
    from flask import Response
    return Response(
        decrypted_data,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename={document.filename}'}
    )


@app.route('/document/<int:doc_id>/approve')
@login_required
def approve_document(doc_id):
    document = Document.query.get_or_404(doc_id)

    # only receiver can approve
    if current_user.id != document.receiver_id:
        flash('You do not have permission to approve this document.', 'error')
        return redirect(url_for('dashboard'))

    document.status = 'Approved'
    log = AuditLog(
        document_id=document.id,
        user_id=current_user.id,
        action='Document approved by receiver'
    )
    db.session.add(log)
    db.session.commit()

    flash('Document has been approved.', 'success')
    return redirect(url_for('view_document', doc_id=doc_id))

@app.route('/dashboard')
@login_required
def dashboard():
    sent_documents = Document.query.filter_by(sender_id=current_user.id).all()
    received_documents = Document.query.filter_by(receiver_id=current_user.id).all()
    return render_template('dashboard.html',
                           sent_documents=sent_documents,
                           received_documents=received_documents)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ─── RUN ───────
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)