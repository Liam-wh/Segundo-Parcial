from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'ClaveSuperSecreta'

# Configurar flask-login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Conexión a la base de datos
def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar base de datos
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Clase User para flask-login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password = password_hash

    @staticmethod
    def get_by_id(id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT posts.*, users.username 
        FROM posts JOIN users ON posts.user_id = users.id 
        ORDER BY posts.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash_pass = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                         (username, hash_pass))
            conn.commit()
            flash('Usuario registrado correctamente. Inicia sesión.', 'success')
            return redirect(url_for('login'))
        except:
            flash('El nombre de usuario ya existe', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidas', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    posts = conn.execute(''' 
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
        WHERE posts.user_id = ?
        ORDER BY posts.created_at DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    return render_template('dashboard.html', username=current_user.username, posts=posts)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('index'))


# crear post
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn = get_db_connection()
        conn.execute('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                     (title, content, current_user.id))
        conn.commit()
        conn.close()
        flash('Post creado correctamente.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('form_post.html', post=None)


# editar post
@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND user_id = ?', 
                        (post_id, current_user.id)).fetchone()

    if post is None:
        conn.close()
        flash('Post no encontrado o no autorizado.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn.execute('UPDATE posts SET title = ?, content = ? WHERE id = ?', (title, content, post_id))
        conn.commit()
        conn.close()
        flash('Post actualizado correctamente.', 'success')
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('form_post.html', post=post)


# eliminar post
@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND user_id = ?', (post_id, current_user.id)).fetchone()

    if post is None:
        conn.close()
        flash('Post no encontrado o no autorizado.', 'danger')
        return redirect(url_for('dashboard'))

    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
    flash('Post eliminado correctamente.', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
