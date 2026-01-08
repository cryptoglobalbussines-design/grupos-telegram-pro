from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer
from models import db, Group, AdminUser
from config import Config
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from flask_bcrypt import Bcrypt
import json

app = Flask(__name__)
app.config.from_object(Config)

# Context processor para JSON de países
@app.context_processor
def utility_processor():
    def load_json(path):
        with open(path[1:], 'r', encoding='utf-8') as f:
            return json.load(f)
    return dict(load_json=load_json)

# Inicializamos extensiones
bcrypt = Bcrypt(app)
db.init_app(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Cargar usuario admin
@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

# Crear base de datos y AdminMaster permanente
with app.app_context():
    db.create_all()
    
    # AdminMaster que siempre existe
    MASTER_USERNAME = "AdminMaster"
    if not AdminUser.query.filter_by(username=MASTER_USERNAME).first():
        hashed = bcrypt.generate_password_hash(app.config['ADMIN_MASTER_PASSWORD']).decode('utf-8')
        master_admin = AdminUser(username=MASTER_USERNAME, password=hashed)
        db.session.add(master_admin)
        db.session.commit()

# Página principal
@app.route('/')
@app.route('/category/<category>')
def index(category=None):
    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    
    query = Group.query.filter_by(approved=True)
    
    if category:
        query = query.filter_by(category=category)
    
    if q:
        search = f"%{q}%"
        query = query.filter(
            (Group.name.ilike(search)) | 
            (Group.description.ilike(search))
        )
    
    pagination = query.order_by(Group.pinned.desc(), Group.submitted_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    groups = pagination.items
    
    for group in groups:
        group.profile_photo = None
        group.member_count = "Grupo privado"
        
        if 't.me/' in group.link:
            try:
                username = group.link.split('t.me/')[-1].split('?')[0].strip('/')
                if username:
                    preview_url = f"https://t.me/s/{username}"
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    response = requests.get(preview_url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        og_images = soup.find_all("meta", property="og:image")
                        if og_images:
                            group.profile_photo = og_images[0]["content"]
                        
                        counters = soup.find("div", class_="tgme_channel_info_counters")
                        if counters:
                            values = counters.find_all("span", class_="counter_value")
                            if values:
                                group.member_count = values[0].get_text(strip=True)
            except:
                pass
    
    return render_template(
        'index.html',
        groups=groups,
        pagination=pagination,
        category=category,
        q=q or ''
    )

# Formulario de envío
@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Por favor, completa el reCAPTCHA.', 'danger')
            return render_template('submit.html')

        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        verify_data = {
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': recaptcha_response,
            'remoteip': request.remote_addr
        }
        verify_response = requests.post(verify_url, data=verify_data)
        verify_result = verify_response.json()

        if not verify_result.get('success'):
            flash('reCAPTCHA falló. Inténtalo de nuevo.', 'danger')
            return render_template('submit.html')

        name = request.form['name']
        link = request.form['link']
        description = request.form['description']
        email = request.form['email']
        category = request.form.get('category', 'General')
        country = request.form.get('country', 'Global')

        new_group = Group(
            name=name,
            link=link,
            description=description,
            email=email,
            category=category,
            country=country,
            confirmed=False,
            approved=False,
            pinned=False
        )
        db.session.add(new_group)
        db.session.commit()

        token = s.dumps({'email': email, 'group_id': new_group.id}, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)

        msg = Message(
            'Confirma tu grupo en Grupos Telegram Pro 🚀',
            sender=('Grupos Telegram Pro', app.config['MAIL_USERNAME']),
            recipients=[email]
        )
        msg.body = f'''
¡Hola!

Gracias por enviar tu grupo "{name}" ({category}) a Grupos Telegram Pro.

Para confirmar tu solicitud, haz clic en este enlace (válido por 1 hora):
{confirm_url}

Una vez confirmado, el administrador lo revisará y aprobará.

¡Gracias por unirte a la comunidad!
Grupos Telegram Pro 🚀
'''
        mail.send(msg)

        flash('¡Solicitud enviada! Revisa tu correo.', 'success')
        return redirect(url_for('index'))

    return render_template('submit.html')

# Confirmación por email
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        data = s.loads(token, salt='email-confirm', max_age=3600)
        email = data['email']
        group_id = data['group_id']
    except:
        flash('Enlace inválido o expirado.', 'danger')
        return redirect(url_for('index'))

    group = Group.query.get(group_id)
    if group and group.email == email and not group.confirmed:
        group.confirmed = True
        db.session.commit()
        flash('¡Confirmado! Pendiente de aprobación.', 'success')
    else:
        flash('Enlace inválido.', 'info')

    return redirect(url_for('index'))

# Login admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = AdminUser.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f'Bienvenido {user.username}!', 'success')
            return redirect(url_for('admin_panel'))
        flash('Usuario o contraseña incorrecta', 'danger')
    
    return render_template('admin/login.html')

# Panel admin
@app.route('/admin')
@login_required
def admin_panel():
    pending = Group.query.filter_by(confirmed=True, approved=False).all()
    approved = Group.query.filter_by(approved=True).all()
    admins = AdminUser.query.all()
    
    stats = {
        'pending_count': len(pending),
        'approved_count': len(approved),
        'total_groups': Group.query.count(),
        'admins_count': len(admins)
    }
    
    return render_template('admin/panel.html', pending=pending, approved=approved, admins=admins, stats=stats)

# Gestión de admins
@app.route('/admin/manage', methods=['GET', 'POST'])
@login_required
def manage_admins():
    admins = AdminUser.query.all()
    
    if request.method == 'POST':
        action = request.form['action']
        
        if action == 'create_admin':
            master_password = request.form.get('master_password', '')
            if master_password != app.config['ADMIN_MASTER_PASSWORD']:
                flash('Contraseña maestra incorrecta.', 'danger')
            else:
                username = request.form['new_username'].strip()
                password = request.form['new_password']
                if AdminUser.query.filter_by(username=username).first():
                    flash('Ese usuario ya existe.', 'danger')
                else:
                    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
                    new_admin = AdminUser(username=username, password=hashed)
                    db.session.add(new_admin)
                    db.session.commit()
                    flash(f'Admin "{username}" creado con éxito!', 'success')
        
        elif action == 'change_password':
            admin_id = request.form['admin_id']
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            
            admin = AdminUser.query.get(admin_id)
            if admin and admin.id == current_user.id and bcrypt.check_password_hash(admin.password, current_password):
                admin.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                db.session.commit()
                flash('Tu contraseña ha sido cambiada con éxito.', 'success')
            else:
                flash('Contraseña actual incorrecta o no tienes permiso.', 'danger')
        
        elif action == 'delete_admin':
            admin_id = request.form['admin_id']
            master_password = request.form.get('master_password', '')
            
            if master_password != app.config['ADMIN_MASTER_PASSWORD']:
                flash('Contraseña maestra incorrecta.', 'danger')
            else:
                admin_to_delete = AdminUser.query.get(admin_id)
                if admin_to_delete:
                    if admin_to_delete.username == "AdminMaster":
                        flash('No puedes eliminar al AdminMaster.', 'danger')
                    elif admin_to_delete.id == current_user.id:
                        flash('No puedes eliminarte a ti mismo.', 'danger')
                    else:
                        db.session.delete(admin_to_delete)
                        db.session.commit()
                        flash(f'Admin "{admin_to_delete.username}" eliminado con éxito.', 'success')
                else:
                    flash('Admin no encontrado.', 'danger')
        
        admins = AdminUser.query.all()
    
    return render_template('admin/manage_admins.html', admins=admins)

# Acciones admin (grupos)
@app.route('/admin/action', methods=['POST'])
@login_required
def admin_action():
    action = request.form['action']
    
    group_id = request.form.get('group_id')
    if not group_id:
        flash('Acción inválida.', 'danger')
        return redirect(url_for('admin_panel'))
    
    group = Group.query.get_or_404(group_id)

    if action == 'approve':
        group.approved = True
    elif action == 'pin':
        group.pinned = not group.pinned
    elif action == 'delete':
        db.session.delete(group)

    db.session.commit()
    flash('Acción realizada', 'success')
    return redirect(url_for('admin_panel'))

# Logout
@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Sesión cerrada', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)