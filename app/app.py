from flask import Flask, render_template, redirect, url_for, flash, request, session
from forms import LoginForm, RegisterForm
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'miclavesecreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuario.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'usuarios'

# Modelo
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Campo para identificar administradores

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Modelo proveedor
class Proveedor(db.Model):
    __tablename__ = 'proveedores'
    
    id_proveedor = db.Column(db.Integer, primary_key=True)
    nombre_proveedor = db.Column(db.String(100), nullable=False)
    direccion_proveedor = db.Column(db.String(200), nullable=False)
    telefono_proveedor = db.Column(db.String(20), nullable=False)
    correo_electronico_proveedor = db.Column(db.String(100), nullable=False, unique=True)
	
# Modelo stock
class Stock(db.Model):
    __tablename__ = 'stock'
    
    id_producto = db.Column(db.Integer, primary_key=True)
    nombre_producto = db.Column(db.String(100), nullable=False)
    cantidad_stock = db.Column(db.Integer, nullable=False)
    precio = db.Column(db.Float, nullable=False)
    imagen = db.Column(db.String(100), nullable=False)
    id_proveedor = db.Column(db.Integer, db.ForeignKey('proveedores.id_proveedor'), nullable=False)
    proveedor = db.relationship('Proveedor', backref=db.backref('productos', lazy=True))
		
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('No tienes permiso para acceder a esta página.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    productos = Stock.query.all()
    return render_template('index.html', productos=productos)

@app.route('/contacto')
def contacto():
    return render_template('contacto.html')

@app.route('/envios')
def envios():
    return render_template('envios.html')

@app.route('/nosotros')
def nosotros():
    return render_template('nosotros.html')

@app.route('/pagos')
def pagos():
    return render_template('pagos.html')

@app.route('/productos')
def productos():
    productos = Stock.query.all()
    return render_template('productos.html', productos=productos)

@app.route('/registroUsuarios', methods=['GET', 'POST'])
def registro_usuarios():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        lastname = form.lastname.data
        username = form.username.data
        email = form.email.data
        password = form.password.data
        is_admin = form.is_admin.data  # Nuevo campo en el formulario

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash('La dirección de correo electrónico ya está en uso. Por favor, ingrese otra.', 'error')
            return redirect(url_for('registro_usuarios'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya está en uso. Por favor, elija otro.', 'error')
            return redirect(url_for('registro_usuarios'))

        new_user = User(name=name, lastname=lastname, username=username, email=email, is_admin=is_admin)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registro completado correctamente!', 'Aviso!')
        return redirect(url_for('index'))

    return render_template('registroUsuarios.html', form=form)

@app.route('/usuarios', methods=['GET', 'POST'])
def usuarios():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Inicio de sesión exitoso', 'Aviso!')
            return redirect(url_for('index'))
        else:
            flash('Nombre de usuario o contraseña incorrectos', 'Advertencia!')
    return render_template('usuarios.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión', 'Aviso!')
    return redirect(url_for('index'))
	
@app.route('/proveedores')
@login_required
@admin_required
def proveedores():
    proveedores = Proveedor.query.all()
    productos = Stock.query.all()
    return render_template('proveedores.html', proveedores=proveedores, productos=productos)

	# Rutas y lógica del carrito de compras
@app.route('/carrito')
def carrito():
    carrito = session.get('carrito', [])
    total = 0.0
    for item in carrito:
        precio = item['producto']['precio']
        # Limpiar el precio en caso de que tenga símbolos o formato incorrecto
        if isinstance(precio, str):
            precio = float(precio.replace('$', '').replace(',', '.'))
        total += precio * int(item['cantidad'])
    return render_template('carrito.html', carrito=carrito, total=total)

@app.route('/agregar_al_carrito/<int:producto_id>')
def agregar_al_carrito(producto_id):
    producto = Stock.query.get(producto_id)
    if not producto:
        flash('Producto no encontrado', 'error')
        return redirect(url_for('productos'))

    carrito = session.get('carrito', [])
    for item in carrito:
        if item['producto']['id_producto'] == producto.id_producto:
            item['cantidad'] += 1
            break
    else:
        precio_sin_simbolo = float(producto.precio.replace('$', '').replace(',', '.'))
        carrito.append({
            'producto': {
                'id_producto': producto.id_producto, 
                'nombre_producto': producto.nombre_producto, 
                'precio': precio_sin_simbolo
            }, 
            'cantidad': 1
        })

    session['carrito'] = carrito
    flash('Producto agregado al carrito', 'success')
    return redirect(url_for('productos'))

@app.route('/eliminar_del_carrito/<int:producto_id>')
def eliminar_del_carrito(producto_id):
    carrito = session.get('carrito', [])
    carrito = [item for item in carrito if item['producto']['id_producto'] != producto_id]
    session['carrito'] = carrito
    flash('Producto eliminado del carrito', 'success')
    return redirect(url_for('carrito'))

@app.route('/proceder_al_pago')
def proceder_al_pago():
    # Lógica para proceder al pago
    return render_template('pago.html')

if __name__ == '__main__':
    app.run(debug=True)
