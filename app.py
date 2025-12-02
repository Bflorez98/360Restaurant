import os
import random
import datetime
import requests
from flask import Flask, render_template, session, request, redirect, url_for, flash
from flaskext.mysql import MySQL
import pymysql, time
import bcrypt
from werkzeug.utils import secure_filename
from twilio.rest import Client
from flask import jsonify

# --- Configuración básica ---
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'secretkey')  # usa una variable de entorno en producción

# --- Configuración base de datos (puedes mover a env vars) ---
app.config['MYSQL_DATABASE_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_DATABASE_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', '')
app.config['MYSQL_DATABASE_DB'] = os.environ.get('MYSQL_DB', 'restaurante_db')
app.config['MYSQL_DATABASE_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_DATABASE_PORT'] = 3307



# --- Configuración Google Maps API  ---
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")

# --- Upload folder ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Inicializar MySQL ---
mysql = MySQL()
mysql.init_app(app)


# ---------------- RUTAS GENERALES ----------------

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    text = ''

    # Inicializar variables de sesión si no existen
    if 'intentos' not in session:
        session['intentos'] = 0
    if 'bloqueado_hasta' not in session:
        session['bloqueado_hasta'] = 0
    if 'nivel_bloqueo' not in session:
        session['nivel_bloqueo'] = 0  # 0 = sin bloqueo, 1 = leve, 2 = fuerte

    # Verificar si el usuario está bloqueado actualmente
    if time.time() < session['bloqueado_hasta']:
        restante = int(session['bloqueado_hasta'] - time.time())
        minutos = restante // 60
        segundos = restante % 60
        text = f"Demasiados intentos fallidos. Intenta de nuevo en {minutos} min {segundos} s."
        return render_template('login.html', text=text)

    # Procesar formulario
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)

        try:
            cur.execute("SELECT * FROM usuarios WHERE correo = %s", (email,))
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['contrasena'].encode('utf-8')):
            # ✅ Login exitoso → limpiar los intentos y bloqueos
            session['loggedin'] = True
            session['id'] = user['id_usuario']
            session['nombre'] = user['nombre']
            session['rol'] = user['id_rol']
            session.pop('intentos', None)
            session.pop('bloqueado_hasta', None)
            session.pop('nivel_bloqueo', None)

            if user['id_rol'] == 1:
                return redirect('/dashboard_admin')
            elif user['id_rol'] == 2:
                return redirect('/dashboard_empleado')
            else:
                return redirect('/dashboard_cliente')
        else:
            # ❌ Credenciales incorrectas
            session['intentos'] += 1

            if session['intentos'] >= 3:
                if session['nivel_bloqueo'] == 0:
                    # Primer bloqueo: 5 minutos
                    session['bloqueado_hasta'] = time.time() + 300
                    session['nivel_bloqueo'] = 1
                    text = "Has excedido el número de intentos. Bloqueo temporal de 5 minutos."
                elif session['nivel_bloqueo'] == 1:
                    # Segundo bloqueo: 24 horas
                    session['bloqueado_hasta'] = time.time() + 86400
                    session['nivel_bloqueo'] = 2
                    text = "Has excedido el número de intentos nuevamente. Bloqueo de 24 horas."
                else:
                    text = "Tu cuenta sigue bloqueada por intentos fallidos repetidos."

                session['intentos'] = 0  # Reinicia el contador tras aplicar el bloqueo
            else:
                restantes = 3 - session['intentos']
                text = f"Correo o contraseña incorrecta. Te quedan {restantes} intentos."

    return render_template('login.html', text=text)


@app.route('/logout')
def logout():
    session.clear()
    # redirige a login (no render)
    resp = redirect(url_for('login'))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.route('/register', methods=['GET', 'POST'])
def register():
    text = ''
    if request.method == 'POST':
        #  Validar checkbox de términos
        if 'terminos' not in request.form:
            text = "Debes aceptar los términos y condiciones para registrarte."
            return render_template('register.html', text=text)

        nombre = request.form['fullname']
        email = request.form['email']
        telefono = request.form['phone']
        password = request.form['password']

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = mysql.connect()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO usuarios (nombre, correo, telefono, contrasena, id_rol) VALUES (%s, %s, %s, %s, %s)",
                (nombre, email, telefono, hashed, 3)
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()

        return redirect('/login')

    return render_template('register.html', text=text)

# ---------------- Recuperación por SMS (Twilio) ----------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Formulario donde el usuario ingresa su teléfono para recibir un código SMS
    """
    if request.method == 'POST':
        telefono = request.form['telefono'].strip()

        # Normalizamos: quitamos +57 si el usuario lo pone
        telefono_normalizado = telefono.replace("+57", "").strip()

        # Verificamos si el teléfono existe en la tabla usuarios
        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        try:
            cur.execute("SELECT * FROM usuarios WHERE telefono = %s", (telefono_normalizado,))
            user = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if not user:
            flash("El número no está registrado.", "danger")
            return render_template('forgot_password.html')

        # Generar código de 6 dígitos + expiración
        codigo = str(random.randint(100000, 999999))
        expiracion = datetime.datetime.now() + datetime.timedelta(minutes=10)

        conn = mysql.connect()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO password_resets (telefono, codigo, expiracion) VALUES (%s, %s, %s)",
                        (telefono_normalizado, codigo, expiracion))
            conn.commit()
        finally:
            cur.close()
            conn.close()

        # Enviar SMS vía Twilio (ahora sí en formato E.164)
        try:
            client.messages.create(
                body=f"Tu código de recuperación es: {codigo}",
                from_=TWILIO_PHONE_NUMBER,
                to=f"+57{telefono_normalizado}"
            )
        except Exception as e:
            flash("Error al enviar SMS. Intenta más tarde.", "danger")
            return render_template('forgot_password.html')

        flash("Se envió un código a tu celular.", "success")
        return redirect(url_for('verify_code'))

    return render_template('forgot_password.html')


@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    """
    Formulario donde el usuario ingresa el teléfono y el código recibido por SMS.
    Si es válido, guarda telefono en session para permitir reset de contraseña.
    """
    if request.method == 'POST':
        telefono = request.form['telefono'].strip()
        telefono_normalizado = telefono.replace("+57", "").strip()
        codigo = request.form['codigo'].strip()

        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        try:
            cur.execute("SELECT * FROM password_resets WHERE telefono=%s AND codigo=%s ORDER BY id DESC LIMIT 1",
                        (telefono_normalizado, codigo))
            registro = cur.fetchone()
        finally:
            cur.close()
            conn.close()

        if registro and datetime.datetime.now() < registro['expiracion']:
            session['reset_telefono'] = telefono_normalizado
            return redirect(url_for('reset_password'))
        else:
            flash("Código inválido o expirado.", "danger")

    return render_template('verify_code.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """
    Formulario para establecer la nueva contraseña una vez verificado el código SMS.
    """
    if 'reset_telefono' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        nueva_pass = request.form['password']
        confirm = request.form.get('confirm_password')
        if nueva_pass != confirm:
            flash("Las contraseñas no coinciden.", "danger")
            return render_template('reset_password.html')

        hashed = bcrypt.hashpw(nueva_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = mysql.connect()
        cur = conn.cursor()
        try:
            cur.execute("UPDATE usuarios SET contrasena=%s WHERE telefono=%s",
                        (hashed, session['reset_telefono']))
            conn.commit()
            # opcional: borrar tokens antiguos del mismo telefono
            cur.execute("DELETE FROM password_resets WHERE telefono=%s", (session['reset_telefono'],))
            conn.commit()
        finally:
            cur.close()
            conn.close()

        session.pop('reset_telefono', None)
        flash("Contraseña actualizada correctamente.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# ---------------- DASHBOARD ----------------

@app.route('/dashboard_cliente')
def dashboard_cliente():
    if not session.get('loggedin'):
        return redirect(url_for('login'))

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("SELECT * FROM productos WHERE disponible = 1")
        productos = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template('dashboardClientes.html', productos=productos)

@app.route('/inicio')
def inicio():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard_cliente'))


@app.route('/dashboard_admin')
def dashboard_admin():
    if 'loggedin' in session and session['rol'] == 1:
        return render_template('dashboardAdmin.html')
    return redirect('/login')

#  NOTIFICACIONES DEL CLIENTE

# OBTENER NOTIFICACIONES DEL CLIENTE
@app.route('/notificaciones_cliente')
def notificaciones_cliente():
    if 'id' not in session:
        return jsonify([])

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    cur.execute("""
        SELECT id_notificacion, mensaje, leido, fecha
        FROM notificaciones
        WHERE id_cliente = %s
        ORDER BY fecha DESC
    """, (session['id'],))

    notificaciones = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify(notificaciones)


# CANTIDAD DE NOTIFICACIONES NO LEÍDAS  
@app.route('/notificaciones/cantidad')
def notificaciones_cantidad():
    if 'id' not in session:
        return jsonify({"cantidad": 0})

    conn = mysql.connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) 
        FROM notificaciones 
        WHERE id_cliente = %s AND leido = 0
    """, (session['id'],))

    cantidad = cur.fetchone()[0]

    cur.close()
    conn.close()

    return jsonify({"cantidad": cantidad})


# MARCAR NOTIFICACIONES COMO LEÍDAS
@app.route('/notificaciones_leidas', methods=['POST'])
def notificaciones_leidas():
    if 'id' not in session:
        return jsonify({'status': 'error', 'message': 'Usuario no autenticado'})

    conn = mysql.connect()
    cur = conn.cursor()

    cur.execute("""
        UPDATE notificaciones
        SET leido = 1
        WHERE id_cliente = %s
    """, (session['id'],))

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'status': 'success'})


# ---------------- MENÚ Y CARRITO ----------------

@app.route('/menu')
def menu():
    if 'loggedin' not in session:
        return redirect('/login')

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    carrito_items = []
    total_carrito = 0.0
    try:
        cur.execute("SELECT * FROM productos WHERE disponible = 1")
        productos = cur.fetchall()

        carrito_ids = session.get('carrito', [])
        for pid in carrito_ids:
            cur.execute(
                "SELECT id_producto, nombre_producto AS nombre, precio, imagen FROM productos WHERE id_producto = %s",
                (pid,)
            )
            p = cur.fetchone()
            if p:
                carrito_items.append(p)
                total_carrito += float(p['precio'])
    finally:
        cur.close()
        conn.close()

    return render_template('menu.html', productos=productos, carrito_items=carrito_items, total_carrito=total_carrito)


@app.route('/carrito')
def ver_carrito():
    if 'loggedin' not in session:
        return redirect('/login')

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    carrito_items = []
    total_carrito = 0.0
    try:
        carrito_ids = session.get('carrito', [])
        for pid in carrito_ids:
            cur.execute(
                "SELECT id_producto, nombre_producto AS nombre, precio, imagen FROM productos WHERE id_producto = %s",
                (pid,)
            )
            p = cur.fetchone()
            if p:
                carrito_items.append(p)
                total_carrito += float(p['precio'])
    finally:
        cur.close()
        conn.close()

    # NUEVO: recuperamos dirección validada
    direccion = session.get('direccion', None)

    return render_template(
        'carrito.html',
        carrito_items=carrito_items,
        total_carrito=total_carrito,
        direccion=direccion  # 🔹 pasamos dirección al template
    )

@app.route('/agregar_carrito', methods=['POST'])
def agregar_carrito():
    if 'loggedin' not in session:
        return redirect('/login')

    pid = request.form.get('producto_id')
    if not pid:
        flash("Producto no válido.", "error")
        return redirect(url_for('menu'))

    carrito = session.get('carrito', [])
    carrito.append(int(pid))
    session['carrito'] = carrito

    flash("Producto agregado al carrito.", "success")
    return redirect(url_for('menu'))


@app.route('/quitar_carrito', methods=['POST'])
def quitar_carrito():
    if 'loggedin' not in session:
        return redirect('/login')

    pid = int(request.form.get('producto_id'))
    carrito = session.get('carrito', [])
    if pid in carrito:
        carrito.remove(pid)
    session['carrito'] = carrito
    return redirect(url_for('menu'))



# ---------------- REALIZAR PEDIDO ----------------
@app.route('/realizar_pedido', methods=['POST'])
def realizar_pedido():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    carrito = session.get('carrito', [])
    if not carrito:
        flash("Tu carrito está vacío.", "warning")
        return redirect(url_for('menu'))

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        # Calcular total del carrito y validar productos
        total_carrito = 0
        productos_con_precios = []
        for pid in carrito:
            cur.execute("SELECT id_producto, precio FROM productos WHERE id_producto = %s", (pid,))
            producto = cur.fetchone()
            if producto and producto['precio']:
                productos_con_precios.append(producto)
                total_carrito += float(producto['precio'])
            else:
                flash(f"El producto con ID {pid} no tiene un precio válido.", "danger")

        # Verificar si hay datos previos del pedido (mesa o dirección)
        pedido_id = session.get('pedido_id')
        mesa_id = session.get('mesa_id')
        direccion = session.get('direccion') if not mesa_id else None  # Solo aplica en domicilio

        if pedido_id:
            # Actualizar total del pedido existente
            cur.execute(
                "UPDATE pedidos SET total = total + %s WHERE id_pedido = %s",
                (total_carrito, pedido_id)
            )
        else:
            # Crear nuevo pedido
            cur.execute("""
                INSERT INTO pedidos (id_cliente, fecha_pedido, estado, total, tipo_pedido, id_mesa, direccion)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                session['id'],
                datetime.datetime.now(),
                'Pendiente',
                total_carrito,
                'En mesa' if mesa_id else 'Domicilio',
                mesa_id,
                direccion
            ))
            pedido_id = cur.lastrowid
            session['pedido_id'] = pedido_id

        # Insertar detalle de cada producto con su precio actual
        for producto in productos_con_precios:
            cur.execute("""
                INSERT INTO detalle_pedidos (id_pedido, id_producto, cantidad, precio_unitario)
                VALUES (%s, %s, %s, %s)
            """, (pedido_id, producto['id_producto'], 1, producto['precio']))

        # Confirmar cambios
        conn.commit()

        # Vaciar carrito después de confirmar
        session['carrito'] = []

        flash("✅ Pedido realizado con éxito.", "success")
        return redirect(url_for('mis_pedidos'))

    finally:
        cur.close()
        conn.close()


@app.route('/pedido_domicilio', methods=['GET', 'POST'])
def pedido_domicilio():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Obtener dirección guardada si existe
    direccion_guardada = session.get('direccion_guardada', None)

    if request.method == 'POST':

        # Si el usuario selecciona la dirección guardada
        if request.form.get("usar_guardada") == "si":
            session['direccion'] = direccion_guardada
            flash("Dirección seleccionada correctamente ✅", "success")
            return redirect(url_for('menu'))

        # Dirección nueva
        via = request.form.get('via')
        numero = request.form.get('numero')
        barrio = request.form.get('barrio')
        localidad = request.form.get('localidad')
        ciudad = request.form.get('ciudad')

        direccion_completa = f"{via} {numero}, {barrio}, {localidad}, {ciudad}"

        # Validación: solo aceptar Fontibón - Bogotá
        if localidad.strip().lower() == "fontibón" and ciudad.strip().lower() == "bogotá":

            # ¿Guardar la nueva dirección?
            if request.form.get("guardar_direccion") == "si":
                session['direccion_guardada'] = direccion_completa

            session['direccion'] = direccion_completa
            flash("Dirección confirmada correctamente ✅", "success")
            return redirect(url_for('menu'))
        else:
            flash("🚫 Solo entregamos en Fontibón, Bogotá.", "error")

    return render_template("pedido_domicilio.html", direccion_guardada=direccion_guardada)


# ----------------Mis pedidos-------------
@app.route('/mis_pedidos')
def mis_pedidos():
    if 'id' not in session:
        flash("Debes iniciar sesión para ver tus pedidos", "error")
        return redirect(url_for('login'))

    # 🔥 MARCAR NOTIFICACIONES COMO LEÍDAS SIN DAÑAR NADA
    conn = mysql.connect()
    cur = conn.cursor()
    cur.execute("""
        UPDATE notificaciones
        SET leido = 1
        WHERE id_cliente = %s
    """, (session['id'],))
    conn.commit()
    cur.close()

    # 🔽 DESDE AQUÍ TODO SIGUE TAL CUAL LO TENÍAS 🔽

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Pedidos en curso
        cur.execute("""
            SELECT p.id_pedido, p.fecha_pedido, p.estado, p.total,
                   GROUP_CONCAT(pr.nombre_producto SEPARATOR ', ') AS productos
            FROM pedidos p
            JOIN detalle_pedidos dp ON p.id_pedido = dp.id_pedido
            JOIN productos pr ON dp.id_producto = pr.id_producto
            WHERE p.id_cliente = %s 
              AND p.estado IN ('Pendiente','Preparando','En camino')
            GROUP BY p.id_pedido, p.fecha_pedido, p.estado, p.total
            ORDER BY p.fecha_pedido DESC
        """, (session['id'],))
        pedidos_curso = cur.fetchall()

        # Pedidos finalizados
        cur.execute("""
            SELECT p.id_pedido, p.fecha_pedido, p.estado, p.total,
                   GROUP_CONCAT(pr.nombre_producto SEPARATOR ', ') AS productos
            FROM pedidos p
            JOIN detalle_pedidos dp ON p.id_pedido = dp.id_pedido
            JOIN productos pr ON dp.id_producto = pr.id_producto
            WHERE p.id_cliente = %s 
              AND p.estado = 'Entregado'
            GROUP BY p.id_pedido, p.fecha_pedido, p.estado, p.total
            ORDER BY p.fecha_pedido DESC
        """, (session['id'],))
        pedidos_finalizados = cur.fetchall()

    finally:
        cur.close()
        conn.close()

    return render_template(
        "mis_pedidos.html",
        pedidos_curso=pedidos_curso,
        pedidos_finalizados=pedidos_finalizados
    )



@app.route('/pedidos_finalizados')
def pedidos_finalizados():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    cur.execute("""
        SELECT p.id, p.fecha, p.estado, GROUP_CONCAT(prod.nombre SEPARATOR ', ') AS productos
        FROM pedidos p
        JOIN detalle_pedidos dp ON p.id = dp.id_pedido
        JOIN productos prod ON dp.id_producto = prod.id
        WHERE p.id_usuario = %s AND p.estado = 'Entregado'
        GROUP BY p.id, p.fecha, p.estado
        ORDER BY p.fecha DESC
    """, (session['id'],))

    pedidos = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('pedidos_finalizados.html', pedidos=pedidos)


# ---------------- MESAS ----------------

@app.route('/mesas')
def mesas():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    user_id = session['id']

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        #  1. Verificar si el usuario ya tiene un pedido pendiente
        cur.execute("""
            SELECT id_pedido 
            FROM pedidos 
            WHERE id_cliente=%s AND estado IN ('Pendiente','En preparación')
            ORDER BY id_pedido DESC LIMIT 1
        """, (user_id,))
        pedido_activo = cur.fetchone()

        if pedido_activo:
            # Ya tiene un pedido en curso → no dejar seleccionar otra mesa
            flash("⚠️ Ya tienes un pedido en curso. Finalízalo antes de seleccionar otra mesa.", "warning")
            return redirect(url_for('menu'))

        #  2. Mostrar mesas realmente disponibles
        cur.execute("SELECT * FROM mesas WHERE disponible = TRUE")
        mesas_disponibles = cur.fetchall()

    finally:
        cur.close()
        conn.close()

    return render_template('mesas.html', mesas=mesas_disponibles)

@app.route('/seleccionar_mesa/<int:mesa_id>', methods=['POST'])
def seleccionar_mesa(mesa_id):
    if 'loggedin' not in session:
        flash("Acceso no autorizado", "danger")
        return redirect(url_for('login'))

    user_id = session['id']

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        #  1. Verificar si el usuario ya tiene pedido pendiente
        cur.execute("""
            SELECT id_pedido FROM pedidos 
            WHERE id_cliente=%s AND estado IN ('Pendiente','En preparación')
            ORDER BY id_pedido DESC LIMIT 1
        """, (user_id,))
        pedido_activo = cur.fetchone()

        if pedido_activo:
            flash("⚠️ Ya tienes un pedido en curso. No puedes seleccionar otra mesa.", "warning")
            return redirect(url_for('menu'))

        #  2. Verificar si la mesa sigue disponible
        cur.execute("SELECT disponible FROM mesas WHERE id_mesa=%s", (mesa_id,))
        mesa_info = cur.fetchone()

        if not mesa_info or mesa_info['disponible'] == 0:
            flash("❌ La mesa ya fue tomada por otro cliente.", "danger")
            return redirect(url_for('mesas'))

        # 3. Marcar mesa como ocupada
        cur.execute("UPDATE mesas SET disponible = 0, id_usuario=%s WHERE id_mesa=%s", 
                    (user_id, mesa_id))

        # 4. Crear el pedido asociado
        cur.execute("""
            INSERT INTO pedidos (id_cliente, tipo_pedido, id_mesa, estado, fecha_pedido, total)
            VALUES (%s, 'En mesa', %s, 'Pendiente', NOW(), 0)
        """, (user_id, mesa_id))

        pedido_id = cur.lastrowid
        conn.commit()

        session['pedido_id'] = pedido_id

    finally:
        cur.close()
        conn.close()

    return redirect(url_for('menu'))

@app.route('/actualizar_estado_pedido/<int:pedido_id>', methods=['POST'])
def actualizar_estado_pedido(pedido_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    nuevo_estado = request.form['estado']

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Actualizar estado
        cur.execute("UPDATE pedidos SET estado=%s WHERE id_pedido=%s", 
                    (nuevo_estado, pedido_id))

        # Si se entregó → liberar mesa
        if nuevo_estado == "Entregado":
            cur.execute("SELECT id_mesa FROM pedidos WHERE id_pedido=%s", (pedido_id,))
            pedido = cur.fetchone()

            if pedido and pedido['id_mesa']:
                cur.execute("""
                    UPDATE mesas 
                    SET disponible=1, id_usuario=NULL 
                    WHERE id_mesa=%s
                """, (pedido['id_mesa'],))

        conn.commit()
        flash("Estado del pedido actualizado correctamente", "success")

    finally:
        cur.close()
        conn.close()

    return redirect(url_for('dashboard_empleado'))


# ---------------- ADMIN CRUD ----------------

@app.route('/admin/crud')
def admin_crud():
    if 'loggedin' in session and session['rol'] == 1:
        conn = mysql.connect()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        try:
            cur.execute("SELECT * FROM categorias")
            categorias = cur.fetchall()
            cur.execute("SELECT p.*, c.nombre_categoria FROM productos p JOIN categorias c ON p.id_categoria = c.id_categoria")
            productos = cur.fetchall()
        finally:
            cur.close()
            conn.close()
        return render_template('editar_producto.html', categorias=categorias, productos=productos)
    return redirect('/login')

@app.route('/admin/empleados', methods=['GET', 'POST'])
def empleados():
    if 'loggedin' not in session or session['rol'] != 1:  # Solo admin
        flash("Acceso no autorizado", "danger")
        return redirect(url_for('login'))

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    mensaje = None

    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        telefono = request.form['telefono']
        rol = request.form['rol']
        cargo = request.form['cargo']
        contrasena = request.form['contrasena']

        # Rol numérico (1=Admin, 2=Empleado)
        id_rol = 1 if rol == "Administrador" else 2  

        # Encriptar contraseña
        hashed_pw = bcrypt.hashpw(contrasena.encode('utf-8'), bcrypt.gensalt())

        try:
            # Insertar en usuarios
            cur.execute("""
                INSERT INTO usuarios (nombre, correo, telefono, contrasena, id_rol)
                VALUES (%s, %s, %s, %s, %s)
            """, (nombre, correo, telefono, hashed_pw, id_rol))
            conn.commit()

            # Obtener el id del usuario insertado
            id_usuario = cur.lastrowid  

            # Insertar en empleados
            cur.execute("""
                INSERT INTO empleados (id_usuario, cargo)
                VALUES (%s, %s)
            """, (id_usuario, cargo))
            conn.commit()

            mensaje = f"✅ Empleado {nombre} agregado con éxito."
        except Exception as e:
            conn.rollback()
            mensaje = f"⚠️ Error al registrar: {str(e)}"

    # Consultar todos los empleados
    cur.execute("""
       SELECT 
        u.id_usuario,      
        u.nombre,          
        u.correo,          
        r.nombre_rol,      
        e.cargo            
       FROM usuarios u
       JOIN roles r ON u.id_rol = r.id_rol
       JOIN empleados e ON u.id_usuario = e.id_usuario
    """)
    empleados = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('empleados.html', empleados=empleados, mensaje=mensaje)

@app.route('/admin/categorias', methods=['POST'])
def registrar_categoria():
    if 'loggedin' not in session or session['rol'] != 1:
        return redirect('/login')

    nombre = request.form['nombre_categoria']
    conn = mysql.connect()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO categorias (nombre_categoria) VALUES (%s)", (nombre,))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    return redirect('/admin/crud')


@app.route('/admin/productos', methods=['POST'])
def registrar_producto():
    if 'loggedin' not in session or session['rol'] != 1:
        return redirect('/login')

    nombre = request.form['nombre_producto']
    descripcion = request.form['descripcion']
    precio = request.form['precio']
    id_categoria = request.form['id_categoria']
    disponible = 1 if 'disponible' in request.form else 0

    imagen = request.files['imagen']
    nombre_imagen = secure_filename(imagen.filename)
    ruta_imagen = os.path.join(app.config['UPLOAD_FOLDER'], nombre_imagen)
    imagen.save(ruta_imagen)

    conn = mysql.connect()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO productos (nombre_producto, descripcion, precio, imagen, id_categoria, disponible) VALUES (%s, %s, %s, %s, %s, %s)",
            (nombre, descripcion, precio, nombre_imagen, id_categoria, disponible)
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return redirect('/admin/crud')


@app.route('/admin/eliminar_producto/<int:id_producto>')
def eliminar_producto(id_producto):
    if 'loggedin' not in session or session['rol'] != 1:
        return redirect('/login')

    conn = mysql.connect()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM productos WHERE id_producto = %s", (id_producto,))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    return redirect('/admin/crud')


@app.route('/admin/editar_producto/<int:id_producto>', methods=['GET', 'POST'])
def editar_producto(id_producto):
    if 'loggedin' not in session or session['rol'] != 1:
        return redirect('/login')

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        if request.method == 'POST':
            nombre = request.form['nombre_producto']
            descripcion = request.form['descripcion']
            precio = request.form['precio']
            id_categoria = request.form['id_categoria']
            disponible = 1 if 'disponible' in request.form else 0

            imagen = request.files['imagen']
            if imagen:
                nombre_imagen = secure_filename(imagen.filename)
                ruta_imagen = os.path.join(app.config['UPLOAD_FOLDER'], nombre_imagen)
                imagen.save(ruta_imagen)
                cur.execute(
                    "UPDATE productos SET nombre_producto=%s, descripcion=%s, precio=%s, imagen=%s, id_categoria=%s, disponible=%s WHERE id_producto=%s",
                    (nombre, descripcion, precio, nombre_imagen, id_categoria, disponible, id_producto)
                )
            else:
                cur.execute(
                    "UPDATE productos SET nombre_producto=%s, descripcion=%s, precio=%s, id_categoria=%s, disponible=%s WHERE id_producto=%s",
                    (nombre, descripcion, precio, id_categoria, disponible, id_producto)
                )

            conn.commit()
            return redirect('/admin/crud')
        else:
            cur.execute("SELECT * FROM productos WHERE id_producto = %s", (id_producto,))
            producto = cur.fetchone()
            cur.execute("SELECT * FROM categorias")
            categorias = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template('editar_producto.html', producto=producto, categorias=categorias)


# ----------------REPORTES----------------
@app.route("/admin/estadisticas", methods=["GET", "POST"])
def admin_reportes():
    fecha_inicio = request.form.get("fecha_inicio")
    fecha_fin = request.form.get("fecha_fin")

    # Abrir conexión manualmente
    conn = mysql.connect()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # === Productos más vendidos ===
    query_productos = """
        SELECT p.nombre_producto, SUM(dp.cantidad) as total_vendidos
        FROM detalle_pedidos dp
        JOIN productos p ON dp.id_producto = p.id_producto
        JOIN pedidos ped ON dp.id_pedido = ped.id_pedido
        WHERE (%s IS NULL OR ped.fecha_pedido >= %s)
          AND (%s IS NULL OR ped.fecha_pedido <= %s)
        GROUP BY p.nombre_producto
        ORDER BY total_vendidos DESC
        LIMIT 5;
    """
    cursor.execute(query_productos, (fecha_inicio, fecha_inicio, fecha_fin, fecha_fin))
    top_productos = cursor.fetchall() or []

    # === Pedidos por día ===
    query_dias = """
        SELECT DATE(fecha_pedido) as fecha, COUNT(*) as total_pedidos
        FROM pedidos
        WHERE (%s IS NULL OR fecha_pedido >= %s)
          AND (%s IS NULL OR fecha_pedido <= %s)
        GROUP BY DATE(fecha_pedido);
    """
    cursor.execute(query_dias, (fecha_inicio, fecha_inicio, fecha_fin, fecha_fin))
    pedidos_por_dia = cursor.fetchall() or []

    # === Pedidos por estado ===
    query_estado = """
        SELECT estado, COUNT(*) as total
        FROM pedidos
        WHERE (%s IS NULL OR fecha_pedido >= %s)
          AND (%s IS NULL OR fecha_pedido <= %s)
        GROUP BY estado;
    """
    cursor.execute(query_estado, (fecha_inicio, fecha_inicio, fecha_fin, fecha_fin))
    pedidos_por_estado = cursor.fetchall() or []

    cursor.close()
    conn.close()

    return render_template(
        "admin_reportes.html",
        top_productos=top_productos,
        pedidos_por_dia=pedidos_por_dia,
        pedidos_por_estado=pedidos_por_estado,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin
    )




# ---------------- EMPLEADOS----------------

# Ruta para dashboard del empleado
@app.route('/dashboard_empleado')
def dashboard_empleado():
    if 'loggedin' not in session or session['rol'] != 2:
        flash("Acceso no autorizado", "danger")
        return redirect(url_for('login'))

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Traer pedidos activos
        cur.execute("""
            SELECT p.id_pedido, 
                   p.estado, 
                   p.fecha_pedido, 
                   u.nombre AS cliente,
                   p.tipo_pedido,
                   p.direccion AS direccion_entrega,
                   m.numero_mesa
            FROM pedidos p
            JOIN usuarios u ON p.id_cliente = u.id_usuario
            LEFT JOIN mesas m ON p.id_mesa = m.id_mesa
            WHERE p.estado IN ('Pendiente', 'Preparando', 'En camino')
            ORDER BY p.fecha_pedido ASC
        """)
        pedidos = cur.fetchall()

        # Agregar los detalles
        for pedido in pedidos:
            cur.execute("""
                SELECT pr.nombre_producto,
                       dp.cantidad,
                       dp.precio_unitario
                FROM detalle_pedidos dp
                JOIN productos pr ON dp.id_producto = pr.id_producto
                WHERE dp.id_pedido = %s
            """, (pedido['id_pedido'],))
            detalle = cur.fetchall()

            # Asegurar valores válidos
            for d in detalle:
                d['cantidad'] = d.get('cantidad') or 0
                d['precio_unitario'] = d.get('precio_unitario') or 0.0
                d['subtotal'] = float(d['cantidad']) * float(d['precio_unitario'])

            pedido['detalle'] = detalle
            pedido['total'] = sum(d['subtotal'] for d in detalle) if detalle else 0
            pedido["total"] = "{:,.0f}".format(int(pedido["total"])).replace(",", ".")

    finally:
        cur.close()
        conn.close()

    return render_template('dashboardEmpleado.html', pedidos=pedidos)


# ---------------- ACTUALIZAR PEDIDO ----------------
@app.route('/actualizar_pedido/<int:id_pedido>', methods=['POST'])
def actualizar_pedido(id_pedido):
    nuevo_estado = request.form['estado']
    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    # Actualizamos estado del pedido
    cur.execute("UPDATE pedidos SET estado=%s WHERE id_pedido=%s", (nuevo_estado, id_pedido))

    # Si se entregó, liberar mesa
    if nuevo_estado == "Entregado":
        cur.execute("SELECT id_mesa FROM pedidos WHERE id_pedido=%s", (id_pedido,))
        mesa = cur.fetchone()
        if mesa and mesa["id_mesa"]:
            cur.execute("UPDATE mesas SET disponible=1 WHERE id_mesa=%s", (mesa["id_mesa"],))

    # Crear notificación para el cliente
    cur.execute("SELECT id_cliente FROM pedidos WHERE id_pedido=%s", (id_pedido,))
    pedido = cur.fetchone()
    if pedido:
        mensaje = f"Tu pedido #{id_pedido} cambió a estado: {nuevo_estado}"
        cur.execute("""
            INSERT INTO notificaciones (id_cliente, mensaje, leido)
            VALUES (%s, %s, 0)
        """, (pedido['id_cliente'], mensaje))

    conn.commit()
    cur.close()
    conn.close()

    flash("Estado actualizado correctamente", "success")
    return redirect(url_for('dashboard_empleado'))


# ---------------- PEDIDOS ENTRANTES ----------------
@app.route('/pedidos_entrantes')
def pedidos_entrantes():
    if 'loggedin' not in session or session['rol'] != 2:
        return redirect('/login')

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Traemos pedidos pendientes con info principal
        cur.execute("""
            SELECT p.id_pedido,
                   p.estado,
                   p.fecha_pedido,
                   u.nombre AS cliente,
                   p.tipo_pedido,
                   p.direccion AS direccion_entrega,
                   m.numero_mesa
            FROM pedidos p
            JOIN usuarios u ON p.id_cliente = u.id_usuario
            LEFT JOIN mesas m ON p.id_mesa = m.id_mesa
            WHERE p.estado = 'Pendiente'
            ORDER BY p.fecha_pedido ASC
        """)
        pedidos = cur.fetchall()

        # Para cada pedido, traer detalle de productos. Si dp.precio_unitario es NULL
        # usamos el precio actual del producto (pr.precio) con COALESCE.
        for pedido in pedidos:
            cur.execute("""
                SELECT pr.nombre_producto,
                       COALESCE(dp.cantidad, 0) AS cantidad,
                       COALESCE(dp.precio_unitario, pr.precio, 0) AS precio_unitario,
                       (COALESCE(dp.cantidad,0) * COALESCE(dp.precio_unitario, pr.precio, 0)) AS subtotal
                FROM detalle_pedidos dp
                JOIN productos pr ON dp.id_producto = pr.id_producto
                WHERE dp.id_pedido = %s
            """, (pedido['id_pedido'],))
            detalle = cur.fetchall() or []

            # Aseguramos tipos numéricos y calculamos subtotal si hace falta
            for d in detalle:
                # forzar tipos
                d['cantidad'] = int(d.get('cantidad') or 0)
                # puede venir Decimal desde pymysql; forzamos float
                d['precio_unitario'] = float(d.get('precio_unitario') or 0.0)
                d['subtotal'] = float(d.get('subtotal') or (d['cantidad'] * d['precio_unitario']))

            pedido['detalle'] = detalle
            total = sum(d['subtotal'] for d in detalle) if detalle else 0.0
            pedido['total'] = total

    finally:
        cur.close()
        conn.close()

    return render_template('dashboardEmpleado.html', pedidos=pedidos)


# ---------------- DETALLE PEDIDO ----------------
@app.route('/pedido/<int:id_pedido>')
def detalle_pedido(id_pedido):
    if 'loggedin' not in session or session['rol'] != 2:
        return redirect('/login')

    conn = mysql.connect()
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        # 1️ Traer la información general del pedido
        cur.execute("""
            SELECT p.*, u.nombre AS cliente, m.numero_mesa
            FROM pedidos p
            JOIN usuarios u ON p.id_cliente = u.id_usuario
            LEFT JOIN mesas m ON p.id_mesa = m.id_mesa
            WHERE p.id_pedido = %s
        """, (id_pedido,))
        pedido = cur.fetchone()

        #  Traer los productos del pedido (detalle)
        cur.execute("""
            SELECT dp.id_detalle,
                   pr.nombre_producto,
                   dp.cantidad,
                   dp.precio_unitario,
                   (dp.cantidad * dp.precio_unitario) AS subtotal
            FROM detalle_pedidos dp
            JOIN productos pr ON dp.id_producto = pr.id_producto
            WHERE dp.id_pedido = %s
        """, (id_pedido,))
        productos = cur.fetchall()

        # 3️⃣ Calcular total del pedido
        total = sum([item['subtotal'] for item in productos]) if productos else 0

    finally:
        cur.close()
        conn.close()

    return render_template('dashboardEmpleado.html',
                           pedido=pedido,
                           productos=productos,
                           total=total)

# ---------------- CONFIGURACIÓN CACHE ----------------

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    app.run(debug=True)
