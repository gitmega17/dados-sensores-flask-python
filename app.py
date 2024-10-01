from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
DATABASE = 'database.db'
SECRET_KEY = 'sua_chave_secreta'  # Substitua por uma chave secreta mais segura em produção

# Função para inicializar o banco de dados e criar as tabelas se não existirem
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE,
                      password TEXT
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS dados_sensores (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      sensor_id INTEGER,
                      temperatura REAL,
                      umidade REAL,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                      )''')
    conn.commit()
    conn.close()

# Inicializando o banco de dados na inicialização do servidor
init_db()

# Função para autenticar JWT
def authenticateJWT(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({"message": "Token não fornecido"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = data['userId']
        except:
            return jsonify({"message": "Acesso negado"}), 403

        return f(*args, **kwargs)
    return decorated

# Rota para cadastrar um novo usuário
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('INSERT INTO usuarios (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Usuário já existe"}), 400
    finally:
        conn.close()

# Rota para login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usuarios WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        # A senha está em bytes, não é necessário usar encode() novamente
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):  # user[2] já é bytes
            token = jwt.encode({'userId': user[0], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, SECRET_KEY, algorithm="HS256")
            return jsonify({"message": "Login realizado com sucesso", "token": token})
        
        return jsonify({"message": "Usuário ou senha incorretos"}), 400
    except Exception as e:
        print(f"Erro no login: {str(e)}")  # Imprime o erro no console
        return jsonify({"message": "Erro interno no servidor"}), 500


# Middleware para validação dos dados do sensor
def validar_dados_sensor(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json()
        sensor_id = data.get('sensor_id')
        temperatura = data.get('temperatura')
        umidade = data.get('umidade')

        if not sensor_id or not isinstance(sensor_id, int):
            return jsonify({"message": "ID do sensor é obrigatório e deve ser um número."}), 400

        if not isinstance(temperatura, (int, float)):
            return jsonify({"message": "Temperatura é obrigatória e deve ser um número válido."}), 400

        if not isinstance(umidade, (int, float)):
            return jsonify({"message": "Umidade é obrigatória e deve ser um número válido."}), 400

        return f(*args, **kwargs)
    return decorated

# Endpoint para inserir dados (POST)
@app.route('/dados-sensores', methods=['POST'])
@authenticateJWT
@validar_dados_sensor
def inserir_dados():
    dados = request.get_json()
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO dados_sensores (sensor_id, temperatura, umidade) VALUES (?, ?, ?)',
                   (dados['sensor_id'], dados['temperatura'], dados['umidade']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Dados inseridos com sucesso"}), 201

# Endpoint para buscar todos os dados (GET)
@app.route('/dados-sensores', methods=['GET'])
@authenticateJWT
def buscar_dados():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM dados_sensores')
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)

# Endpoint para limpar todos os dados da tabela (DELETE)
@app.route('/limpar-dados', methods=['DELETE'])
@authenticateJWT
def limpar_dados():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM dados_sensores')
    conn.commit()
    conn.close()
    return jsonify({"message": "Dados limpos com sucesso"}), 200

# Endpoint para fornecer dados JSON para gráficos
@app.route('/dados-sensores-json')
@authenticateJWT
def dados_sensores_json():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, temperatura, umidade FROM dados_sensores')
    rows = cursor.fetchall()
    conn.close()
    
    timestamps = [row[0] for row in rows]
    temperaturas = [row[1] for row in rows]
    umidades = [row[2] for row in rows]
    
    return jsonify({
        'timestamp': timestamps,
        'temperatura': temperaturas,
        'umidade': umidades
    })

# Rota para a página principal
@app.route('/')
def index():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM dados_sensores')
    dados = cursor.fetchall()
    conn.close()
    return render_template('index.html', dados=dados)

# Rota para a exibição de gráficos
@app.route('/graficos')
def graficos():
    return render_template('graficos.html') 

# Inicia o servidor Flask
if __name__ == '__main__':
    app.run(debug=True)
