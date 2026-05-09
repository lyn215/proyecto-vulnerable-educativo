"""
=============================================================
SENTIMENT SECURITY LAB — VERSIÓN VULNERABLE
=============================================================
⚠️  ADVERTENCIA: Este archivo contiene vulnerabilidades
    INTENCIONALES para uso exclusivo en laboratorio local.
    NO desplegar en producción ni en redes públicas.
    Cada fallo está documentado con # [VULN-XX].
=============================================================
"""

import os
import sqlite3
import logging
from flask import Flask, request, render_template, redirect, url_for, session
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import pandas as pd

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# [VULN-01] Debug mode activo — expone traceback completo al usuario
app = Flask(__name__)
app.secret_key = os.urandom(24) # [VULN-02] Clave secreta débil y hardcodeada
app.config["DEBUG"] = False  # [VULN-01]
app.config["UPLOAD_FOLDER"] = "uploads"

# [VULN-03] Logging sin filtrado de datos sensibles
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    filename="app.log"
)
logger = logging.getLogger(__name__)

# [VULN-04] Contraseña almacenada en texto plano
password1 = "admin123"
password2 = "password"
USUARIOS = {
    "admin": generate_password_hash(password1),
    "alumno": generate_password_hash(password2)
}

analyzer = SentimentIntensityAnalyzer()


def get_db():
    """Conexión a SQLite sin protección."""
    conn = sqlite3.connect("data/resultados.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    # [VULN-05] Tabla creada sin índices ni restricciones
    conn.execute("""
        CREATE TABLE IF NOT EXISTS resultados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comentario TEXT NOT NULL,
            sentimiento TEXT NOT NULL,
            score REAL NOT NULL,
            usuario TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def analizar_sentimiento(texto):
    scores = analyzer.polarity_scores(texto)
    compound = scores["compound"]
    if compound >= 0.05:
        return "positivo", compound
    elif compound <= -0.05:
        return "negativo", compound
    else:
        return "neutral", compound


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        password = request.form.get("password", "")

        # [VULN-03] Log con credenciales en texto plano
        logger.debug(f"Intento de login: usuario={usuario} password={password}")

        # [VULN-06] Sin rate limiting — vulnerable a fuerza bruta
        if usuario in USUARIOS and USUARIOS[usuario] == password:
            session["usuario"] = usuario
            return redirect(url_for("index"))
        else:
            # [VULN-07] Mensaje de error detallado que revela info del sistema
            error = f"Usuario '{usuario}' no encontrado o contraseña incorrecta para ese usuario."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/analizar", methods=["POST"])
def analizar():
    resultados = []

    # --- Análisis de texto manual ---
    comentario = request.form.get("comentario", "")
    if comentario:
        # [VULN-08] Sin validación de longitud ni sanitización
        sentimiento, score = analizar_sentimiento(comentario)
        resultados.append({
            "comentario": comentario,  # [VULN-09] XSS: se renderiza sin escape en template
            "sentimiento": sentimiento,
            "score": round(score, 4)
        })

        # Guardar en DB
        conn = get_db()
        usuario = session.get("usuario", "anonimo")
        # [VULN-10] Query construida con concatenación — SQL Injection educativo
        query = f"INSERT INTO resultados (comentario, sentimiento, score, usuario) VALUES ('{comentario}', '{sentimiento}', {score}, '{usuario}')"
        logger.debug(f"Ejecutando query: {query}")
        conn.execute(query)
        conn.commit()
        conn.close()

    # --- Análisis de archivo ---
    archivo = request.files.get("archivo")
    if archivo and archivo.filename:
        # [VULN-11] Sin validación de extensión ni MIME type
        # [VULN-12] Nombre de archivo sin sanitización — path traversal posible
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], archivo.filename)
        archivo.save(filepath)
        logger.debug(f"Archivo guardado: {filepath}")

        try:
            # [VULN-13] Sin límite de tamaño de archivo
            if archivo.filename.endswith(".csv"):
                df = pd.read_csv(filepath)
                columna = df.columns[0]
                for texto in df[columna].dropna().tolist():
                    sentimiento, score = analizar_sentimiento(str(texto))
                    resultados.append({
                        "comentario": texto,
                        "sentimiento": sentimiento,
                        "score": round(score, 4)
                    })
            else:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for linea in f.readlines():
                        linea = linea.strip()
                        if linea:
                            sentimiento, score = analizar_sentimiento(linea)
                            resultados.append({
                                "comentario": linea,
                                "sentimiento": sentimiento,
                                "score": round(score, 4)
                            })
        except Exception as e:
            # [VULN-14] Mensaje de error con stack trace completo al usuario
            return f"<h2>Error interno:</h2><pre>{str(e)}</pre>", 500

    # Estadísticas básicas
    stats = {"positivo": 0, "neutral": 0, "negativo": 0}
    for r in resultados:
        stats[r["sentimiento"]] = stats.get(r["sentimiento"], 0) + 1

    return render_template("results.html", resultados=resultados, stats=stats)


@app.route("/historial")
def historial():
    conn = get_db()
    # [VULN-10] Query con parámetro de URL sin sanitización
    usuario_filtro = request.args.get("usuario", "")
    if usuario_filtro:
        query = f"SELECT * FROM resultados WHERE usuario = '{usuario_filtro}'"
    else:
        query = "SELECT * FROM resultados"
    rows = conn.execute(query).fetchall()
    conn.close()
    return render_template("historial.html", rows=rows)


@app.route("/reporte")
def reporte():
    conn = get_db()
    rows = conn.execute("SELECT * FROM resultados").fetchall()
    conn.close()

    import csv, io
    from flask import Response
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "comentario", "sentimiento", "score", "usuario"])
    for row in rows:
        writer.writerow([row["id"], row["comentario"], row["sentimiento"], row["score"], row["usuario"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=reporte.csv"}
    )


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    init_db()
    # [VULN-01] Debug y host 0.0.0.0 expuesto
    app.run(debug=True, host="0.0.0.0", port=5000)
 