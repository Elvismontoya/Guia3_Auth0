# app.py
import os
import json
from functools import wraps

import requests
from flask import Flask, redirect, render_template, request, session, url_for, flash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv, find_dotenv


# =========================
# Cargar variables de entorno
# =========================
load_dotenv(find_dotenv('.env', usecwd=True), override=True)

def clean_domain(value: str) -> str:
    """
    Normaliza el dominio:
    - quita 'https://'
    - elimina '/' finales
    - deja solo <tenant>.us.auth0.com
    """
    if not value:
        return value
    v = value.strip()
    v = v.replace("https://", "").replace("http://", "")
    return v.strip("/")

AUTH0_DOMAIN        = clean_domain(os.getenv("AUTH0_DOMAIN", ""))
AUTH0_CLIENT_ID     = os.getenv("AUTH0_CLIENT_ID", "").strip()
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "").strip()
BASE_URL            = os.getenv("BASE_URL", "http://localhost:3000").strip().rstrip("/")
APP_SECRET_KEY      = os.getenv("APP_SECRET_KEY", "change-me").strip()

# Credenciales para la Management API (M2M)
MGMT_CLIENT_ID      = os.getenv("MGMT_CLIENT_ID", "").strip()
MGMT_CLIENT_SECRET  = os.getenv("MGMT_CLIENT_SECRET", "").strip()

# Validaciones mínimas
if not all([AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET]):
    raise RuntimeError("Faltan variables Auth0 en .env (AUTH0_DOMAIN/ID/SECRET).")


# ==========
# Flask app
# ==========
app = Flask(__name__)
app.secret_key = APP_SECRET_KEY


# ==========
# Auth0 OIDC
# ==========
oauth = OAuth(app)
oauth.register(
    name="auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
)


# ==========
# Helpers
# ==========
def requires_auth(fn):
    """Protege rutas: exige que haya usuario en sesión."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def get_management_token() -> str:
    """
    Obtiene un access_token usando Client Credentials para la Auth0 Management API.
    Requiere que tu app M2M esté autorizada con scopes: read:users, update:users.
    """
    if not MGMT_CLIENT_ID or not MGMT_CLIENT_SECRET:
        raise RuntimeError("Faltan MGMT_CLIENT_ID / MGMT_CLIENT_SECRET en .env")

    url = f"https://{AUTH0_DOMAIN}/oauth/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": MGMT_CLIENT_ID,
        "client_secret": MGMT_CLIENT_SECRET,
        "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
    }
    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()["access_token"]


def mgmt_get_user_metadata(user_id: str, token: str) -> dict:
    url = f"https://{AUTH0_DOMAIN}/api/v2/users/{user_id}"
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20)
    r.raise_for_status()
    return r.json().get("user_metadata") or {}


def mgmt_patch_user_metadata(user_id: str, metadata: dict, token: str) -> dict:
    url = f"https://{AUTH0_DOMAIN}/api/v2/users/{user_id}"
    payload = {"user_metadata": metadata}
    r = requests.patch(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
        timeout=20,
    )
    r.raise_for_status()
    return r.json()


# ==========
# Rutas
# ==========
@app.route("/")
def index():
    """Página de inicio (muestra datos básicos si hay sesión)."""
    return render_template("index.html")


@app.route("/login")
def login():
    """Redirige al Universal Login de Auth0."""
    redirect_uri = f"{BASE_URL}/callback"
    return oauth.auth0.authorize_redirect(redirect_uri=redirect_uri)


@app.route("/callback")
def callback():
    """
    Recibe el code de Auth0, obtiene tokens y guarda el perfil en sesión.
    """
    token = oauth.auth0.authorize_access_token()
    userinfo = token.get("userinfo")
    if not userinfo:
        # Algunas versiones requieren llamar a /userinfo explícitamente
        userinfo = oauth.auth0.userinfo()

    # Guardamos lo esencial en sesión
    session["user"] = {
        "id": userinfo.get("sub"),
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
        "picture": userinfo.get("picture"),
    }
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    """Cierra sesión local y redirige al logout de Auth0."""
    session.clear()
    return redirect(
        f"https://{AUTH0_DOMAIN}/v2/logout"
        f"?client_id={AUTH0_CLIENT_ID}"
        f"&returnTo={BASE_URL}"
    )


@app.route("/profile", methods=["GET", "POST"])
@requires_auth
def profile():
    """
    GET: precarga el formulario con `user_metadata` desde Auth0.
    POST: hace PATCH a /api/v2/users/{id} guardando `user_metadata`.
    """
    user_id = session["user"]["id"]  # p.ej. "auth0|abc123"

    if request.method == "POST":
        metadata_form = {
            "tipo_documento":   request.form.get("tipo_documento", "").strip(),
            "numero_documento": request.form.get("numero_documento", "").strip(),
            "direccion":        request.form.get("direccion", "").strip(),
            "telefono":         request.form.get("telefono", "").strip(),
        }
        try:
            token = get_management_token()
            mgmt_patch_user_metadata(user_id, metadata_form, token)
            flash("Perfil actualizado correctamente.")
        except requests.HTTPError as e:
            # Muestra código y fragmento del error para facilitar el debug
            body = e.response.text
            flash(f"Error al actualizar ({e.response.status_code}): {body[:180]}")
        except Exception as e:
            flash(f"Error inesperado: {e}")
        return redirect(url_for("profile"))

    # GET → cargar metadata
    user_metadata = {}
    try:
        token = get_management_token()
        user_metadata = mgmt_get_user_metadata(user_id, token)
    except Exception:
        # Si falla la lectura no rompemos la vista; mostramos vacío
        user_metadata = {}

    return render_template("profile.html", user_metadata=user_metadata)


# Opcional: healthcheck simple
@app.route("/health")
def health():
    return {"status": "ok"}, 200


# ==========
# Main
# ==========
if __name__ == "__main__":
    # Corre en 127.0.0.1:3000 para que coincida con tu BASE_URL
    app.run(host="127.0.0.1", port=3000, debug=True)
