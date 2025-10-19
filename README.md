GUIA 3 con Auth0

Aplicación Flask con inicio de sesión de Auth0 (Universal Login) y edición de perfil
guardando datos en `user_metadata` con la Auth0 Management API.

## Configuración de Auth0
1) Regular Web App → Settings:
   - **Allowed Callback URLs**: `http://localhost:3000/callback`
   - **Allowed Logout URLs**: `http://localhost:3000/`
   - **Allowed Web Origins / CORS**: `http://localhost:3000`
2) APIs → **Auth0 Management API** → Machine to Machine Applications:
   - Autorizar la app M2M con **read:users** y **update:users**.
3) Branding → Universal Login (New Experience):
   - Logo, colores y (opcional) imagen de fondo.

## Variables de entorno
1) Copia `.env.example` a `.env` y completa tus credenciales.
2) Asegúrate de que `AUTH0_DOMAIN` sea del tipo `xxxx.us.auth0.com` (sin `https://`).

## Instalación y ejecución
```bash
python -m venv .venv
# Windows PowerShell:  .\.venv\Scripts\Activate.ps1
# Windows Git Bash:    source .venv/Scripts/activate
pip install -r requirements.txt
python app.py
# Abre http://localhost:3000
