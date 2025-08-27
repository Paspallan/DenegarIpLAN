## Reddit Subreddit Explorer (solo lectura)

CLI en Python para explorar subreddits de forma segura y conforme a políticas:
- Obtiene metadatos públicos: reglas, moderadores, requisitos típicos.
- Señala restricciones comunes de publicación (edad de cuenta, karma, verificación, NSFW, flairs requeridos).
- No realiza publicaciones ni reposts. Solo lectura.

### Requisitos
- Python 3.10+

### Instalación
No requiere dependencias externas. Solo Python 3.10+.

### Uso rápido
```bash
python3 -m reddit_cli search --query cars --limit 10
python3 -m reddit_cli inspect --subreddit cars
```

### Notas de cumplimiento
- Respeta las políticas de Reddit y TOS. Sin automatización de acciones de usuario.
- Solo consume endpoints públicos y rate-limits conservadores.
