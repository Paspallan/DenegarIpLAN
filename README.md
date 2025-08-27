## Reddit Subreddit Explorer (solo lectura + crosspost propio)

CLI en Python para explorar subreddits de forma segura y conforme a políticas:
- Obtiene metadatos públicos: reglas, moderadores, requisitos típicos.
- Señala restricciones comunes de publicación (edad de cuenta, karma, verificación, NSFW, flairs requeridos).
- Soporta crosspost de tus propios posts (opcional, conforme a reglas de cada subreddit).

### Requisitos
- Python 3.10+

### Instalación
No requiere dependencias externas. Solo Python 3.10+.

### Configuración OAuth (opcional para comandos con autenticación)
Exporta variables de entorno de tu app tipo "script":
```bash
export REDDIT_CLIENT_ID=xxxx
export REDDIT_CLIENT_SECRET=yyyy
export REDDIT_USERNAME=tu_usuario
export REDDIT_PASSWORD=tu_password
```

### Uso rápido
```bash
python3 -m reddit_cli search --query cars --limit 10
python3 -m reddit_cli inspect --subreddit cars
python3 -m reddit_cli candidates-from-subreddit --subreddit cars --min-score 500 --older-than-days 120 --time-range all --limit 100 --use-auth
python3 -m reddit_cli discover-image-subs --limit-per-query 20
python3 -m reddit_cli candidates --from-user TU_USER --source-subreddit cars --min-score 200 --older-than-days 90
python3 -m reddit_cli crosspost --fullname t3_abcdef --to-subreddit cars --title "Mi título" --execute
python3 -m reddit_cli crosspost-from-subreddit --subreddit cars --to-subreddit carpics --author-allowlist all --min-score 800 --older-than-days 180 --time-range all --limit 200 --execute
```

### Notas de cumplimiento
- Respeta las políticas de Reddit y TOS. No automatiza re-posteo de contenido ajeno.
- Crosspost únicamente de tus propios posts y respetando reglas anti-repost.
