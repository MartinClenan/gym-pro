# Gym Pro

Panel web para socios, pagos, asistencia y reportes. El sitio estático no debe guardar credenciales ni conectarse directamente a Airtable; para eso se incluye una API Node.js que valida el inicio de sesión y mantiene el token de Airtable en variables privadas del servidor.

## Acción urgente antes de publicar

El repositorio público anterior contenía un token de Airtable y contraseñas dentro del HTML. Revocá o regenerá el token filtrado desde Airtable y cambiá esas contraseñas si siguen vigentes. Revisá la actividad y los datos recientes de la base. Borrar el texto del último archivo no elimina copias del historial de Git; la rotación del token es lo que invalida la credencial expuesta.

No publiques esta versión hasta desplegar y configurar la API. Sin backend, el acceso y las operaciones de datos quedan bloqueados a propósito.

## Configurar la API

Requiere Node.js 20 o posterior. El servidor usa módulos incluidos con Node y no necesita instalar dependencias.

1. En Airtable, creá un token nuevo limitado a la base del gimnasio y a los permisos de lectura y escritura de registros que necesita la aplicación. No lo pongas en `gym-config.js`, HTML, GitHub Pages ni en el historial de Git.
2. Creá una contraseña nueva y única para cada usuario. En una terminal local, ejecutá `node backend/hash-password.mjs martin MC` y `node backend/hash-password.mjs danilo DR`. La contraseña se solicita sin mostrar lo que escribís; el comando imprime un fragmento JSON con el hash. No compartas la contraseña ni pegues el hash en este chat.
3. Combiná los dos fragmentos en un único objeto JSON y guardalo como variable secreta `AUTH_USERS_JSON` en el host de la API. El contenido tendrá esta forma, con los valores generados por el comando:

   ```json
   {"martin":{"salt":"...","hash":"...","rol":"admin","iniciales":"MC"},"danilo":{"salt":"...","hash":"...","rol":"admin","iniciales":"DR"}}
   ```

4. Configurá estas variables privadas en un host que ejecute Node 20 y ofrezca HTTPS:

   - `ALLOWED_ORIGIN=https://martinclenan.github.io`
   - `AIRTABLE_BASE_ID`
   - `AIRTABLE_PERSONAL_ACCESS_TOKEN`
   - `SOCIOS_TABLE_ID`
   - `PAGOS_TABLE_ID`
   - `SESSION_SECRET` (mínimo 32 caracteres aleatorios)
   - `AUTH_USERS_JSON`
   - `PORT` (opcional; el valor predeterminado es 3000)

5. En `gym-config.js`, asigná a `window.GYM_API_BASE` la URL HTTPS de la API, sin una barra final. Esa URL es pública; no pongas allí secretos.
6. Desplegá la API y el sitio. La sesión vence a los 30 minutos y la pantalla se bloquea tras 15 minutos sin actividad. El token se conserva solo en memoria del navegador; después de recargar la página habrá que iniciar sesión otra vez. Cambiar `SESSION_SECRET` invalida todas las sesiones abiertas.

Para generar un secreto de sesión localmente con Node, ejecutá `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"` y cargá el resultado como variable secreta `SESSION_SECRET`.

## Alcance actual

- El servidor valida usuarios con hashes PBKDF2, limita intentos de acceso, entrega sesiones firmadas de corta duración y restringe las operaciones a las dos tablas configuradas.
- El navegador ya no conserva la sesión en `localStorage` ni contiene el token de Airtable.
- La asistencia todavía se guarda en el navegador que la registra; no se sincroniza entre dispositivos y conviene migrarla a la API en una etapa posterior.
- No se hicieron cambios en Airtable ni se publicaron cambios en GitHub Pages.
