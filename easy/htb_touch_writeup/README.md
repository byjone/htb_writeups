# HTB Touch — Writeup | byjone

Writeup personal de **Touch**, máquina Windows de dificultad **Easy** de Hack The Box. Incluye el recorrido completo, capturas de apoyo y un registro de las pruebas que funcionaron, las que no dieron resultado y las que quedaron pendientes.

> **Aviso: spoilers.** Este repositorio contiene la solución de la máquina, incluidas las flags y la cadena de explotación completa. Si todavía estás trabajando en Touch, guarda este README para más adelante.

## Máquina

- **Plataforma:** Hack The Box
- **Máquina:** [Touch](https://app.hackthebox.com/machines/Touch?sort_by=created_at&sort_type=desc)
- **Dificultad:** Easy
- **Sistema operativo:** Windows
- **Autora del writeup:** [@byjone](https://github.com/byjone)

## Writeups

- [Leer en español](writeup-touch-es.md)
- [Read in English](writeup-touch-en.md)

## Resumen de la ruta

1. Reconocimiento de puertos y servicios con Nmap.
2. Enumeración de Nexion DeviceHub con Burp Suite.
3. Obtención del número de serie a través de un endpoint accesible sin sesión y acceso al panel.
4. Identificación de endpoints de la API sin autenticación.
5. Acceso por RDP con credenciales encontradas en la aplicación.
6. Escape del kiosco al provocar un error en el escáner.
7. Enumeración local y escalada de privilegios mediante MySQL UDF hasta `NT AUTHORITY\SYSTEM`.

## Qué incluye

- Explicaciones junto a las capturas.
- Comandos y respuestas relevantes para reproducir el recorrido dentro del laboratorio.
- Registro de intentos fallidos, resultados útiles y pruebas pendientes, distinguiendo lo demostrado de lo que no se llegó a confirmar.
- Versiones en español e inglés.

## Nota

Este material está documentado con fines educativos y se refiere a una máquina de laboratorio de Hack The Box. Utiliza estas técnicas únicamente en sistemas para los que tengas autorización.
