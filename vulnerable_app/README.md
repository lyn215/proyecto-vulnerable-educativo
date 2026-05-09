# 🔓 Sentiment Security Lab — Versión Vulnerable

> ⚠️ **SOLO PARA USO LOCAL EN LABORATORIO EDUCATIVO**
> No desplegar en producción ni en redes públicas.

## Propósito

Esta versión contiene **vulnerabilidades intencionales** para que los alumnos puedan:
1. Identificar cada fallo de seguridad.
2. Entender su impacto.
3. Aplicar la corrección en la versión segura.

## Vulnerabilidades incluidas

| Código | Descripción |
|--------|-------------|
| VULN-01 | Debug mode activo — expone traceback |
| VULN-02 | Secret key débil y hardcodeada |
| VULN-03 | Logging con datos sensibles (contraseñas) |
| VULN-04 | Contraseñas en texto plano |
| VULN-05 | DB sin índices ni restricciones |
| VULN-06 | Sin rate limiting — fuerza bruta posible |
| VULN-07 | Error detallado revela usuarios existentes |
| VULN-08 | Sin validación de longitud de entrada |
| VULN-09 | XSS via `\| safe` sin sanitización |
| VULN-10 | SQL Injection por concatenación de strings |
| VULN-11 | Sin validación de tipo/extensión de archivo |
| VULN-12 | Path traversal en nombre de archivo |
| VULN-13 | Sin límite de tamaño de archivo |
| VULN-14 | Stack trace completo expuesto al usuario |

## Instalación

```bash
cd vulnerable_app
pip install -r requirements.txt
python app.py
```

Accede en: http://localhost:5000

**Credenciales de prueba** (intencionalmente débiles):
- `admin` / `admin123`
- `alumno` / `password`

## Ejercicios sugeridos

1. Ingresa `<script>alert('XSS')</script>` como comentario → observa VULN-09
2. En `/historial?usuario=' OR '1'='1` → observa VULN-10
3. Revisa `app.log` después de hacer login → observa VULN-03
4. Sube un archivo `.exe` → observa VULN-11
