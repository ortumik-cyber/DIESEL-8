# /security-review — Autoescuela Diesel

**Fecha:** 2026-05-10  
**Versión analizada:** v7.0  
**Arquitectura actual:** SPA estática en GitHub Pages + Firebase Firestore directo desde cliente

---

## 1. ARQUITECTURA ACTUAL vs ARQUITECTURA DE PRODUCCIÓN

### Actual (GitHub Pages)
```
Navegador → Firebase Firestore (directo, API key pública)
Navegador → WhatsApp Web (URL) / 360dialog API (key en localStorage)
```

### Producción recomendada
```
Navegador → BACKEND (Node.js/Cloud Run)
              ├── Firebase Admin SDK (clave de servicio, env variable)
              ├── WhatsApp 360dialog (API key, env variable)
              ├── Rate limiting (express-rate-limit)
              ├── Validación entrada (zod / joi)
              ├── Auth con JWT firmados (HS256)
              └── Audit logs (Cloud Logging)
```

---

## 2. VULNERABILIDADES IDENTIFICADAS — POR NIVEL DE RIESGO

### 🔴 CRÍTICO

#### 2.1 Contraseña del admin en localStorage
**Dónde:** `localStorage.getItem('diesel_pass_v7')`  
**Riesgo:** Cualquier script en la página puede leer `localStorage`. Si hay XSS, se expone la contraseña. No hay hashing.  
**Solución:** Firebase Authentication con email/password. La contraseña nunca sale del servidor Firebase.

```javascript
// INSEGURO (actual)
localStorage.setItem('diesel_pass_v7', '1234');

// SEGURO
firebase.auth().signInWithEmailAndPassword(email, pass)
  .then(user => user.getIdToken()) // JWT firmado por Firebase
```

#### 2.2 API key de WhatsApp en localStorage
**Dónde:** `localStorage.getItem('diesel_wa_v7')`  
**Riesgo:** Cualquier usuario puede abrir DevTools y copiar la API key de 360dialog. La key permite enviar mensajes de WhatsApp en su nombre y puede generar costes.  
**Solución:** La key debe vivir en el backend como variable de entorno. El cliente solo manda el número y el mensaje; el backend hace la llamada a 360dialog.

```javascript
// INSEGURO (actual) — API key expuesta en cliente
fetch('https://waba.360dialog.io/v1/messages', {
  headers: { 'D360-API-KEY': localStorage.getItem('wa_key') }
})

// SEGURO — el backend actúa como proxy
fetch('/api/whatsapp/send', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer '+idToken },
  body: JSON.stringify({ to: tel, message: msg })
})
// El backend usa process.env.WHATSAPP_API_KEY — nunca visible para el cliente
```

#### 2.3 Reglas Firestore en modo test (allow all)
**Dónde:** Firebase Console → Firestore → Reglas  
**Riesgo:** Cualquier persona en internet puede leer y escribir TODA la base de datos. Nombre de alumnos, firmas, datos personales. GDPR violation.  
**Solución:** Aplicar las reglas del archivo `FIRESTORE_RULES.txt` adjunto. Requieren Firebase Authentication.

---

### 🟠 ALTO

#### 2.4 Sin autenticación real en el servidor
**Riesgo:** El control de acceso (admin vs profesor) es solo CSS/JS en el cliente. Cualquiera puede abrir DevTools y cambiar `rol = 'admin'` en la consola.  
**Solución:** Firebase Auth + custom claims. El rol se verifica en Firestore Rules, no en el cliente.

```javascript
// Asignar rol admin via Firebase Admin SDK (backend)
admin.auth().setCustomUserClaims(uid, { admin: true });

// Verificar en Firestore Rules
allow write: if request.auth.token.admin == true;
```

#### 2.5 Sin rate limiting
**Riesgo:** Un atacante puede hacer miles de requests a Firestore (coste económico, denegación de servicio). Las firmas base64 pueden generar documentos grandes repetidamente.  
**Solución:** Rate limiting en backend. Firebase App Check para bloquear clientes no autorizados.

```javascript
// Backend Node.js con express-rate-limit
const rateLimit = require('express-rate-limit');
app.use('/api/', rateLimit({ windowMs: 60000, max: 60 })); // 60 req/min
```

#### 2.6 Firma digital (base64) almacenada en Firestore
**Riesgo:** Las imágenes PNG en base64 pueden ser 50-200KB por firma. Un alumno con 200 prácticas firmadas = ~40MB solo en su historial. Firestore tiene límite de 1MB por documento.  
**Solución:** Almacenar firmas en Firebase Storage. Guardar solo la URL en Firestore.

```javascript
// SEGURO — firma en Storage
const ref = firebase.storage().ref(`firmas/${pracId}.png`);
await ref.putString(b64, 'data_url');
const url = await ref.getDownloadURL();
await db.collection('practicas_'+fecha).doc(pracId).update({ firmaUrl: url });
```

---

### 🟡 MEDIO

#### 2.7 Sin validación de entrada en cliente
**Riesgo actual:** Un alumno puede tener un nombre de 10.000 caracteres o caracteres maliciosos en notas.  
**Estado v7:** Hay `maxlength` en HTML (6000 chars para notas), pero no validación en JS.  
**Mejora:** Validar antes de enviar a Firebase.

```javascript
// Añadir antes de db.collection().add()
if(nombre.length > 100) { toast('Nombre demasiado largo'); return; }
if(!/^[+0-9\s\-()]{7,20}$/.test(telefono)) { toast('Teléfono inválido'); return; }
```

#### 2.8 Firebase API key expuesta en el código fuente
**Contexto:** Esto es ESPERADO y DISEÑADO por Google. La API key de Firebase para web NO es un secreto — es un identificador público. La seguridad real viene de las Firestore Rules y Firebase Auth.  
**Riesgo real:** Bajo, si las reglas están bien configuradas.  
**Referencia:** https://firebase.google.com/docs/projects/api-keys

#### 2.9 Service Worker cacheando versiones antiguas
**Riesgo:** Un usuario puede seguir usando una versión antigua de la app con bugs de seguridad.  
**Estado v7:** El SW usa `skipWaiting()` — correcto.

---

### 🟢 BAJO / INFORMATIVO

#### 2.10 Sin logs de auditoría
Actualmente no hay registro de quién borró qué práctica o quién modificó datos de alumnos.  
**Solución backend:**
```javascript
// Cada operación crítica logea a Cloud Logging
await admin.firestore().collection('audit_log').add({
  userId: req.user.uid, action: 'DELETE_PRACTICA',
  targetId: pracId, timestamp: admin.firestore.FieldValue.serverTimestamp(),
  ip: req.ip
});
```

#### 2.11 HTTPS en GitHub Pages
GitHub Pages fuerza HTTPS. ✅ Correcto.

#### 2.12 Sin CORS configurado (aplica solo si se añade backend)
Si se añade un backend, configurar CORS para aceptar solo el dominio de GitHub Pages.

---

## 3. PLAN DE MIGRACIÓN A PRODUCCIÓN SEGURA

### Fase 1 — Inmediata (sin backend, mejora Firestore)
1. ✅ Activar **Firebase Authentication** (email/password)
   - Crear cuenta admin en Firebase Console → Authentication
   - Crear cuentas para cada profesor
   - Asignar custom claim `{ admin: true }` al admin
2. ✅ Aplicar **FIRESTORE_RULES.txt** — bloquea acceso sin auth
3. ✅ Activar **Firebase App Check** (verifica que requests vienen del dominio correcto)

### Fase 2 — Backend ligero (Cloud Functions o Vercel)
```
/api/auth/login      → verifica credenciales, devuelve JWT
/api/whatsapp/send   → proxy seguro a 360dialog
/api/audit/log       → registra acciones críticas
```

Variables de entorno necesarias:
```
FIREBASE_SERVICE_ACCOUNT={"type":"service_account",...}
WHATSAPP_API_KEY=xxx
JWT_SECRET=min_32_chars_random_string
ALLOWED_ORIGIN=https://mikel.github.io
```

### Fase 3 — Hardening completo
- Rate limiting por IP y por usuario
- Firma de firmas digitales con timestamp firmado
- Backup automático de Firestore
- Alertas de uso anómalo (Cloud Monitoring)
- Revisión GDPR: datos de alumnos son datos personales sensibles

---

## 4. RESUMEN EJECUTIVO

| Área | Estado actual | Con Firestore Rules + Firebase Auth |
|------|--------------|--------------------------------------|
| Autenticación | ❌ localStorage | ✅ JWT firmado por Firebase |
| Autorización BD | ❌ Sin reglas | ✅ Rules por rol |
| Secretos cliente | ❌ WA key en localStorage | ⚠️ Necesita backend |
| Rate limiting | ❌ Ninguno | ⚠️ Firebase App Check parcial |
| Validación entrada | ⚠️ Solo HTML maxlength | ⚠️ Mejorable en JS |
| HTTPS | ✅ GitHub Pages | ✅ |
| Firmas digitales | ⚠️ En Firestore (tamaño) | 🔧 Migrar a Storage |
| Audit logs | ❌ Ninguno | 🔧 Requiere backend |
| GDPR | ⚠️ Sin encriptación extra | 🔧 Revisar retención datos |

**La mejora más impactante con menos esfuerzo:** aplicar Firebase Authentication + Firestore Rules del archivo adjunto. Elimina los riesgos 2.1, 2.3 y 2.4 sin necesitar backend.
