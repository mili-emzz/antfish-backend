# **Documento de Propuesta y Levantamiento de Requerimientos**

## **1\. Nombre del Proyecto**

**AntFish**

## **2\. Planteamiento del Problema**

### **Contexto Actual**

Actualmente, el phishing y el smishing representan problemáticas críticas dentro de la seguridad informática, debido a que son técnicas utilizadas por ciberdelincuentes para engañar a las personas mediante enlaces y mensajes fraudulentos. El phishing se presenta comúnmente a través de correos electrónicos que contienen enlaces a páginas falsas, mientras que el smishing utiliza mensajes SMS para suplantar la identidad de instituciones bancarias, empresas de paquetería, servicios digitales y otras organizaciones.

Estas técnicas buscan que las víctimas accedan a sitios web maliciosos, proporcionen información personal, compartan credenciales de acceso o realicen acciones que puedan comprometer su seguridad. Aunque existen herramientas y servicios que permiten verificar la reputación de enlaces y detectar sitios potencialmente peligrosos, los usuarios no siempre cuentan con una forma sencilla e inmediata de analizar los enlaces o mensajes sospechosos que reciben. Esto representa una oportunidad para desarrollar una aplicación móvil que permita realizar estos análisis de manera accesible, combinando un motor propio de detección sintáctica/heurística con servicios externos de inteligencia de amenazas.

### **Justificación**

Resolver esta problemática es relevante porque el phishing y el smishing aprovechan principalmente la confianza, la urgencia y la falta de herramientas de verificación rápida de los usuarios para facilitar el robo de información y fraudes financieros. Una persona puede recibir un mensaje que aparentemente proviene de una organización legítima y acceder a un enlace fraudulento sin identificar los riesgos que representa.

### **Impacto Esperado**

* **Reducción del Riesgo del Usuario Final:** Proporcionar una herramienta accesible e intuitiva que evalúe enlaces y mensajes en segundos antes de que el usuario interactúe con ellos.  
* **Mitigación de Fraudes Financieros y Robo de Identidad:** Disminuir la tasa de éxito de campañas de phishing y smishing dirigidas a usuarios finales.  
* **Educación y Concientización:** Informar al usuario sobre los motivos concretos por los cuales un mensaje o URL es peligroso (ej. lenguaje de urgencia, reputación negativa del dominio, solicitudes de información confidencial).

## **3\. Objetivos**

### **Objetivo General**

Desarrollar una aplicación móvil multiplataforma respaldada por una API REST en Python (FastAPI) que permita analizar el contenido de mensajes SMS y URLs sospechosas mediante un motor heurístico propio y servicios externos de inteligencia de amenazas (Google Web Risk, VirusTotal y PhishTank), determinando y visualizando el nivel de riesgo en tiempo real.

### **Objetivos Específicos**

1. **Diseñar e implementar la arquitectura del backend y el motor de análisis:** Crear un backend asíncrono en Python (FastAPI) que procese mensajes SMS y URLs mediante reglas heurísticas (patrones de urgencia, extracción sintáctica de enlaces) y ejecute consultas en paralelo a APIs externas.  
2. **Implementar el mecanismo de rendimiento y caché:** Configurar un sistema de almacenamiento de caché para guardar reputaciones de dominios previamente analizados, reduciendo el tiempo de respuesta y optimizando la cuota de peticiones a servicios externos.  
3. **Desarrollar el módulo de métricas y estadísticas de escaneo:** Implementar un sistema de seguimiento que contabilice el volumen de análisis realizados por el usuario, distinguiendo entre URLs y SMS, e identificando el nivel de amenazas bloqueadas.  
4. **Desarrollar la aplicación móvil multiplataforma:** Construir una interfaz móvil que permita la entrada manual o directa mediante la función nativa de "Compartir" de SMS y enlaces, presentando el diagnóstico con un semáforo de riesgo, hallazgos clave y recomendaciones.  
5. **Ejecutar pruebas de integración, seguridad y rendimiento:** Realizar pruebas de esfuerzo para validar tiempos de respuesta bajos y auditar la seguridad de la API mediante autenticación JWT y comunicaciones cifradas sobre HTTPS.

## **4\. Stack Tecnológico Seleccionado**

* **Frontend Móvil:** Flutter (Dart) — Permite una aplicación nativa para Android y iOS desde un solo código base, garantizando rapidez y fluidez en la interfaz.  
* **Backend & API REST:** Python con FastAPI — Procesa las solicitudes de manera asíncrona (asyncio), permitiendo consultar múltiples APIs de inteligencia en paralelo sin congelar el servidor.  
* **Base de Datos & Caché:** MongoDB (NoSQL) para almacenamiento no estructurado de respuestas complejas JSON y Redis para caché de dominios en memoria.  
* **Infraestructura & Seguridad:** Docker para contenedorización, autenticación mediante JWT (JSON Web Tokens) y cifrado obligatorio HTTPS/TLS en todas las comunicaciones.

## **5\. Propuesta de Heurísticas y Sistema de Puntuación**

### **Arquitectura de Evaluación (Score de 0 a 100\)**

El nivel de riesgo se calcula combinando tres capas de análisis en el motor en Python:

$PuntuaciónTotal=\min\limits_{}(100,Punto{s}_{APIs}+Punto{s}_{URL}+Punto{s}_{Texto})$

#### **Capa 1: Inteligencia Externa / Listas Negras (Máx. 60 pts)**

* **Google Web Risk (Positivo):** \+50 pts.  
* **PhishTank (Positivo):** \+50 pts.  
* **VirusTotal ($\geq 3$ detecciones):** \+40 pts.  
* **VirusTotal (1 a 2 detecciones):** \+20 pts.  
* *Regla de Cortocircuito:* Si Google Web Risk o PhishTank confirman amenaza, la puntuación escala automáticamente a un rango de **95-100 pts (Crítico)**.

#### **Capa 2: Heurística Sintáctica de URL (Máx. 30 pts)**

* **Uso de IP directa en la URL:** \+20 pts.  
* **Subdominio engañoso o impersonación de marca:** \+20 pts.  
* **Dominio con TLD de alto riesgo (.xyz, .top, .tk):** \+15 pts.  
* **Uso de acortadores de enlaces (bit.ly, tinyurl):** \+10 pts.  
* **Exceso de guiones o palabras claves encadenadas:** \+10 pts.

#### **Capa 3: Heurística de Texto y SMS (Máx. 20 pts)**

* **Lenguaje de urgencia o amenaza ("bloqueada", "inmediato", "suspensión"):** \+10 pts.  
* **Solicitud de datos personales o acciones financieras ("verifica tu PIN", "cancela cargo"):** \+10 pts.  
* **Ofuscación de caracteres o leetspeak ("b4nco", "p4yp4l"):** \+5 pts.

### **Escala de Riesgo y Semáforo Visual**

* 🟢 **0 a 19 pts — RIESGO BAJO:** Sin patrones sospechosos ni reportes en listas negras.  
* 🟡 **20 a 49 pts — RIESGO MEDIO:** Presencia de patrones leves (acortadores, lenguaje de urgencia), pero sin reportes de reputación negativa.  
* 🟠 **50 a 79 pts — RIESGO ALTO:** Coincidencia de múltiples reglas de suplantación sintáctica o reporte menor en motores antivirus.  
* 🔴 **80 a 100 pts — RIESGO CRÍTICO:** Confirmación en listas negras o imitación directa de marca legítima.

## **6\. Flujos del Sistema y Procesamiento de Información**

### **Flujo General de la Aplicación**

Plaintext  
\[ USUARIO \]  
     │  
     ├───► \[ Ingrese URL \] ─────────┐  
     │                              │  
     └───► \[ Ingrese Texto / SMS \] ─┴──► \[ API REST (FastAPI) \]  
                                                │  
                                                ▼  
                                      \[ Motor de Análisis \]  
                                                │  
                                ┌───────────────┼───────────────┐  
                                ▼               ▼               ▼  
                            \[ Dominio \]    \[ Contenido \]   \[ Reputación \]  
                                └───────────────┬───────────────┘  
                                                │  
                                                ▼  
                                      \[ Nivel de Riesgo \]  
                                                │  
                                                ▼  
                                   \[ Semáforo Visual (🟢🟡🟠🔴) \]  
\`\`\`\[cite: 1\]

\---

\#\#\# Flujo Detallado de Análisis de SMS / Phishing

\`\`\`text  
\[ SMS Recibido / URL de Correo \]  
               │  
               ▼  
       \[ App Móvil Android / iOS \]  
               │  
               ▼  
       \[ API REST Propia (FastAPI) \]  
               │  
               ▼  
  ┌───────────────────────────────────────────────┐  
  │ Motor de Análisis (Python)                    │  
  │  • Análisis del texto                         │  
  │  • Extracción de URLs                         │  
  │  • Análisis sintáctico y reglas de smishing   │  
  │  • Reputación de URL                          │  
  └──────────────────────┬────────────────────────┘  
                         │  
                         ▼  
  ┌───────────────────────────────────────────────┐  
  │ Consultas a APIs Externas                     │  
  │  ├─ Google Web Risk                           │  
  │  ├─ VirusTotal                                │  
  │  └─ PhishTank                                 │  
  └──────────────────────┬────────────────────────┘  
                         │  
                         ▼  
              \[ Motor de Puntuación \]  
                         │  
                         ▼  
        \[ Retorno de Diagnóstico a la App \]  
\`\`\`\[cite: 2\]

\---

\#\#\# Ejemplo de Estructura del Resultado Retornado al Usuario

\`\`\`text  
RIESGO: ALTO  
Puntuación: 87/100

🔗 URL sospechosa  
   El dominio tiene reputación negativa.

⚠️ Lenguaje de urgencia  
   El mensaje intenta provocar una acción inmediata.

⚠️ Solicitud de información  
   Solicita datos personales mediante un enlace.

🛡️ Recomendación  
   No accedas al enlace, no compartas datos personales ni credenciales de acceso.  
\`\`\`\[cite: 2\]

\---

\#\#\# Diferenciación por Tipo de Entrada  
\* \*\*Correos electrónicos:\*\* El análisis se enfoca en la extracción sintáctica y verificación de reputación de la \*\*URL contenida\*\* en el mensaje\[cite: 3, 4, 5\].  
\* \*\*Mensajes SMS:\*\* Se analiza el \*\*contenido del texto completo\*\* para evaluar patrones de urgencia, ofuscación y solicitudes de información sensible, combinándolo con la verificación de la URL extraída\[cite: 2, 3, 5\].

### **1\. Requerimientos Funcionales (RF)**

* **RF-01: Recepción de Entradas (Nativa y Manual)**  
  * **RF-01.1:** La aplicación debe permitir pegar manualmente texto SMS o URLs en la interfaz.  
     MD  
  * **RF-01.2:** La aplicación debe integrarse con el menú nativo "Compartir" de Android e iOS para recibir enlaces o textos directamente desde otras apps.  
     MD  
* **RF-02: Motor de Análisis Combinado**  
  * **RF-02.1:** El backend debe extraer sintácticamente todas las URLs contenidas dentro de un mensaje de texto.  
  * **RF-02.2:** El backend debe ejecutar en paralelo las consultas a Google Web Risk, VirusTotal y PhishTank mediante el cliente asíncrono de FastAPI (`asyncio`).  
     MD  
  * **RF-02.3:** El backend debe evaluar las reglas heurísticas sintácticas de la URL (IP directa, TLDs de alto riesgo, subdominios engañosos, acortadores).  
     MD  
  * **RF-02.4:** El backend debe analizar el texto del mensaje buscando lenguaje de urgencia, patrones de suplantación de identidad (leetspeak) y solicitudes de información sensible.  
     MD  
* **RF-03: Asignación de Riesgo y Diagnóstico**  
  * **RF-03.1:** El sistema debe calcular la puntuación total e invocar la regla de cortocircuito (escalar a 95–100 pts) si el dominio está listado en Google Web Risk o PhishTank.  
  * **RF-03.2:** La app debe renderizar el resultado con la codificación de colores del semáforo visual (Verde, Amarillo, Naranja, Rojo) según la puntuación obtenida.  
  * **RF-03.3:** El diagnóstico debe incluir la lista desglosada de hallazgos detectados y recomendaciones de acción concretas.  
* **RF-04: Caché y Rendimiento de Consultas**  
  * **RF-04.1:** El backend debe consultar Redis antes de consumir las APIs externas para verificar si el dominio fue analizado recientemente dentro del TTL definido.  
     MD  
  * **RF-04.2:** En caso de coincidencia en caché (*cache hit*), se deben devolver los resultados de la reputación sin consumir cuota de las APIs.  
     MD  
* **RF-05: Métricas y Panel del Usuario**  
  * **RF-05.1:** El sistema debe almacenar el historial de análisis realizados por cada usuario autenticado.  
     MD  
  * **RF-05.2:** La interfaz debe mostrar un panel con estadísticas de escaneos totales, desglose entre SMS y URLs, y cantidad de amenazas bloqueadas.  
     MD

### **2\. Requerimientos No Funcionales (RNF)**

* **RNF-01: Tiempo de Respuesta (Latencia):** El tiempo total desde que el usuario envía la solicitud hasta que recibe la respuesta visual en la app no debe superar los **2.5 segundos** en el 95% de los casos (aprovechando ejecuciones asíncronas y caché).  
   MD  
* **RNF-02: Disponibilidad y Tolerancia a Fallos (Degradación Grácil):** Si una de las APIs externas (ej. VirusTotal) no responde o alcanza su límite de peticiones (*rate-limit*), el motor debe continuar el cálculo con las APIs disponibles y las heurísticas internas sin interrumpir el servicio al usuario.  
* **RNF-03: Seguridad y Privacidad:**  
  * Todas las comunicaciones deben estar cifradas obligatoriamente mediante HTTPS/TLS.  
     MD  
  * La autenticación y autorización entre la app móvil y el API REST debe realizarse vía JWT (*JSON Web Tokens*).  
     MD  
  * Los textos de los mensajes SMS analizados no deben almacenarse en texto plano permanentemente en MongoDB si no es estrictamente necesario para el historial del usuario.  
* **RNF-04: Multiplataforma:** La app móvil debe construirse sobre un único código base en Flutter capaz de compilar e interactuar nativamente en Android y iOS.

