# Universal Mirror Manager

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Supports](https://img.shields.io/badge/Supports-Debian%20%26%20Ubuntu-green.svg)

Un script de Bash de nivel empresarial, robusto y flexible para crear y mantener réplicas (mirrors) de repositorios de paquetes locales para **Debian** y **Ubuntu**.

Este script ha sido diseñado para la automatización en entornos de producción, con un manejo de errores detallado, configuración flexible y detección inteligente de repositorios.

---

## Características Principales

-   **Soporte Multi-Distribución:** Funciona a la perfección con Debian y Ubuntu, usando los métodos de resolución de versiones canónicos para cada una.
-   **Detección Dinámica de Repositorios:** Comprueba automáticamente la existencia de repositorios (`-updates`, `-security`, `-backports`, etc.) antes de intentar sincronizarlos, evitando errores con versiones que no los tienen (como Debian `unstable`).
-   **Resolución Inteligente de Alias:** Entiende alias como `stable`, `testing`, `lts`, y los resuelve a sus nombres de código actuales (ej. `stable` -> `bookworm`, `lts` -> `noble`).
-   **Manejo Robusto de Errores:** Utiliza `set -euo pipefail` y un manejador de salida (`trap`) para asegurar que los fallos se capturen, se reporten y se realice una limpieza segura.
-   **Protección de Concurrencia:** Implementa un bloqueo de archivo (`flock`) para prevenir que múltiples instancias del script se ejecuten al mismo tiempo y corrompan el mirror.
-   **Configuración Flexible:** Se puede configurar mediante un archivo de configuración, variables de entorno o flags en la línea de comandos, en ese orden de prioridad.
-   **Detección de Red Lenta:** Realiza una prueba de ancho de banda opcional y ajusta los timeouts de `wget` y `curl` para ser más tolerante en conexiones lentas.
-   **Limpieza Automática:** Busca y elimina archivos parciales o corruptos (`.PART`, `.FAILED`) de sincronizaciones anteriores antes de empezar.
-   **Logging Detallado:** Genera archivos de log con niveles de severidad (INFO, WARN, ERROR) y rotación automática.
-   **Notificaciones:** Puede enviar notificaciones de éxito o fracaso por email (`sendmail`) o a un webhook (Slack, Discord, etc.).

## Requisitos

Asegúrate de tener los siguientes paquetes instalados en tu sistema.

-   **Herramientas Esenciales:**
    -   `debmirror`: La herramienta principal para la sincronización.
    -   `curl`: Para las comprobaciones de red y resolución de versiones.
    -   `util-linux`: Proporciona el comando `flock` para el bloqueo.
    -   `coreutils`, `findutils`, `bc`: Herramientas estándar de sistema.
-   **Keyrings de las Distribuciones:**
    -   `debian-archive-keyring`: Necesario para verificar los repositorios de Debian.
    -   `ubuntu-archive-keyring`: Necesario para verificar los repositorios de Ubuntu.

Puedes instalarlos en un sistema basado en Debian/Ubuntu con:
```bash
sudo apt update
sudo apt install debmirror curl util-linux debian-archive-keyring ubuntu-archive-keyring bc
