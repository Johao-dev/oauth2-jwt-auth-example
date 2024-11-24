# OAuth2 JWT Auth Example

Este proyecto es una implementación de OAuth2 utilizando Spring Boot, que incluye un servidor de autorización, un servidor de recursos y un cliente. Se utiliza JWT (JSON Web Tokens) para la autenticación y autorización de usuarios.

## 🚀 **Tecnologías Utilizadas:**
- **Java 21**
- **Spring Boot**
- **Spring Security**
- **JWT (JSON Web Tokens)**
- **OAuth2 Authorization Server**
- **OAuth2 Resource Server**

---

## 📂 **Estructura del Proyecto:**

- **oauth-server:** Gestiona la autenticación del usuario y emite tokens JWT.
- **resource-server:** Protege los recursos y valida los tokens JWT.
- **oauth-client:** Consume recursos protegidos mediante tokens JWT.

---

## Configuración del entorno

### Instalación y ejecución

1. Clonar el repositorio:

   ```bash
   git clone https://github.com/Johao-dev/oauth2-jwt-auth-example.git

2. Iniciar el servidor de autorización:

   ```bash
   cd oauth-server
   mvn spring-boot:run

3. Iniciar el servidor de recursos:

   ```bash
   cd resource-server
   mvn spring-boot:run

---

## Configuración del servidor de autorización

### Configuración principal (application.properties)

- **Puerto:** `9000`

- **Usuario predeterminado:**

    - usuario: `zuzz`
    - contraseña: `zuzz1221`

 - **Cliente registrado:**

   | Parámetro             | Valor                                                  |
   | --------------------- | ------------------------------------------------------ |
   | **Client ID**         | `oauth-client`                                         |
   | **Client Secret**     | `12345678910`                                          |
   | **Redirect URIs**     | `http://127.0.0.1:8080/login/oauth2/code/oauth-client` |
   | **Grant Types**       | `authorization_code`, `refresh_token`                  |
   | **Scopes**            | `openid`, `profile`, `read`, `write`                   |

- **Endpoints:**

  - Autorización:
 
    `GET /login`: Para solicitar un token de autorización.

  - Token:
 
    `POST /oauth2/token`: Para intercambiar un código de autorización por un token de acceso.

---

## Configuración del servidor de recursos

### Configuración principal (application.properties)

- **Puerto:** `8081`

- **Validación de tokens:** `issuer-uri=http://127.0.0.1:9000`

- **Endpoints protegidoa**

  | Método   | Endpoint          | Requiere Scope | Descripción                        |
  | -------- | ----------------- | -------------- | ---------------------------------- |
  | **GET**  | `/resources/user` | `read`         | Obtener información del usuario.   |
  | **POST** | `/resources/user` | `write`        | Modificar información del usuario. |

  - **Ejemplo de petición:**
 
    ```bash
    curl -X GET http://127.0.0.1:8081/resources/user \ -H "Authorization: Bearer <token_jwt>"

---

## 🚀Flujo de autenticación

1. **Iniciar sesión en el servidor de autorización:**

   El cliente redirige al usuario a `/login`.

2. **Obtener código de autorización:**

   Después de autenticarse, el usuario es redirigido a la URI de redirección con un
   código de autorización.

3. **Solicitar token de acceso:**

   El cliente intercambia el código de autorización por un token de acceso en
   `oauth2/token`.

4. **Acceder a recursos protegidos:**

   El cliente utiliza el token de acceso para hacer solicitudes al servidor
   de recursos.

   
