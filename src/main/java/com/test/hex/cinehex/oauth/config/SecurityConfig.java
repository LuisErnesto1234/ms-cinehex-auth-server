package com.test.hex.cinehex.oauth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Configuración de seguridad para el servidor de autorización OAuth2.
 * <p>
 * Esta clase configura todos los aspectos de seguridad necesarios para el funcionamiento
 * del servidor de autorización OAuth2, incluyendo:
 * - Cadenas de filtros de seguridad diferenciadas para OAuth2 y formulario de login
 * - Repositorio de clientes registrados con diferentes tipos de grant
 * - Configuración de llaves criptográficas para firmar tokens JWT
 * - Codificador de contraseñas BCrypt para autenticación segura
 *
 * @author Sistema CineHex
 * @version 1.0
 * @since 2026-01-21
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Secreto del cliente OAuth2 utilizado para autenticación de clientes registrados.
     * Se puede sobrescribir mediante la propiedad oauth2.client.secret.
     */
    @Value("${oauth2.client.secret:cinehex-secret-2026}")
    private String clientSecret;

    /**
     * Contraseña del KeyStore PKCS#12 que contiene las llaves criptográficas.
     * Se puede sobrescribir mediante la propiedad keystore.password.
     */
    @Value("${keystore.password:Prueba123!}")
    private String keyStorePassword;

    /**
     * Configura la cadena de filtros de seguridad específica para el servidor de autorización OAuth2.
     * <p>
     * Este filtro se aplica únicamente a las rutas relacionadas con OAuth2 (/oauth2/**) y
     * OpenID Connect (/.well-known/**). Requiere autenticación para todas las peticiones
     * y redirige a la página de login cuando el usuario no está autenticado.
     *
     * @param http El objeto HttpSecurity para configurar la seguridad HTTP
     * @return La cadena de filtros de seguridad configurada para el servidor de autorización
     * @throws Exception Si ocurre un error durante la configuración de seguridad
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher("/oauth2/**", "/.well-known/**")
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/.well-known/**").permitAll()
                                .anyRequest().authenticated())
                .with(authorizationServerConfigurer, Customizer.withDefaults());

        // 2. Habilita OpenID Connect (OIDC)
        // ¡ESTA ES LA CLAVE QUE FALTABA!
        // Esto activa los endpoints /.well-known/openid-configuration automáticamente
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // 3. Define qué hacer si el usuario no está autenticado (Redirigir a Login)
        http.exceptionHandling(e -> e.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")));

        // 4. Configurar el decodificador de JWT para el propio Auth Server (necesario para validaciones internas)
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

    /**
     * Configura la cadena de filtros de seguridad por defecto para la aplicación.
     * <br>
     * Este filtro maneja todas las rutas que no son interceptadas por el filtro del servidor
     * de autorización. Deshabilita CSRF para simplificar el desarrollo, requiere autenticación
     * para todas las peticiones y habilita el formulario de login estándar de Spring Security.
     *
     * @param http El objeto HttpSecurity para configurar la seguridad HTTP
     * @return La cadena de filtros de seguridad por defecto configurada
     * @throws Exception Si ocurre un error durante la configuración de seguridad
     */
    // 2. Filtro de seguridad estándar (Para el formulario de login)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                        .permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults()); // Habilita form login por defecto
        return http.build();
    }

    /**
     * Configura el codificador de contraseñas para la aplicación.
     * <br>
     * Utiliza BCrypt como algoritmo de hash para codificar las contraseñas de manera segura.
     * BCrypt es un algoritmo de hash adaptativo que incluye sal automática y es resistente
     * a ataques de fuerza bruta debido a su capacidad de ajustar el tiempo de cómputo.
     *
     * @return Una instancia de BCryptPasswordEncoder configurada
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configura el repositorio de clientes registrados para el servidor de autorización OAuth2.
     * <p>
     * Define los clientes que están autorizados para solicitar tokens de acceso. Incluye:
     * - Un cliente frontend para aplicaciones web (Angular, React) y herramientas de prueba (Postman)
     * que utiliza Authorization Code Grant Type para flujos con usuarios humanos
     * - Un cliente para microservicios que utiliza Client Credentials Grant Type para comunicación
     * entre servicios backend sin intervención de usuarios
     *
     * @return Repositorio de clientes registrados en memoria con los clientes configurados
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        // CLIENTE 1: Tu Frontend (Postman, Angular, React)
        // Este actúa en nombre de un usuario humano.
        RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("cinehex-front")
                .clientSecret(passwordEncoder().encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback") // Postman
                .redirectUri("http://127.0.0.1:8080/authorized")  // Frontend local
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("cinehex.read") // Permisos de lectura generales
                .build();

        // CLIENTE 2: Microservicio de Reservas (Backend puro)
        // Este servicio necesita consultar datos sin intervención humana.
        // Usa CLIENT_CREDENTIALS (es como su propia "cédula" de identidad).
        RegisteredClient reservasMsClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("ms-cinehex-business")
                .clientSecret(passwordEncoder().encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // <--- CLAVE PARA MICROSERVICIOS
                .scope("movies.admin") // Un scope especial solo para sistemas internos
                .build();

        // Puedes agregar tantos como necesites (ms-administracion, ms-notificaciones, etc.)

        return new InMemoryRegisteredClientRepository(frontendClient, reservasMsClient);
    }

    /**
     * Configura la fuente de llaves web JSON (JWK) para firmar y verificar tokens JWT.
     * <p>
     * Carga un KeyStore PKCS#12 desde el classpath que contiene las llaves RSA necesarias
     * para firmar los tokens de acceso JWT. Extrae tanto la llave privada (para firmar)
     * como la llave pública (para verificación) y las configura en un JWKSet.
     *
     * @return Fuente inmutable de JWK configurada con las llaves RSA del KeyStore
     * @throws IllegalStateException Si el KeyStore no se puede cargar o las llaves no se encuentran
     */
    // 5. Llaves de Firma (RSA)
    // Genera llaves en memoria al iniciar. En PROD usa un KeyStore real.
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            // 1. Cargar el archivo .p12 desde resources
            KeyStore keyStore = KeyStore.getInstance("PKCS12");

            getPublicKeyStore(keyStore);

            // 2. Obtener la llave privada y el certificado
            RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey("cinehex-key", keyStorePassword.toCharArray());

            Certificate certificate = keyStore.getCertificate("cinehex-key");
            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();

            // 3. Crear el objeto RSAKey de Nimbus
            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString()) // O usa un ID fijo si prefieres
                    .build();

            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);

        } catch (Exception ex) {
            throw new IllegalStateException("Error cargando el KeyStore", ex);
        }
    }

    /**
     * Carga el KeyStore PKCS#12 desde el classpath de la aplicación.
     * <p>
     * Método auxiliar que se encarga de localizar y cargar el archivo de KeyStore
     * ubicado en el classpath. El KeyStore contiene las llaves criptográficas necesarias
     * para el funcionamiento del servidor de autorización OAuth2.
     *
     * @param keyStore El KeyStore que será inicializado con los datos del archivo .p12
     * @throws IOException Si el archivo KeyStore no se encuentra, no se puede leer,
     *                     o si ocurre un error durante la carga del certificado
     */
    private void getPublicKeyStore(KeyStore keyStore) throws IOException {
        try (var inputStream = getClass().getClassLoader().getResourceAsStream("cinehex-keystore.p12")) {

            if (inputStream == null) throw new IllegalStateException("No se encuentra el archivo .p12");
            keyStore.load(inputStream, keyStorePassword.toCharArray());

        } catch (RuntimeException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new IOException("Error loading keystore", e);
        }
    }
}