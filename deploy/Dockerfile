# -----------------------------------------------------------------------------
# ETAPA 1: BUILDER
# Usamos una imagen con Maven para compilar y extraer las capas.
# -----------------------------------------------------------------------------
FROM maven:3.9.6-eclipse-temurin-17-alpine AS builder
WORKDIR /app

# 1. Copiamos SOLO el pom.xml primero.
# Esto permite a Docker cachear las dependencias si el pom no cambia.
COPY pom.xml .

# 2. Descargamos dependencias (modo offline).
# Si no tocas el pom.xml, este paso se salta en futuros builds (Ahorro de tiempo brutal).
RUN mvn dependency:go-offline

# 3. Copiamos el código fuente y compilamos.
COPY src ./src
RUN mvn clean package -DskipTests

# 4. "La Magia Senior": Extraemos las capas del JAR usando layertools.
# Esto divide el JAR en: dependencias, loader, snapshots y tu aplicación.
WORKDIR /app/target
RUN java -Djarmode=layertools -jar *.jar extract

# -----------------------------------------------------------------------------
# ETAPA 2: RUNTIME
# Usamos una imagen JRE (no JDK) muy ligera para producción.
# -----------------------------------------------------------------------------
FROM eclipse-temurin:17-jre-alpine
WORKDIR /application

# 1. SEGURIDAD: Creamos un usuario "no-root".
# Si hackean el contenedor, no tendrán control total.
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# 2. Copiamos las capas extraídas en la etapa anterior.
# El orden importa: lo que menos cambia va primero.
COPY --from=builder /app/target/dependencies/ ./
COPY --from=builder /app/target/spring-boot-loader/ ./
COPY --from=builder /app/target/snapshot-dependencies/ ./
COPY --from=builder /app/target/application/ ./

# 3. ENTRYPOINT optimizado.
# Usamos JarLauncher en lugar de "java -jar" para arrancar desde las capas.
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]