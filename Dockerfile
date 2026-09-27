# ---------------------------------------------------------------- build
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B dependency:go-offline
COPY src ./src
RUN mvn -B clean package -DskipTests

# --------------------------------------------------------------- trivy
FROM aquasec/trivy:0.58.1 AS trivy

# ----------------------------------------------------------------- jre
FROM eclipse-temurin:21-jre-alpine AS jre

# ------------------------------------------------------------- runtime
# La base es la imagen de Semgrep, no una de Java.
#
# El orden importa: Semgrep viene con su interprete de Python y su arbol de
# dependencias resueltos entre si, y cualquier intento de trasplantar sus
# piezas a otra imagen es pelear contra el empaquetado de otro. Java, en
# cambio, se añade copiando un directorio.
FROM semgrep/semgrep:1.101.0

ARG SEMGREP_RULES_REF=develop

USER root

RUN apk add --no-cache git ca-certificates \
    && true \
    && true

# JRE portable: basta el directorio y las variables de entorno.
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

# AVISO DE LICENCIA: las reglas mantenidas de semgrep-rules estan bajo
# Semgrep Rules License v1.0, que restringe su uso en servicios comerciales
# competidores. Valido para portfolio; revisar antes de comercializar.
RUN git clone --depth 1 --branch "${SEMGREP_RULES_REF}" \
        https://github.com/semgrep/semgrep-rules /opt/semgrep-rules \
    && rm -rf /opt/semgrep-rules/.git \
    && rm -rf /opt/semgrep-rules/.github /opt/semgrep-rules/.pre-commit-config.yaml \
    && rm -rf /opt/semgrep-rules/stats /opt/semgrep-rules/template.yaml \
    && find /opt/semgrep-rules -maxdepth 1 -name ".*" -exec rm -rf {} + \
    && find /opt/semgrep-rules -name "*.test.yaml" -delete \
    && semgrep scan --config /opt/semgrep-rules --json --quiet /tmp > /tmp/chk.json 2>&1 \
       || (echo "Las reglas no cargan:" && head -c 800 /tmp/chk.json && exit 1) \
    && rm -f /tmp/chk.json

# Si una herramienta no funciona, mejor saberlo al construir que en el primer
# scan de un usuario.
RUN java -version && trivy --version && semgrep --version

RUN (addgroup -S devguard 2>/dev/null || true) \
    && (adduser -S -G devguard devguard 2>/dev/null || true) \
    && mkdir -p /var/devguard/workspace /var/devguard/trivy-cache \
    && chown -R devguard:devguard /var/devguard

WORKDIR /app
COPY --from=build /build/target/*.jar app.jar
USER devguard
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]