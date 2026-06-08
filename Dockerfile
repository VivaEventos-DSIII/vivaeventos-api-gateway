FROM maven:3.9.6-eclipse-temurin-21 AS builder
RUN mkdir -p /root/.m2 && echo '<settings><mirrors><mirror><id>aliyun</id><url>https://maven.aliyun.com/repository/public</url><mirrorOf>*</mirrorOf></mirror></mirrors></settings>' > /root/.m2/settings.xml
WORKDIR /app
COPY pom.xml ./
COPY src ./src
RUN mvn package -DskipTests -q || mvn package -DskipTests -q || mvn package -DskipTests -q

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN addgroup -S vivaeventos && adduser -S vivaeventos -G vivaeventos
USER vivaeventos
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
