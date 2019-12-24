# Start with a base image containing Java runtime
FROM openjdk:8-jdk-alpine

# Spring Boot application creates working directories for Tomcat 
VOLUME /tmp

# Add Maintainer Info
LABEL maintainer="vgeorgiou@trading-point.com"

# The application's jar file
ARG JAR_FILE=build/libs/*.jar

# Service logging directory 
ENV LOGGING_PATH /var/log/ms

# Add the application's jar to the container
ADD ${JAR_FILE} /opt/tpam/ms/service.jar

# Run the jar file
ENTRYPOINT ["java", "-Xmx512m", "-Djava.security.egd=file:/dev/./urandom", "-jar","/opt/tpam/ms/service.jar"]