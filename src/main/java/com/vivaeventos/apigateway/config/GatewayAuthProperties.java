package com.vivaeventos.apigateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "gateway.auth")
public class GatewayAuthProperties {

    private String validateUrl;
    private List<String> publicPaths = List.of();

    public String getValidateUrl() { return validateUrl; }
    public void setValidateUrl(String validateUrl) { this.validateUrl = validateUrl; }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) { this.publicPaths = publicPaths; }
}
