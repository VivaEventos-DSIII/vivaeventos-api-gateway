package com.vivaeventos.apigateway.filter;

import com.vivaeventos.apigateway.config.GatewayAuthProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Filtro global del API Gateway que valida el JWT en cada petición.
 *
 * Flujo:
 * 1. Si la ruta es pública (/api/auth/**) → deja pasar sin validar
 * 2. Si no hay JWT o no empieza con "Bearer " → retorna 401
 * 3. Llama a auth-service /auth/validate con el JWT
 * 4. Si auth-service retorna error → retorna 401
 * 5. Si auth-service retorna 200 → extrae email y rol,
 *    los inyecta en headers X-User-Email y X-User-Role,
 *    y enruta la petición al microservicio destino
 *
 * Criterio 1 (US-26): sin JWT → 401 sin enrutar ✅
 * Criterio 2 (US-26): JWT inválido/expirado → 401 ✅
 * Criterio 3 (US-26): JWT válido → enruta e inyecta rol en header ✅
 *
 * @GlobalFilter → se aplica a TODAS las peticiones que entran al gateway
 * @Ordered(-1)  → se ejecuta antes que otros filtros (prioridad alta)
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final WebClient webClient;
    private final GatewayAuthProperties properties;

    public JwtAuthenticationFilter(WebClient.Builder webClientBuilder,
                                   GatewayAuthProperties properties) {
        this.webClient = webClientBuilder.build();
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Criterio 1: rutas públicas pasan sin validación
        if (properties.getPublicPaths().stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        // Criterio 1: sin JWT → 401 inmediato
        String authHeader = exchange.getRequest().getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Criterios 2 y 3: llamar a auth-service para validar el JWT
        return webClient.get()
                .uri(properties.getValidateUrl())
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                // Criterio 2: si auth-service retorna 4xx/5xx → onErrorResume maneja el 401
                .bodyToMono(ValidateResponse.class)
                .flatMap(validateResponse -> {
                    // Criterio 3: JWT válido → inyectar email y rol en headers
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(exchange.getRequest().mutate()
                                    .header("X-User-Email", validateResponse.email())
                                    .header("X-User-Role", validateResponse.role())
                                    .build())
                            .build();
                    return chain.filter(mutatedExchange);
                })
                .onErrorResume(ex -> {
                    // Criterio 2: token inválido/expirado → 401
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }

    /**
     * Record local para deserializar la respuesta de /auth/validate.
     * Contiene email y rol del usuario autenticado.
     * Se define aquí para no crear dependencia entre módulos.
     */
    record ValidateResponse(String email, String role) {}
}
