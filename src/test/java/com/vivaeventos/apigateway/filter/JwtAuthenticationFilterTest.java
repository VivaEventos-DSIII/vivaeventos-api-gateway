package com.vivaeventos.apigateway.filter;

import com.vivaeventos.apigateway.config.GatewayAuthProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock WebClient webClient;
    @SuppressWarnings("rawtypes") @Mock WebClient.RequestHeadersUriSpec requestHeadersUriSpec;
    @SuppressWarnings("rawtypes") @Mock WebClient.RequestHeadersSpec requestHeadersSpec;
    @Mock WebClient.ResponseSpec responseSpec;
    @Mock GatewayFilterChain chain;

    JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        GatewayAuthProperties properties = new GatewayAuthProperties();
        properties.setValidateUrl("lb://auth-service/api/auth/validate");
        properties.setPublicPaths(List.of("/api/auth/"));

        WebClient.Builder builder = mock(WebClient.Builder.class);
        when(builder.build()).thenReturn(webClient);

        filter = new JwtAuthenticationFilter(builder, properties);
    }

    // --- US-26 Criterio 1: sin JWT → 401, no se llama al auth-service ---

    @Test
    void missingAuthorizationHeader_returns401WithoutCallingAuthService() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(webClient);
        verify(chain, never()).filter(any());
    }

    @Test
    void nonBearerAuthorizationHeader_returns401WithoutCallingAuthService() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1")
            .header(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(webClient);
        verify(chain, never()).filter(any());
    }

    @Test
    void publicPath_register_passesWithoutCallingAuthService() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/register").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        verifyNoInteractions(webClient);
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void publicPath_login_passesWithoutCallingAuthService() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/auth/login").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        verifyNoInteractions(webClient);
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    // --- US-26 Criterio 2: JWT inválido/expirado → 401, no se enruta ---

    @Test
    @SuppressWarnings("unchecked")
    void authServiceReturns401_returns401ToClientWithoutRouting() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1")
            .header(HttpHeaders.AUTHORIZATION, "Bearer invalid.jwt.token")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(
            Mono.error(WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(), "Unauthorized", HttpHeaders.EMPTY, null, null))
        );

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void authServiceReturns401ForExpiredToken_returns401ToClient() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/orders/5")
            .header(HttpHeaders.AUTHORIZATION, "Bearer expired.jwt.token")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(
            Mono.error(WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(), "Unauthorized", HttpHeaders.EMPTY, null, null))
        );

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(any());
    }

    // --- US-26 Criterio 3: JWT válido → inyecta X-User-Email y X-User-Role, enruta ---

    @Test
    @SuppressWarnings("unchecked")
    void validJwt_injectsEmailAndRoleHeadersThenRoutes() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1")
            .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.token")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(
            Mono.just(new JwtAuthenticationFilter.ValidateResponse("user@example.com", "ROLE_USER"))
        );

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(chain.filter(captor.capture())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
        ServerWebExchange routed = captor.getValue();
        assertThat(routed.getRequest().getHeaders().getFirst("X-User-Email"))
            .isEqualTo("user@example.com");
        assertThat(routed.getRequest().getHeaders().getFirst("X-User-Role"))
            .isEqualTo("ROLE_USER");
    }

    @Test
    @SuppressWarnings("unchecked")
    void validJwt_adminRole_injectsAdminRoleHeader() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1")
            .header(HttpHeaders.AUTHORIZATION, "Bearer admin.jwt.token")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(
            Mono.just(new JwtAuthenticationFilter.ValidateResponse("admin@example.com", "ROLE_ADMIN"))
        );

        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        when(chain.filter(captor.capture())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        ServerWebExchange routed = captor.getValue();
        assertThat(routed.getRequest().getHeaders().getFirst("X-User-Role")).isEqualTo("ROLE_ADMIN");
        assertThat(routed.getRequest().getHeaders().getFirst("X-User-Email")).isEqualTo("admin@example.com");
    }

    // --- Fallo de conexión con auth-service → 503 ---

    @Test
    @SuppressWarnings("unchecked")
    void authServiceUnavailable_returns503() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1")
            .header(HttpHeaders.AUTHORIZATION, "Bearer any.jwt.token")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri(anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(
            Mono.error(new java.io.IOException("Connection refused: auth-service"))
        );

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        verify(chain, never()).filter(any());
    }

    // --- Verifica que el filtro llama al path correcto ---

    @Test
    @SuppressWarnings("unchecked")
    void filter_callsCorrectValidateUrl() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/events/1")
            .header(HttpHeaders.AUTHORIZATION, "Bearer valid.jwt.token")
            .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        ArgumentCaptor<String> uriCaptor = ArgumentCaptor.forClass(String.class);
        when(requestHeadersUriSpec.uri(uriCaptor.capture())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString())).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.bodyToMono(any(Class.class))).thenReturn(
            Mono.just(new JwtAuthenticationFilter.ValidateResponse("user@example.com", "ROLE_USER"))
        );
        when(chain.filter(any())).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(exchange, chain))
            .verifyComplete();

        assertThat(uriCaptor.getValue()).isEqualTo("lb://auth-service/api/auth/validate");
    }
}
