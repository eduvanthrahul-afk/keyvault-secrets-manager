package dev.keyvault.web;

import dev.keyvault.auth.SessionService;
import dev.keyvault.config.KeyVaultProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * Serves the built React app from classpath:/static. Hashed assets are cached forever;
     * any non-API path that is not a file falls back to index.html for client-side routing.
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/assets/**")
                .addResourceLocations("classpath:/static/assets/")
                .setCacheControl(CacheControl.maxAge(java.time.Duration.ofDays(365)).cachePublic().immutable());
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/")
                .setCacheControl(CacheControl.noCache())
                .resourceChain(true)
                .addResolver(new PathResourceResolver() {
                    @Override
                    protected Resource getResource(String path, Resource location) throws IOException {
                        if (path.startsWith("api/") || path.startsWith("actuator/")) return null;
                        Resource r = location.createRelative(path);
                        if (r.exists() && r.isReadable()) return r;
                        Resource index = new ClassPathResource("/static/index.html");
                        return index.exists() ? index : null;
                    }
                });
    }

    /** Rejects oversized request bodies before they are buffered (largest legit payload: key rotation). */
    @Bean
    FilterRegistrationBean<OncePerRequestFilter> bodyLimit() {
        long max = 8L * 1024 * 1024;
        var bean = new FilterRegistrationBean<OncePerRequestFilter>(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                    throws ServletException, IOException {
                if (req.getContentLengthLong() > max) {
                    res.sendError(413, "Payload too large");
                    return;
                }
                chain.doFilter(req, res);
            }
        });
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

    @RestController
    static class PublicConfigController {
        private final KeyVaultProperties props;

        PublicConfigController(KeyVaultProperties props) {
            this.props = props;
        }

        @GetMapping(value = "/api/config", produces = MediaType.APPLICATION_JSON_VALUE)
        ResponseEntity<Map<String, Object>> config() {
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .body(Map.of("registrationEnabled", props.registrationEnabled(), "version", "2.0.0"));
        }
    }

    @Component
    static class Housekeeping {
        private static final Logger log = LoggerFactory.getLogger(Housekeeping.class);
        private final SessionService sessions;
        private final JdbcClient db;

        Housekeeping(SessionService sessions, JdbcClient db) {
            this.sessions = sessions;
            this.db = db;
        }

        @Scheduled(fixedDelayString = "PT15M", initialDelayString = "PT1M")
        void purge() {
            int s = sessions.purgeExpired();
            int sends = db.sql("DELETE FROM sends WHERE expires_at < now() - interval '1 day'").update();
            if (s + sends > 0) log.info("Housekeeping purged {} sessions and {} share links", s, sends);
        }
    }
}
