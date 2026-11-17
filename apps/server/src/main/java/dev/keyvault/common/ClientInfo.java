package dev.keyvault.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Request metadata for audit and rate limiting. Client IP comes from getRemoteAddr(), which
 * Spring rewrites from X-Forwarded-For only when server.forward-headers-strategy is enabled
 * (i.e. only when deployed behind a trusted proxy). Never parse XFF by hand.
 */
public record ClientInfo(String ip, String userAgent) {

    public static ClientInfo of(HttpServletRequest req) {
        String ua = req.getHeader("User-Agent");
        if (ua != null && ua.length() > 255) ua = ua.substring(0, 255);
        return new ClientInfo(req.getRemoteAddr(), ua);
    }

    public static ClientInfo current() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            return of(attrs.getRequest());
        }
        return new ClientInfo(null, null);
    }
}
