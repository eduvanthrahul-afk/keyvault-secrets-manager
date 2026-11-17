package dev.keyvault.auth;

import dev.keyvault.common.Codec;
import dev.keyvault.common.ServerCrypto;
import dev.keyvault.user.UserRecord;
import dev.keyvault.user.UserRepository;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits, ±1 step) with replay protection and one-time recovery codes. */
@Service
public class TotpService {
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int PERIOD = 30;
    private static final String AAD = "totp-seed";

    private final ServerCrypto crypto;
    private final UserRepository users;

    public TotpService(ServerCrypto crypto, UserRepository users) {
        this.crypto = crypto;
        this.users = users;
    }

    public record Setup(String secret, String otpauthUri) {}

    public Setup beginSetup(UserRecord user) {
        byte[] seed = Codec.randomBytes(20);
        users.setPendingTotp(user.id(), crypto.encrypt(seed, AAD + ":" + user.id()));
        String secret = base32(seed);
        String label = URLEncoder.encode("KeyVault:" + user.email(), StandardCharsets.UTF_8).replace("+", "%20");
        return new Setup(secret, "otpauth://totp/" + label + "?secret=" + secret + "&issuer=KeyVault&algorithm=SHA1&digits=6&period=30");
    }

    /** Returns true and burns the time step if the code is valid and not previously used. */
    public boolean verifyAndConsume(UserRecord user, String code) {
        if (user.totpSecretEnc() == null || code == null || !code.matches("^\\d{6}$")) return false;
        byte[] seed = crypto.decrypt(user.totpSecretEnc(), AAD + ":" + user.id());
        OptionalLong step = matchingStep(seed, code, System.currentTimeMillis() / 1000);
        return step.isPresent() && users.advanceTotpStep(user.id(), step.getAsLong());
    }

    public boolean consumeRecoveryCode(UserRecord user, String code) {
        if (code == null) return false;
        String normalized = code.trim().toLowerCase().replace("-", "").replace(" ", "");
        return normalized.matches("^[a-z2-7]{10}$") && users.consumeRecoveryCode(user.id(), Codec.sha256Hex(normalized));
    }

    public List<String> issueRecoveryCodes(UserRecord user) {
        List<String> codes = new ArrayList<>();
        List<String> hashes = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            String raw = base32(Codec.randomBytes(7)).substring(0, 10).toLowerCase();
            codes.add(raw.substring(0, 5) + "-" + raw.substring(5));
            hashes.add(Codec.sha256Hex(raw));
        }
        users.replaceRecoveryCodes(user.id(), hashes);
        return codes;
    }

    static OptionalLong matchingStep(byte[] seed, String code, long epochSeconds) {
        long current = epochSeconds / PERIOD;
        for (long s = current - 1; s <= current + 1; s++) {
            if (Codec.constantTimeEquals(generate(seed, s), code)) return OptionalLong.of(s);
        }
        return OptionalLong.empty();
    }

    public static String generate(byte[] seed, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(seed, "HmacSHA1"));
            byte[] h = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
            int o = h[h.length - 1] & 0x0f;
            int bin = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
            return String.format("%06d", bin % 1_000_000);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String base32(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(B32.charAt((buffer << (5 - bits)) & 31));
        return sb.toString();
    }

    public static byte[] fromBase32(String s) {
        ByteBuffer out = ByteBuffer.allocate(s.length() * 5 / 8);
        int buffer = 0, bits = 0;
        for (char c : s.toCharArray()) {
            buffer = (buffer << 5) | B32.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                out.put((byte) (buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return out.array();
    }
}
