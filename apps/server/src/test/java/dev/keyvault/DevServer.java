package dev.keyvault;

import com.zaxxer.hikari.HikariDataSource;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.File;
import java.io.IOException;
import javax.sql.DataSource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Zero-setup local server: boots a real embedded PostgreSQL (data kept in apps/server/.data)
 * and the API on :8080. Run with:  ./mvnw spring-boot:test-run
 */
public class DevServer {
    public static void main(String[] args) {
        SpringApplication.from(KeyVaultApplication::main)
                .with(EmbeddedDatabase.class)
                .withAdditionalProfiles("dev")
                .run(args);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class EmbeddedDatabase {
        @Bean(destroyMethod = "close")
        EmbeddedPostgres embeddedPostgres() throws IOException {
            File dir = new File(".data/postgres");
            dir.mkdirs();
            return EmbeddedPostgres.builder().setDataDirectory(dir).setCleanDataDirectory(false).setPort(54329).start();
        }

        /** Pooled like production (Hikari); an unpooled source would open a backend process per request. */
        @Bean(destroyMethod = "close")
        DataSource dataSource(EmbeddedPostgres pg) {
            HikariDataSource ds = new HikariDataSource();
            ds.setJdbcUrl(pg.getJdbcUrl("postgres", "postgres"));
            ds.setMaximumPoolSize(10);
            ds.setPoolName("keyvault-dev");
            return ds;
        }
    }
}
