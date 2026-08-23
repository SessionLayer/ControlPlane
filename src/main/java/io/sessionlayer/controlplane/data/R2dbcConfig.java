package io.sessionlayer.controlplane.data;

import io.r2dbc.postgresql.codec.Json;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;
import org.springframework.data.r2dbc.dialect.PostgresDialect;
import org.springframework.data.relational.core.mapping.NamingStrategy;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
@EnableR2dbcAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
public class R2dbcConfig {

	@Bean
	public DateTimeProvider auditingDateTimeProvider() {
		return () -> Optional.of(Instant.now());
	}

	@Bean
	public NamingStrategy namingStrategy() {
		return new SnakeCaseNamingStrategy();
	}

	@Bean
	public R2dbcCustomConversions r2dbcCustomConversions(ObjectMapper objectMapper) {
		return R2dbcCustomConversions.of(PostgresDialect.INSTANCE,
				List.of(new JsonNodeWritingConverter(objectMapper), new JsonNodeReadingConverter(objectMapper)));
	}

	@WritingConverter
	static final class JsonNodeWritingConverter implements Converter<JsonNode, Json> {

		private final ObjectMapper objectMapper;

		JsonNodeWritingConverter(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
		}

		@Override
		public Json convert(JsonNode source) {
			try {
				return Json.of(objectMapper.writeValueAsBytes(source));
			} catch (JacksonException e) {
				throw new IllegalArgumentException("Failed to serialize JsonNode to jsonb", e);
			}
		}
	}

	@ReadingConverter
	static final class JsonNodeReadingConverter implements Converter<Json, JsonNode> {

		private final ObjectMapper objectMapper;

		JsonNodeReadingConverter(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
		}

		@Override
		public JsonNode convert(Json source) {
			try {
				return objectMapper.readTree(source.asArray());
			} catch (JacksonException e) {
				throw new IllegalStateException("Failed to parse jsonb into JsonNode", e);
			}
		}
	}
}
