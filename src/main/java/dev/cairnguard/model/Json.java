package dev.cairnguard.model;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

public final class Json {
    private Json() {}
    public static final ObjectMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(48)
                    .maxStringLength(1_048_576).maxNumberLength(128).build()).build())
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();
    public static String write(Object value) {
        // Preserve the frozen raw-v1 shape for legacy Java fixtures; explicit saves use PolicyCodec.
        if (value instanceof GuardConfig config)
            return config.schemaVersion() == 1 ? PolicyCodec.encodeLegacy(config) : PolicyCodec.encode(config);
        try { return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value); }
        catch (Exception e) { throw new IllegalArgumentException("JSON serialization failed"); }
    }
    public static <T> T read(String input, Class<T> type) {
        if (type == GuardConfig.class) return type.cast(PolicyCodec.decode(input).config());
        if (input == null || input.length() > 2_097_152) throw new IllegalArgumentException("JSON input exceeds limit");
        try { return MAPPER.readValue(input, type); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid bounded JSON input"); }
    }
}
