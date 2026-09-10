package com.novibe.common.data_sources;

import com.novibe.common.base_structures.HostsLine;
import com.novibe.common.util.DataParser;
import com.novibe.common.util.Log;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.StructuredTaskScope;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Setter(onMethod_ = @Autowired)
public abstract class ListLoader<T> {

    private static final Path HOSTS_EXCLUDE_FILE = Path.of("hosts_exclude");

    private HttpClient client;

    protected abstract T toObject(HostsLine hostsLine);

    protected abstract String listType();

    protected abstract Predicate<HostsLine> filterRelatedLines();

    @SuppressWarnings("preview")
    public List<T> fetchWebsites(List<String> urls) {
        try (var scope = StructuredTaskScope.open()) {
            List<StructuredTaskScope.Subtask<String>> requests = new ArrayList<>();
            urls.stream()
                    .map(url -> scope.fork(() -> fetchList(url)))
                    .forEach(requests::add);
            scope.join();

            Set<String> excludedSections = loadExcludedSections();
            return requests.stream()
                    .map(StructuredTaskScope.Subtask::get)
                    .flatMap(data -> filterExcludedSections(data, excludedSections).stream())
                    .map(String::strip)
                    .parallel()
                    .filter(line -> !line.isBlank())
                    .filter(line -> !DataParser.isComment(line))
                    .map(String::toLowerCase)
                    .map(DataParser::parseHostsLine)
                    .filter(Objects::nonNull)
                    .filter(filterRelatedLines())
                    .distinct()
                    .map(this::toObject)
                    .collect(Collectors.toCollection(ArrayList::new));
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private Set<String> loadExcludedSections() {
        if (!Files.exists(HOSTS_EXCLUDE_FILE)) {
            return Set.of();
        }
        try {
            Set<String> sections = Files.readAllLines(HOSTS_EXCLUDE_FILE, StandardCharsets.UTF_8).stream()
                    .map(ListLoader::normalizeSectionName)
                    .filter(section -> !section.isBlank())
                    .collect(Collectors.toCollection(HashSet::new));
            Log.io("Loaded %s excluded hosts sections".formatted(sections.size()));
            return sections;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + HOSTS_EXCLUDE_FILE, e);
        }
    }

    private List<String> filterExcludedSections(String data, Set<String> excludedSections) {
        if (excludedSections.isEmpty()) {
            return DataParser.splitByEol(data).toList();
        }

        List<String> filtered = new ArrayList<>();
        boolean skipSection = false;
        for (String line : DataParser.splitByEol(data).toList()) {
            String stripped = line.strip();
            if (DataParser.isComment(stripped)) {
                skipSection = excludedSections.contains(normalizeSectionName(stripped));
                continue;
            }
            if (!skipSection) {
                filtered.add(line);
            }
        }
        return filtered;
    }

    private static String normalizeSectionName(String value) {
        String normalized = value.strip();
        while (normalized.startsWith("#")) {
            normalized = normalized.substring(1).strip();
        }
        return normalized.toLowerCase();
    }

    private String fetchList(String url) throws IOException, InterruptedException {
        Log.io("Loading %s list from url: %s".formatted(listType(), url));
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)).body();
    }

}
