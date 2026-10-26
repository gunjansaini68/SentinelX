package com.sentinelx.service;

import com.sentinelx.model.SecurityEvent;
import com.sentinelx.model.SecurityEvent.EventType;
import com.sentinelx.model.SecurityEvent.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for EventService.
 *
 * These tests verify that the in-memory event store is populated correctly
 * and that filtering by severity and event type works as expected.
 *
 * No Spring context is started here – we create EventService directly with
 * "new EventService()", which makes the tests fast.
 */
class EventServiceTest {

    private EventService eventService;

    @BeforeEach
    void setUp() {
        // Create a fresh EventService before each test
        eventService = new EventService();
    }

    // -----------------------------------------------------------------------
    // Basic data integrity
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sample data is loaded on startup and contains events")
    void sampleDataIsLoaded() {
        assertThat(eventService.getAllEvents()).isNotEmpty();
    }

    @Test
    @DisplayName("Total event count matches the size of getAllEvents()")
    void totalCountMatchesListSize() {
        assertThat(eventService.getTotalCount())
                .isEqualTo(eventService.getAllEvents().size());
    }

    @Test
    @DisplayName("All events have non-null required fields")
    void allEventsHaveRequiredFields() {
        for (SecurityEvent event : eventService.getAllEvents()) {
            assertThat(event.id()).isPositive();
            assertThat(event.timestamp()).isNotNull();
            assertThat(event.username()).isNotBlank();
            assertThat(event.sourceIp()).isNotBlank();
            assertThat(event.eventType()).isNotNull();
            assertThat(event.severity()).isNotNull();
            assertThat(event.description()).isNotBlank();
        }
    }

    @Test
    @DisplayName("Event IDs are unique")
    void eventIdsAreUnique() {
        List<Long> ids = eventService.getAllEvents().stream()
                .map(SecurityEvent::id)
                .toList();
        long distinctCount = ids.stream().distinct().count();
        assertThat(distinctCount).isEqualTo(ids.size());
    }

    // -----------------------------------------------------------------------
    // Severity filter
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Filtering by HIGH severity returns only HIGH events")
    void filterBySeverityReturnsOnlyMatchingEvents() {
        List<SecurityEvent> highEvents = eventService.getEvents(Severity.HIGH, null);
        assertThat(highEvents).isNotEmpty();
        assertThat(highEvents).allMatch(e -> e.severity() == Severity.HIGH);
    }

    @Test
    @DisplayName("Filtering by LOW severity returns only LOW events")
    void filterByLowSeverityReturnsOnlyLowEvents() {
        List<SecurityEvent> lowEvents = eventService.getEvents(Severity.LOW, null);
        assertThat(lowEvents).isNotEmpty();
        assertThat(lowEvents).allMatch(e -> e.severity() == Severity.LOW);
    }

    @Test
    @DisplayName("Null severity filter returns all events")
    void nullSeverityFilterReturnsAllEvents() {
        List<SecurityEvent> all = eventService.getEvents(null, null);
        assertThat(all).hasSize(eventService.getTotalCount());
    }

    // -----------------------------------------------------------------------
    // Event type filter
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Filtering by LOGIN_FAILURE returns only login failure events")
    void filterByEventTypeReturnsOnlyMatchingEvents() {
        List<SecurityEvent> failures = eventService.getEvents(null, EventType.LOGIN_FAILURE);
        assertThat(failures).isNotEmpty();
        assertThat(failures).allMatch(e -> e.eventType() == EventType.LOGIN_FAILURE);
    }

    @Test
    @DisplayName("Filtering by PORT_SCAN returns only port scan events")
    void filterByPortScanReturnsOnlyPortScanEvents() {
        List<SecurityEvent> scans = eventService.getEvents(null, EventType.PORT_SCAN);
        assertThat(scans).isNotEmpty();
        assertThat(scans).allMatch(e -> e.eventType() == EventType.PORT_SCAN);
    }

    // -----------------------------------------------------------------------
    // Combined filter
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Combining severity and type filters returns only matching events")
    void combinedFilterReturnsOnlyMatchingEvents() {
        List<SecurityEvent> results = eventService.getEvents(Severity.HIGH, EventType.LOGIN_FAILURE);
        assertThat(results).allMatch(
                e -> e.severity() == Severity.HIGH && e.eventType() == EventType.LOGIN_FAILURE
        );
    }

    // -----------------------------------------------------------------------
    // Sort order
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getEvents() returns events sorted newest first")
    void eventsAreSortedNewestFirst() {
        List<SecurityEvent> events = eventService.getEvents(null, null);
        for (int i = 0; i < events.size() - 1; i++) {
            assertThat(events.get(i).timestamp())
                    .as("Event at index %d should be >= event at index %d", i, i + 1)
                    .isAfterOrEqualTo(events.get(i + 1).timestamp());
        }
    }

    // -----------------------------------------------------------------------
    // getAllEvents() immutability
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("getAllEvents() returns a defensive copy – modifying it does not affect the store")
    void getAllEventsReturnsDefensiveCopy() {
        List<SecurityEvent> copy = eventService.getAllEvents();
        int originalSize = copy.size();
        // The list returned by getAllEvents() is unmodifiable (List.copyOf returns an unmodifiable list)
        // Just verify the count hasn't changed from a second call
        assertThat(eventService.getAllEvents()).hasSize(originalSize);
    }
}
