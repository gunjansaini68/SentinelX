package com.sentinelx.service;

import com.sentinelx.model.Alert;
import com.sentinelx.model.SecurityEvent;
import com.sentinelx.model.SecurityEvent.EventType;
import com.sentinelx.model.SecurityEvent.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for DetectionService – brute-force login detection.
 *
 * Design approach
 * ---------------
 * We do NOT start a Spring context (no @SpringBootTest). Instead we:
 *   1. Create a real EventService (holds sample data).
 *   2. Create a DetectionService with a *known* threshold and window.
 *   3. Call the package-private detectAlerts(List<SecurityEvent>) overload
 *      so we can pass precisely crafted synthetic event lists without
 *      depending on the sample data in EventService.
 *
 * This makes the tests fast, deterministic, and easy to understand.
 *
 * Helper: makeFailure() / makeSuccess()
 *   Build a SecurityEvent with just enough fields to exercise the rule.
 *   All IPs use RFC 5737 documentation ranges (192.0.2.x / 198.51.100.x).
 */
class DetectionServiceTest {

    // Use known values so test assertions are independent of application.properties
    private static final int THRESHOLD = 5;
    private static final int WINDOW_MINUTES = 10;

    private DetectionService detectionService;
    private long idSeq;   // simple counter for event IDs in each test

    @BeforeEach
    void setUp() {
        EventService eventService = new EventService();
        detectionService = new DetectionService(THRESHOLD, WINDOW_MINUTES, eventService);
        idSeq = 1;
    }

    // -----------------------------------------------------------------------
    // Configuration sanity
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("DetectionService reads threshold and window correctly")
    void configurationValuesAreInjected() {
        assertThat(detectionService.getThreshold()).isEqualTo(THRESHOLD);
        assertThat(detectionService.getWindowMinutes()).isEqualTo(WINDOW_MINUTES);
    }

    // -----------------------------------------------------------------------
    // Threshold boundary tests
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Alert fires when failures equal the threshold (at-threshold)")
    void alertFiresAtExactThreshold() {
        // Exactly THRESHOLD failures from one IP, all inside the window
        List<SecurityEvent> events = failuresFromIp("192.0.2.42", THRESHOLD, 1);

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).hasSize(1);
        Alert alert = alerts.get(0);
        assertThat(alert.sourceIp()).isEqualTo("192.0.2.42");
        assertThat(alert.eventCount()).isEqualTo(THRESHOLD);
        assertThat(alert.ruleName()).isEqualTo("BRUTE_FORCE_LOGIN");
        assertThat(alert.severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    @DisplayName("Alert fires when failures exceed the threshold (above-threshold)")
    void alertFiresAboveThreshold() {
        List<SecurityEvent> events = failuresFromIp("192.0.2.42", THRESHOLD + 2, 1);

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).eventCount()).isEqualTo(THRESHOLD + 2);
    }

    @Test
    @DisplayName("No alert when failures are one below the threshold")
    void noAlertOneBelowThreshold() {
        List<SecurityEvent> events = failuresFromIp("192.0.2.42", THRESHOLD - 1, 1);

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).isEmpty();
    }

    @Test
    @DisplayName("No alert when the event list is empty")
    void noAlertForEmptyEventList() {
        List<Alert> alerts = detectionService.detectAlerts(List.of());

        assertThat(alerts).isEmpty();
    }

    // -----------------------------------------------------------------------
    // Time-window tests
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("No alert when all failures are outside the time window")
    void noAlertWhenAllFailuresAreOutsideWindow() {
        Instant now = Instant.now();
        // All THRESHOLD failures happened more than WINDOW_MINUTES ago
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < THRESHOLD; i++) {
            events.add(makeFailure("192.0.2.42", "alice",
                    now.minus(WINDOW_MINUTES + 1 + i, ChronoUnit.MINUTES)));
        }

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).isEmpty();
    }

    @Test
    @DisplayName("Only failures inside the window count toward the threshold")
    void onlyInWindowFailuresCountTowardThreshold() {
        Instant now = Instant.now();
        List<SecurityEvent> events = new ArrayList<>();

        // (THRESHOLD - 1) failures INSIDE the window — not enough to trigger
        for (int i = 1; i < THRESHOLD; i++) {
            events.add(makeFailure("192.0.2.42", "alice",
                    now.minus(i, ChronoUnit.MINUTES)));           // 1..4 min ago
        }
        // Extra failures OUTSIDE the window — should not be counted
        for (int i = 0; i < 10; i++) {
            events.add(makeFailure("192.0.2.42", "alice",
                    now.minus(WINDOW_MINUTES + 5 + i, ChronoUnit.MINUTES)));  // 15+ min ago
        }

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).isEmpty();
    }

    @Test
    @DisplayName("Failure near the window boundary is included")
    void failureAtExactWindowBoundaryIsIncluded() {
        Instant now = Instant.now();
        List<SecurityEvent> events = new ArrayList<>();

        // THRESHOLD - 1 failures well inside the window
        for (int i = 1; i < THRESHOLD; i++) {
            events.add(makeFailure("192.0.2.42", "alice",
                    now.minus(i, ChronoUnit.MINUTES)));
        }
        // One failure just inside the window boundary (30 seconds of margin avoids
        // a race between the test's Instant.now() and DetectionService's Instant.now())
        events.add(makeFailure("192.0.2.42", "alice",
                now.minus(WINDOW_MINUTES, ChronoUnit.MINUTES).plusSeconds(30)));

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).eventCount()).isEqualTo(THRESHOLD);
    }

    // -----------------------------------------------------------------------
    // Grouping by IP tests
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Each IP that reaches the threshold gets its own separate alert")
    void eachOverThresholdIpGetsItsOwnAlert() {
        List<SecurityEvent> events = new ArrayList<>();
        events.addAll(failuresFromIp("192.0.2.10", THRESHOLD, 1));     // should alert
        events.addAll(failuresFromIp("198.51.100.20", THRESHOLD, 1));  // should alert

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).hasSize(2);
        assertThat(alerts).extracting(Alert::sourceIp)
                .containsExactlyInAnyOrder("192.0.2.10", "198.51.100.20");
    }

    @Test
    @DisplayName("IP below threshold does not fire even when another IP triggers")
    void belowThresholdIpDoesNotFireAlongside() {
        List<SecurityEvent> events = new ArrayList<>();
        events.addAll(failuresFromIp("192.0.2.10", THRESHOLD,     1)); // should alert
        events.addAll(failuresFromIp("198.51.100.7", THRESHOLD - 1, 1)); // should NOT

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).sourceIp()).isEqualTo("192.0.2.10");
    }

    @Test
    @DisplayName("Failures from different IPs are not merged together")
    void failuresAreNotMixedAcrossIps() {
        Instant now = Instant.now();
        List<SecurityEvent> events = new ArrayList<>();

        // Two IPs, each with (THRESHOLD - 1) failures — neither should trigger alone
        for (int i = 1; i <= THRESHOLD - 1; i++) {
            events.add(makeFailure("192.0.2.11", "alice", now.minus(i, ChronoUnit.MINUTES)));
            events.add(makeFailure("192.0.2.12", "bob",   now.minus(i, ChronoUnit.MINUTES)));
        }

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).isEmpty();
    }

    // -----------------------------------------------------------------------
    // Successful logins must not count toward the rule
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Successful logins from the same IP do not count toward the threshold")
    void successfulLoginsDoNotCount() {
        Instant now = Instant.now();
        List<SecurityEvent> events = new ArrayList<>();

        // THRESHOLD - 1 failures (not enough to trigger on their own)
        for (int i = 1; i < THRESHOLD; i++) {
            events.add(makeFailure("192.0.2.42", "alice", now.minus(i, ChronoUnit.MINUTES)));
        }
        // Many successful logins from the same IP — must be ignored by the rule
        for (int i = 0; i < 20; i++) {
            events.add(makeSuccess("192.0.2.42", "alice", now.minus(i, ChronoUnit.MINUTES)));
        }

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).isEmpty();
    }

    @Test
    @DisplayName("Only successful logins present — no alert")
    void onlySuccessfulLoginsProducesNoAlert() {
        Instant now = Instant.now();
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            events.add(makeSuccess("192.0.2.42", "alice", now.minus(i, ChronoUnit.MINUTES)));
        }

        List<Alert> alerts = detectionService.detectAlerts(events);

        assertThat(alerts).isEmpty();
    }

    // -----------------------------------------------------------------------
    // Alert content tests
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Generated alert has non-blank explanation and recommended action")
    void alertHasUsefulContent() {
        List<SecurityEvent> events = failuresFromIp("192.0.2.42", THRESHOLD, 1);

        Alert alert = detectionService.detectAlerts(events).get(0);

        assertThat(alert.explanation()).isNotBlank();
        assertThat(alert.recommendedAction()).isNotBlank();
        assertThat(alert.explanation()).contains("192.0.2.42");
        assertThat(alert.recommendedAction()).contains("192.0.2.42");
    }

    @Test
    @DisplayName("Alert lists all distinct usernames targeted from the same IP")
    void alertListsDistinctTargetedUsernames() {
        Instant now = Instant.now();
        List<SecurityEvent> events = List.of(
                makeFailure("192.0.2.42", "alice", now.minus(1, ChronoUnit.MINUTES)),
                makeFailure("192.0.2.42", "bob",   now.minus(2, ChronoUnit.MINUTES)),
                makeFailure("192.0.2.42", "carol", now.minus(3, ChronoUnit.MINUTES)),
                makeFailure("192.0.2.42", "alice", now.minus(4, ChronoUnit.MINUTES)), // duplicate
                makeFailure("192.0.2.42", "dave",  now.minus(5, ChronoUnit.MINUTES))
        );

        Alert alert = detectionService.detectAlerts(events).get(0);

        // affectedUsername should contain all 4 distinct names (alice, bob, carol, dave)
        assertThat(alert.affectedUsername()).contains("alice");
        assertThat(alert.affectedUsername()).contains("bob");
        assertThat(alert.affectedUsername()).contains("carol");
        assertThat(alert.affectedUsername()).contains("dave");
    }

    @Test
    @DisplayName("Alert eventCount matches the actual number of in-window failures")
    void alertEventCountIsAccurate() {
        int extraFailures = 3;
        List<SecurityEvent> events = failuresFromIp("192.0.2.42", THRESHOLD + extraFailures, 1);

        Alert alert = detectionService.detectAlerts(events).get(0);

        assertThat(alert.eventCount()).isEqualTo(THRESHOLD + extraFailures);
    }

    // -----------------------------------------------------------------------
    // Sample-data integration: verify default data produces expected alerts
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Default sample data triggers exactly one brute-force alert (from 192.0.2.42)")
    void defaultSampleDataTriggersOneAlert() {
        // detectAlerts() (no-arg) uses the real EventService sample data
        List<Alert> alerts = detectionService.detectAlerts();

        // The sample data has 6 recent failures from 192.0.2.42 — should fire
        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).sourceIp()).isEqualTo("192.0.2.42");
    }

    // -----------------------------------------------------------------------
    // Helper methods
    // -----------------------------------------------------------------------

    /**
     * Creates `count` LOGIN_FAILURE events from the given IP, each spaced
     * `minutesApart` minutes apart, all within the current window.
     */
    private List<SecurityEvent> failuresFromIp(String ip, int count, int minutesApart) {
        Instant now = Instant.now();
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            events.add(makeFailure(ip, "testuser",
                    now.minus((long) (i + 1) * minutesApart, ChronoUnit.MINUTES)));
        }
        return events;
    }

    /** Builds a minimal LOGIN_FAILURE SecurityEvent. */
    private SecurityEvent makeFailure(String ip, String username, Instant timestamp) {
        return new SecurityEvent(idSeq++, timestamp, username, ip,
                EventType.LOGIN_FAILURE, Severity.HIGH,
                "Synthetic failed login for " + username + " from " + ip);
    }

    /** Builds a minimal LOGIN_SUCCESS SecurityEvent. */
    private SecurityEvent makeSuccess(String ip, String username, Instant timestamp) {
        return new SecurityEvent(idSeq++, timestamp, username, ip,
                EventType.LOGIN_SUCCESS, Severity.LOW,
                "Synthetic successful login for " + username + " from " + ip);
    }
}
