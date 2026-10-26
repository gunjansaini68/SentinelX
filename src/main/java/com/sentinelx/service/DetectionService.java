package com.sentinelx.service;

import com.sentinelx.model.Alert;
import com.sentinelx.model.SecurityEvent;
import com.sentinelx.model.SecurityEvent.EventType;
import com.sentinelx.model.SecurityEvent.Severity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * DetectionService applies detection rules to the list of security events
 * and produces Alerts when suspicious patterns are found.
 *
 * Current rules
 * -------------
 * 1. Brute-Force Login Detection
 *    Fires when the same source IP has >= `threshold` LOGIN_FAILURE events
 *    within the last `windowMinutes` minutes.
 *
 *    Both values are read from application.properties so you can tune them
 *    without changing any code:
 *      sentinelx.detection.brute-force.threshold      (default 5)
 *      sentinelx.detection.brute-force.window-minutes (default 10)
 *
 * How it works (step by step)
 * ---------------------------
 *  1. Take all events from EventService.
 *  2. Keep only LOGIN_FAILURE events whose timestamp falls inside the window.
 *  3. Group those events by source IP using a Map<String, List<SecurityEvent>>.
 *  4. For each IP, if the group size >= threshold → create one Alert.
 *  5. The Alert includes the IP, how many failures were counted, a plain-English
 *     explanation, and a recommended defensive action.
 */
@Service
public class DetectionService {

    /** The minimum number of failures from one IP to raise an alert. */
    private final int threshold;

    /** How far back in time (minutes) to look when counting failures. */
    private final int windowMinutes;

    private final EventService eventService;

    /** Assigns a unique ID to each alert produced in a single analysis run. */
    private final AtomicLong alertIdCounter = new AtomicLong(1);

    /**
     * Spring calls this constructor and injects:
     *   - the two @Value properties from application.properties
     *   - the EventService bean (so we can read events)
     *
     * The colon syntax (@Value("${...}:5")) provides a default value in case
     * the property is missing from application.properties.
     */
    public DetectionService(
            @Value("${sentinelx.detection.brute-force.threshold:5}") int threshold,
            @Value("${sentinelx.detection.brute-force.window-minutes:10}") int windowMinutes,
            EventService eventService) {
        this.threshold = threshold;
        this.windowMinutes = windowMinutes;
        this.eventService = eventService;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Runs all detection rules against the current event list and returns
     * the resulting alerts.
     *
     * Calling this method is safe to call repeatedly – it re-evaluates from
     * scratch each time and resets the alert ID counter.
     */
    public List<Alert> detectAlerts() {
        alertIdCounter.set(1); // reset so IDs are stable across repeated calls
        List<Alert> alerts = new ArrayList<>();
        alerts.addAll(detectBruteForceLogins(eventService.getAllEvents()));
        return alerts;
    }

    /**
     * Package-private overload used by unit tests to pass a custom event list
     * instead of the one held by EventService.
     *
     * This is the standard testing pattern: inject controlled data directly
     * rather than relying on the full sample dataset.
     */
    List<Alert> detectAlerts(List<SecurityEvent> events) {
        alertIdCounter.set(1);
        List<Alert> alerts = new ArrayList<>();
        alerts.addAll(detectBruteForceLogins(events));
        return alerts;
    }

    /** Returns the configured failure threshold (exposed for tests). */
    int getThreshold() {
        return threshold;
    }

    /** Returns the configured time window in minutes (exposed for tests). */
    int getWindowMinutes() {
        return windowMinutes;
    }

    // -----------------------------------------------------------------------
    // Detection rules
    // -----------------------------------------------------------------------

    /**
     * Brute-Force Login Detection rule.
     *
     * Algorithm:
     *  1. Compute the earliest timestamp that is still inside the window.
     *  2. Filter: keep only LOGIN_FAILURE events at or after that cutoff.
     *  3. Group by sourceIp → Map<String, List<SecurityEvent>>
     *  4. For each IP where the group size >= threshold, produce one Alert.
     *
     * @param events the full list of events to analyse
     * @return list of brute-force alerts (may be empty)
     */
    private List<Alert> detectBruteForceLogins(List<SecurityEvent> events) {
        Instant windowStart = Instant.now().minus(windowMinutes, ChronoUnit.MINUTES);

        // Step 1 + 2: keep only LOGIN_FAILURE events inside the time window
        Map<String, List<SecurityEvent>> failuresByIp = events.stream()
                .filter(e -> e.eventType() == EventType.LOGIN_FAILURE)
                .filter(e -> !e.timestamp().isBefore(windowStart))
                .collect(Collectors.groupingBy(SecurityEvent::sourceIp));

        // Step 3: check each IP's count against the threshold
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<SecurityEvent>> entry : failuresByIp.entrySet()) {
            String ip = entry.getKey();
            List<SecurityEvent> failures = entry.getValue();

            if (failures.size() >= threshold) {
                alerts.add(buildBruteForceAlert(ip, failures));
            }
        }

        return alerts;
    }

    /**
     * Constructs the Alert record for a detected brute-force cluster.
     *
     * The "affectedUsername" is set to the distinct usernames targeted by this IP.
     * If multiple accounts were tried, all are listed (comma-separated).
     */
    private Alert buildBruteForceAlert(String ip, List<SecurityEvent> failures) {
        // Collect distinct usernames that were targeted from this IP
        String usernames = failures.stream()
                .map(SecurityEvent::username)
                .distinct()
                .sorted()
                .collect(Collectors.joining(", "));

        int count = failures.size();

        String explanation = String.format(
                "Brute-force attack detected: %d failed login attempt%s from IP %s " +
                "within the last %d minute%s, targeting account%s: %s.",
                count,
                count == 1 ? "" : "s",
                ip,
                windowMinutes,
                windowMinutes == 1 ? "" : "s",
                failures.stream().map(SecurityEvent::username).distinct().count() == 1 ? "" : "s",
                usernames
        );

        String recommendedAction =
                "Block or rate-limit IP " + ip + " at the firewall. " +
                "Force a password reset for the targeted account(s): " + usernames + ". " +
                "Enable multi-factor authentication (MFA) to prevent future credential attacks.";

        return new Alert(
                alertIdCounter.getAndIncrement(),
                Instant.now(),
                "BRUTE_FORCE_LOGIN",
                ip,
                usernames,
                explanation,
                recommendedAction,
                Severity.HIGH,
                count
        );
    }
}
