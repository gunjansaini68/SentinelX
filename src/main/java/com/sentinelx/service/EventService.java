package com.sentinelx.service;

import com.sentinelx.model.SecurityEvent;
import com.sentinelx.model.SecurityEvent.EventType;
import com.sentinelx.model.SecurityEvent.Severity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * EventService is the in-memory "database" for SentinelX.
 *
 * It generates a fixed set of synthetic (made-up) security events when the
 * application starts, and provides methods to query them.
 *
 * Why no real database?
 *   Keeping everything in a plain Java List means zero configuration.
 *   The data resets every time you restart the app, which is fine for a
 *   demo/portfolio project.
 *
 * IP address ranges used:
 *   192.0.2.x   – TEST-NET-1  (RFC 5737, reserved for documentation)
 *   198.51.100.x – TEST-NET-2 (RFC 5737, reserved for documentation)
 *   These are never routed on the real internet, so they are safe to display.
 */
@Service
public class EventService {

    /** Auto-incrementing counter used to assign unique IDs to each event. */
    private final AtomicLong idCounter = new AtomicLong(1);

    /** The in-memory list that holds all synthetic events. */
    private final List<SecurityEvent> events;

    /**
     * Constructor – called once by Spring when the application starts.
     * Populates the event list with sample data.
     */
    public EventService() {
        this.events = new ArrayList<>(generateSampleEvents());
    }

    // -----------------------------------------------------------------------
    // Public query methods
    // -----------------------------------------------------------------------

    /**
     * Returns all events, optionally filtered by severity and/or event type.
     *
     * @param severity  if non-null, only events with this severity are returned
     * @param eventType if non-null, only events of this type are returned
     * @return filtered (or unfiltered) list of events, newest first
     */
    public List<SecurityEvent> getEvents(Severity severity, EventType eventType) {
        return events.stream()
                .filter(e -> severity == null || e.severity() == severity)
                .filter(e -> eventType == null || e.eventType() == eventType)
                .sorted((a, b) -> b.timestamp().compareTo(a.timestamp()))
                .collect(Collectors.toList());
    }

    /**
     * Returns every event without any filtering.
     * Convenience method used internally by the DetectionService.
     */
    public List<SecurityEvent> getAllEvents() {
        return List.copyOf(events); // defensive copy so callers can't modify the list
    }

    /**
     * Returns the total number of events in the store.
     */
    public int getTotalCount() {
        return events.size();
    }

    // -----------------------------------------------------------------------
    // Sample data generation
    // -----------------------------------------------------------------------

    /**
     * Builds a realistic-looking set of 40 synthetic security events spread
     * across the last 30 minutes.
     *
     * The events are designed to include:
     *   - A brute-force cluster: 6 failed logins from 192.0.2.42 within 8 minutes
     *   - A second smaller cluster: 3 failed logins from 198.51.100.7 (below threshold)
     *   - A port scan event
     *   - Privilege escalation attempts
     *   - Normal successful logins
     *   - Suspicious traffic events
     */
    private List<SecurityEvent> generateSampleEvents() {
        List<SecurityEvent> list = new ArrayList<>();
        Instant now = Instant.now();

        // ------------------------------------------------------------------
        // Cluster A: 6 failed logins from 192.0.2.42 → should trigger alert
        // Spread across 8 minutes (all within the 10-minute window)
        // ------------------------------------------------------------------
        list.add(make(now.minus(9, ChronoUnit.MINUTES),  "alice",   "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user alice from 192.0.2.42"));
        list.add(make(now.minus(8, ChronoUnit.MINUTES),  "alice",   "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user alice from 192.0.2.42"));
        list.add(make(now.minus(7, ChronoUnit.MINUTES),  "alice",   "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user alice from 192.0.2.42"));
        list.add(make(now.minus(6, ChronoUnit.MINUTES),  "alice",   "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user alice from 192.0.2.42"));
        list.add(make(now.minus(5, ChronoUnit.MINUTES),  "alice",   "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user alice from 192.0.2.42"));
        list.add(make(now.minus(4, ChronoUnit.MINUTES),  "alice",   "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user alice from 192.0.2.42"));

        // ------------------------------------------------------------------
        // Cluster B: 3 failed logins from 198.51.100.7 → below threshold
        // ------------------------------------------------------------------
        list.add(make(now.minus(12, ChronoUnit.MINUTES), "bob",     "198.51.100.7", EventType.LOGIN_FAILURE, Severity.MEDIUM, "Failed login attempt for user bob from 198.51.100.7"));
        list.add(make(now.minus(11, ChronoUnit.MINUTES), "bob",     "198.51.100.7", EventType.LOGIN_FAILURE, Severity.MEDIUM, "Failed login attempt for user bob from 198.51.100.7"));
        list.add(make(now.minus(10, ChronoUnit.MINUTES), "bob",     "198.51.100.7", EventType.LOGIN_FAILURE, Severity.MEDIUM, "Failed login attempt for user bob from 198.51.100.7"));

        // ------------------------------------------------------------------
        // Successful logins (normal behaviour)
        // ------------------------------------------------------------------
        list.add(make(now.minus(3, ChronoUnit.MINUTES),  "carol",   "192.0.2.10",  EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user carol from 192.0.2.10"));
        list.add(make(now.minus(2, ChronoUnit.MINUTES),  "dave",    "198.51.100.20",EventType.LOGIN_SUCCESS, Severity.LOW,    "Successful login for user dave from 198.51.100.20"));
        list.add(make(now.minus(1, ChronoUnit.MINUTES),  "eve",     "192.0.2.55",  EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user eve from 192.0.2.55"));

        // ------------------------------------------------------------------
        // Port scan events
        // ------------------------------------------------------------------
        list.add(make(now.minus(25, ChronoUnit.MINUTES), "unknown", "192.0.2.99",  EventType.PORT_SCAN,      Severity.HIGH,   "Port scan detected from 192.0.2.99 targeting ports 22, 80, 443, 8080"));
        list.add(make(now.minus(20, ChronoUnit.MINUTES), "unknown", "198.51.100.50",EventType.PORT_SCAN,     Severity.MEDIUM, "Port scan detected from 198.51.100.50 targeting ports 3306, 5432"));

        // ------------------------------------------------------------------
        // Privilege escalation attempts
        // ------------------------------------------------------------------
        list.add(make(now.minus(18, ChronoUnit.MINUTES), "frank",   "192.0.2.77",  EventType.PRIVILEGE_ESCALATION, Severity.CRITICAL, "Privilege escalation attempt by frank from 192.0.2.77 – sudo abuse detected"));
        list.add(make(now.minus(15, ChronoUnit.MINUTES), "grace",   "198.51.100.88",EventType.PRIVILEGE_ESCALATION, Severity.HIGH,    "Privilege escalation attempt by grace from 198.51.100.88"));

        // ------------------------------------------------------------------
        // Suspicious traffic
        // ------------------------------------------------------------------
        list.add(make(now.minus(28, ChronoUnit.MINUTES), "unknown", "192.0.2.200", EventType.SUSPICIOUS_TRAFFIC,  Severity.MEDIUM, "Unusual outbound traffic volume detected from 192.0.2.200"));
        list.add(make(now.minus(22, ChronoUnit.MINUTES), "unknown", "198.51.100.101",EventType.SUSPICIOUS_TRAFFIC,Severity.LOW,    "Repeated DNS lookups for unusual domains from 198.51.100.101"));
        list.add(make(now.minus(16, ChronoUnit.MINUTES), "heidi",   "192.0.2.33",  EventType.SUSPICIOUS_TRAFFIC,  Severity.MEDIUM, "Suspicious traffic pattern from heidi at 192.0.2.33 – possible data exfiltration"));

        // ------------------------------------------------------------------
        // Older events (> 10 minutes ago) – used to verify time-window logic
        // ------------------------------------------------------------------
        list.add(make(now.minus(30, ChronoUnit.MINUTES), "ivan",    "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user ivan from 192.0.2.42 (older event, outside window)"));
        list.add(make(now.minus(29, ChronoUnit.MINUTES), "judy",    "192.0.2.42",  EventType.LOGIN_FAILURE,  Severity.HIGH,   "Failed login attempt for user judy from 192.0.2.42 (older event, outside window)"));

        // Mix of additional varied events to make the dashboard look realistic
        list.add(make(now.minus(27, ChronoUnit.MINUTES), "karl",    "198.51.100.3", EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user karl from 198.51.100.3"));
        list.add(make(now.minus(26, ChronoUnit.MINUTES), "lena",    "192.0.2.14",  EventType.LOGIN_FAILURE,  Severity.MEDIUM, "Failed login attempt for user lena from 192.0.2.14"));
        list.add(make(now.minus(24, ChronoUnit.MINUTES), "mike",    "198.51.100.9", EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user mike from 198.51.100.9"));
        list.add(make(now.minus(23, ChronoUnit.MINUTES), "nina",    "192.0.2.61",  EventType.PORT_SCAN,      Severity.MEDIUM, "Port scan detected from 192.0.2.61 targeting ports 21, 23, 25"));
        list.add(make(now.minus(21, ChronoUnit.MINUTES), "oscar",   "198.51.100.77",EventType.LOGIN_FAILURE, Severity.MEDIUM, "Failed login attempt for user oscar from 198.51.100.77"));
        list.add(make(now.minus(19, ChronoUnit.MINUTES), "paul",    "192.0.2.5",   EventType.SUSPICIOUS_TRAFFIC, Severity.LOW, "Low-level suspicious traffic from 192.0.2.5"));
        list.add(make(now.minus(17, ChronoUnit.MINUTES), "quinn",   "198.51.100.44",EventType.LOGIN_SUCCESS, Severity.LOW,    "Successful login for user quinn from 198.51.100.44"));
        list.add(make(now.minus(14, ChronoUnit.MINUTES), "ruth",    "192.0.2.88",  EventType.LOGIN_FAILURE,  Severity.MEDIUM, "Failed login attempt for user ruth from 192.0.2.88"));
        list.add(make(now.minus(13, ChronoUnit.MINUTES), "sam",     "198.51.100.60",EventType.PRIVILEGE_ESCALATION, Severity.HIGH, "Privilege escalation attempt by sam from 198.51.100.60"));
        list.add(make(now.minus(8,  ChronoUnit.MINUTES), "tina",    "192.0.2.111", EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user tina from 192.0.2.111"));
        list.add(make(now.minus(7,  ChronoUnit.MINUTES), "uma",     "198.51.100.55",EventType.SUSPICIOUS_TRAFFIC, Severity.MEDIUM, "Suspicious traffic pattern from uma at 198.51.100.55"));
        list.add(make(now.minus(6,  ChronoUnit.MINUTES), "victor",  "192.0.2.78",  EventType.LOGIN_FAILURE,  Severity.MEDIUM, "Failed login attempt for user victor from 192.0.2.78"));
        list.add(make(now.minus(5,  ChronoUnit.MINUTES), "wendy",   "198.51.100.22",EventType.LOGIN_SUCCESS, Severity.LOW,    "Successful login for user wendy from 198.51.100.22"));
        list.add(make(now.minus(4,  ChronoUnit.MINUTES), "xavier",  "192.0.2.19",  EventType.PORT_SCAN,      Severity.HIGH,   "Port scan detected from 192.0.2.19 targeting a wide port range"));
        list.add(make(now.minus(3,  ChronoUnit.MINUTES), "yara",    "198.51.100.33",EventType.LOGIN_FAILURE, Severity.MEDIUM, "Failed login attempt for user yara from 198.51.100.33"));
        list.add(make(now.minus(2,  ChronoUnit.MINUTES), "zoe",     "192.0.2.91",  EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user zoe from 192.0.2.91"));
        list.add(make(now.minus(1,  ChronoUnit.MINUTES), "alice",   "192.0.2.42",  EventType.LOGIN_SUCCESS,  Severity.LOW,    "Successful login for user alice from 192.0.2.42 (finally succeeded)"));

        return list;
    }

    /**
     * Helper method: builds a SecurityEvent and auto-assigns an ID.
     */
    private SecurityEvent make(Instant timestamp, String username, String sourceIp,
                                EventType type, Severity severity, String description) {
        return new SecurityEvent(
                idCounter.getAndIncrement(),
                timestamp,
                username,
                sourceIp,
                type,
                severity,
                description
        );
    }
}
