package com.sentinelx.controller;

import com.sentinelx.model.Alert;
import com.sentinelx.model.SecurityEvent;
import com.sentinelx.model.SecurityEvent.EventType;
import com.sentinelx.model.SecurityEvent.Severity;
import com.sentinelx.service.DetectionService;
import com.sentinelx.service.EventService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DashboardController exposes the SentinelX REST API.
 *
 * @RestController means every method returns JSON automatically —
 * Spring converts the Java objects to JSON for you.
 *
 * @RequestMapping("/api") means every endpoint in this class
 * starts with /api (e.g. /api/health, /api/events).
 *
 * Endpoints
 * ---------
 *   GET /api/health   – confirms the app is running
 *   GET /api/events   – lists synthetic security events (filterable)
 *   GET /api/alerts   – lists active brute-force alerts
 *   GET /api/summary  – totals and counts for the dashboard header
 */
@RestController
@RequestMapping("/api")
public class DashboardController {

    private final EventService eventService;
    private final DetectionService detectionService;

    /**
     * Spring injects both services automatically because they are @Service beans.
     */
    public DashboardController(EventService eventService, DetectionService detectionService) {
        this.eventService = eventService;
        this.detectionService = detectionService;
    }

    // -----------------------------------------------------------------------
    // GET /api/health
    // -----------------------------------------------------------------------

    /**
     * Health check endpoint.
     *
     * Returns a simple JSON object confirming the app is up.
     * Useful for quickly verifying the server started correctly.
     *
     * Example response:
     *   {"status":"UP","application":"SentinelX"}
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("application", "SentinelX");
        return ResponseEntity.ok(response);
    }

    // -----------------------------------------------------------------------
    // GET /api/events
    // -----------------------------------------------------------------------

    /**
     * Returns the list of synthetic security events.
     *
     * Optional query parameters (both can be combined):
     *   ?severity=HIGH          – filter by severity (LOW/MEDIUM/HIGH/CRITICAL)
     *   ?type=LOGIN_FAILURE     – filter by event type
     *
     * Invalid values are ignored safely and return an empty list with HTTP 400.
     *
     * Example URLs:
     *   /api/events
     *   /api/events?severity=HIGH
     *   /api/events?type=LOGIN_FAILURE
     *   /api/events?severity=HIGH&type=LOGIN_FAILURE
     */
    @GetMapping("/events")
    public ResponseEntity<?> getEvents(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type) {

        // Parse severity — return 400 if the value is not a valid enum constant
        Severity severityEnum = null;
        if (severity != null && !severity.isBlank()) {
            try {
                severityEnum = Severity.valueOf(severity.toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid severity value: '" + severity +
                                "'. Valid values: LOW, MEDIUM, HIGH, CRITICAL"));
            }
        }

        // Parse event type — return 400 if the value is not a valid enum constant
        EventType eventTypeEnum = null;
        if (type != null && !type.isBlank()) {
            try {
                eventTypeEnum = EventType.valueOf(type.toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid type value: '" + type +
                                "'. Valid values: LOGIN_FAILURE, LOGIN_SUCCESS, " +
                                "PORT_SCAN, PRIVILEGE_ESCALATION, SUSPICIOUS_TRAFFIC"));
            }
        }

        List<SecurityEvent> events = eventService.getEvents(severityEnum, eventTypeEnum);
        return ResponseEntity.ok(events);
    }

    // -----------------------------------------------------------------------
    // GET /api/alerts
    // -----------------------------------------------------------------------

    /**
     * Returns the list of active security alerts produced by the detection engine.
     *
     * Alerts are re-evaluated fresh on every request, so they always reflect
     * the current state of the event store.
     *
     * Example response item:
     * {
     *   "id": 1,
     *   "ruleName": "BRUTE_FORCE_LOGIN",
     *   "sourceIp": "192.0.2.42",
     *   "explanation": "Brute-force attack detected ...",
     *   "recommendedAction": "Block or rate-limit IP ...",
     *   "severity": "HIGH",
     *   "eventCount": 6
     * }
     */
    @GetMapping("/alerts")
    public ResponseEntity<List<Alert>> getAlerts() {
        return ResponseEntity.ok(detectionService.detectAlerts());
    }

    // -----------------------------------------------------------------------
    // GET /api/summary
    // -----------------------------------------------------------------------

    /**
     * Returns summary counts for the dashboard header cards.
     *
     * Example response:
     * {
     *   "totalEvents": 40,
     *   "totalAlerts": 1,
     *   "bySeverity": {
     *     "LOW": 14,
     *     "MEDIUM": 12,
     *     "HIGH": 12,
     *     "CRITICAL": 2
     *   }
     * }
     */
    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> getSummary() {
        List<SecurityEvent> allEvents = eventService.getAllEvents();
        List<Alert> allAlerts = detectionService.detectAlerts();

        // Count events grouped by severity
        Map<String, Long> bySeverity = new HashMap<>();
        for (Severity s : Severity.values()) {
            long count = allEvents.stream()
                    .filter(e -> e.severity() == s)
                    .count();
            bySeverity.put(s.name(), count);
        }

        Map<String, Object> summary = new HashMap<>();
        summary.put("totalEvents", allEvents.size());
        summary.put("totalAlerts", allAlerts.size());
        summary.put("bySeverity", bySeverity);

        return ResponseEntity.ok(summary);
    }
}
