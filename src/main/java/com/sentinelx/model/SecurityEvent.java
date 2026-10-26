package com.sentinelx.model;

import java.time.Instant;

/**
 * Represents a single synthetic security event.
 *
 * Think of this as one row in a security log spreadsheet.
 * Every field is set at construction time and never changes (immutable record).
 *
 * Fields:
 *   id          – unique number so we can tell events apart
 *   timestamp   – when the event happened (UTC)
 *   username    – fictional user involved (e.g. "alice")
 *   sourceIp    – fictional IP address (RFC 5737 documentation ranges – never real)
 *   eventType   – what kind of event: LOGIN_FAILURE, LOGIN_SUCCESS, PORT_SCAN, etc.
 *   severity    – how serious it is: LOW, MEDIUM, HIGH, CRITICAL
 *   description – human-readable sentence explaining what happened
 */
public record SecurityEvent(
        long id,
        Instant timestamp,
        String username,
        String sourceIp,
        EventType eventType,
        Severity severity,
        String description
) {

    /** The kinds of security events SentinelX can generate. */
    public enum EventType {
        LOGIN_FAILURE,
        LOGIN_SUCCESS,
        PORT_SCAN,
        PRIVILEGE_ESCALATION,
        SUSPICIOUS_TRAFFIC
    }

    /** How serious an event is, from least to most severe. */
    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
}
