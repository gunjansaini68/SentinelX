package com.sentinelx.model;

import java.time.Instant;

/**
 * Represents an alert raised by a detection rule.
 *
 * When the DetectionService spots something suspicious in the event list
 * (e.g. too many failed logins from the same IP), it creates an Alert
 * and includes:
 *   - which rule fired
 *   - a plain-English explanation of the threat
 *   - a recommended defensive action the user could take
 *
 * Fields:
 *   id                  – unique number
 *   timestamp           – when the alert was generated
 *   ruleName            – short label for the rule (e.g. "BRUTE_FORCE_LOGIN")
 *   sourceIp            – the IP address that triggered the alert
 *   affectedUsername    – the user account being targeted (may be "multiple" or "N/A")
 *   explanation         – what this alert means in plain English
 *   recommendedAction   – what a defender should do about it
 *   severity            – how serious this alert is
 *   eventCount          – how many matching events contributed to this alert
 */
public record Alert(
        long id,
        Instant timestamp,
        String ruleName,
        String sourceIp,
        String affectedUsername,
        String explanation,
        String recommendedAction,
        SecurityEvent.Severity severity,
        int eventCount
) {}
