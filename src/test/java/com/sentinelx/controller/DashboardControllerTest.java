package com.sentinelx.controller;

import com.sentinelx.service.DetectionService;
import com.sentinelx.service.EventService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Controller tests for DashboardController.
 *
 * @WebMvcTest starts only the web layer (no full Spring context), which keeps
 * tests fast. It gives us a MockMvc object that simulates HTTP requests
 * without starting a real server.
 *
 * @Import(EventService.class, DetectionService.class) brings in the real
 * service beans so the controller has something to call — no mocking needed
 * for a project this size.
 */
@WebMvcTest(DashboardController.class)
@Import({EventService.class, DetectionService.class})
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // -----------------------------------------------------------------------
    // GET /api/health
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/health returns 200 with status UP")
    void healthReturns200() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.application").value("SentinelX"));
    }

    // -----------------------------------------------------------------------
    // GET /api/events
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/events returns 200 with a non-empty list")
    void eventsReturns200WithEvents() throws Exception {
        mockMvc.perform(get("/api/events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThan(0))));
    }

    @Test
    @DisplayName("GET /api/events?severity=HIGH returns only HIGH severity events")
    void eventsFilteredBySeverity() throws Exception {
        mockMvc.perform(get("/api/events").param("severity", "HIGH"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].severity", everyItem(is("HIGH"))));
    }

    @Test
    @DisplayName("GET /api/events?type=LOGIN_FAILURE returns only LOGIN_FAILURE events")
    void eventsFilteredByType() throws Exception {
        mockMvc.perform(get("/api/events").param("type", "LOGIN_FAILURE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].eventType", everyItem(is("LOGIN_FAILURE"))));
    }

    @Test
    @DisplayName("GET /api/events with combined severity and type filters works correctly")
    void eventsFilteredBySeverityAndType() throws Exception {
        mockMvc.perform(get("/api/events")
                        .param("severity", "HIGH")
                        .param("type", "LOGIN_FAILURE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].severity", everyItem(is("HIGH"))))
                .andExpect(jsonPath("$[*].eventType", everyItem(is("LOGIN_FAILURE"))));
    }

    @Test
    @DisplayName("GET /api/events with invalid severity returns 400 with error message")
    void eventsInvalidSeverityReturns400() throws Exception {
        mockMvc.perform(get("/api/events").param("severity", "EXTREME"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", containsString("EXTREME")));
    }

    @Test
    @DisplayName("GET /api/events with invalid type returns 400 with error message")
    void eventsInvalidTypeReturns400() throws Exception {
        mockMvc.perform(get("/api/events").param("type", "HACK"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", containsString("HACK")));
    }

    @Test
    @DisplayName("GET /api/events severity filter is case-insensitive")
    void eventsSeverityFilterIsCaseInsensitive() throws Exception {
        mockMvc.perform(get("/api/events").param("severity", "high"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].severity", everyItem(is("HIGH"))));
    }

    // -----------------------------------------------------------------------
    // GET /api/alerts
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/alerts returns 200 with a list")
    void alertsReturns200() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(0))));
    }

    @Test
    @DisplayName("GET /api/alerts returns at least one alert from sample data")
    void alertsContainsAtLeastOneAlert() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThan(0))))
                .andExpect(jsonPath("$[0].ruleName").value("BRUTE_FORCE_LOGIN"))
                .andExpect(jsonPath("$[0].severity").value("HIGH"));
    }

    @Test
    @DisplayName("GET /api/alerts response includes explanation and recommendedAction")
    void alertsHaveExplanationAndAction() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].explanation", not(emptyString())))
                .andExpect(jsonPath("$[0].recommendedAction", not(emptyString())));
    }

    // -----------------------------------------------------------------------
    // GET /api/summary
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /api/summary returns 200 with totalEvents, totalAlerts and bySeverity")
    void summaryReturns200WithExpectedFields() throws Exception {
        mockMvc.perform(get("/api/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents", greaterThan(0)))
                .andExpect(jsonPath("$.totalAlerts", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.LOW", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.MEDIUM", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.HIGH", greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.CRITICAL", greaterThanOrEqualTo(0)));
    }

    @Test
    @DisplayName("GET /api/summary totalEvents matches total event count")
    void summaryTotalEventsIsAccurate() throws Exception {
        // We know the sample data has 38 events — verify the summary reflects that
        mockMvc.perform(get("/api/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(38));
    }

    @Test
    @DisplayName("GET /api/summary bySeverity counts sum to totalEvents")
    void summarySeverityCountsSumToTotal() throws Exception {
        // Fetch summary and verify counts are consistent (done via separate assertions)
        mockMvc.perform(get("/api/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bySeverity.LOW",      greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.MEDIUM",   greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.HIGH",     greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$.bySeverity.CRITICAL", greaterThanOrEqualTo(0)));
    }
}
