# AtlaSent Java SDK

Java 17+ SDK for the [AtlaSent](https://atlasent.io) execution-time authorization API.

## Maven coordinates

```xml
<dependency>
  <groupId>io.atlasent</groupId>
  <artifactId>atlasent-sdk</artifactId>
  <version>1.0.0-BETA</version>
</dependency>
```

## Quick start

```java
import io.atlasent.sdk.AtlaSentClient;
import io.atlasent.sdk.AtlaSentClientOptions;
import io.atlasent.sdk.model.EvaluateRequest;
import io.atlasent.sdk.model.EvaluateResponse;
import java.util.Map;

AtlaSentClient client = new AtlaSentClient(
    AtlaSentClientOptions.builder()
        .apiKey("ask_live_...")
        .build()
);

EvaluateResponse resp = client.evaluate(
    new EvaluateRequest("production.deploy", "user_abc123", Map.of("environment", "prod"))
);

if (!resp.isAllowed()) {
    throw new SecurityException("Blocked: " + resp.getDecision());
}
// execute the protected action
```

## Method reference

| Method | Description | Required scope |
|---|---|---|
| `evaluate(EvaluateRequest)` | Evaluate an authorization request; returns allow / deny / hold | `evaluate:write` |
| `verifyPermit(VerifyPermitRequest)` | Verify and consume a single-use permit token | `verify:execute` |
| `listRbacRules(orgId, options)` | List dynamic RBAC rules for an org | `rbac:read` |
| `createRbacRule(CreateRbacRuleRequest)` | Create a dynamic RBAC rule | `rbac:write` |
| `deleteRbacRule(id)` | Delete a dynamic RBAC rule by ID | `rbac:write` |
| `getApprovalSla(orgId, days)` | Fetch approval SLA statistics | `audit:read` |
| `AtlaSentClient.submitEnterpriseInquiry(baseUrl, request)` | Submit an enterprise inquiry (no API key required) | none |

## Fail-closed guarantee

A DENY decision is returned as a normal `EvaluateResponse` (never thrown).
`AtlaSentException` is thrown only on network errors, timeouts, non-2xx HTTP
responses, or malformed JSON.

Always gate on `response.isAllowed()` (or `verifyResponse.isValid()`) before
executing the protected action.

## Configuration

```java
AtlaSentClientOptions options = AtlaSentClientOptions.builder()
    .apiKey("ask_live_...")           // required
    .baseUrl("https://api.atlasent.io") // default
    .timeoutSeconds(30)               // default
    .build();
```

## Requirements

- Java 17 or later
- Jackson Databind 2.17+
