# Payload Styles and Destinations

## Destination Requirements

Each style requires its own destination. A destination will be added for each payload style and will be configured in the following steps.

## Payload Differences

Snapshot payloads are larger and contain more data about the object, while thin payloads are smaller, delivering only the essential information.

## Examples

Example event: `setup_intent.created`

### Snapshot Payload

{
"id": "evt_abc123xyz",
"object": "event",
"api_version": "2019-02-19",
"created": 1686089970,
"data": {… 1 item},
"livemode": false,
"pending_webhooks": 0,
"request": {… 2 items},
"type": "setup_intent.created",
}

### Thin Payload

{
"id": "evt_abc123xyz",
"object": "v2.core.event",
"type": "v1.billing.meter.error_report_triggered",
"livemode": false,
"created": "2024-09-17T06:20:52.246Z",
"related_object": {
"id": "mtr_test_123456789",
"type": "billing.meter",
"url": "/v1/billing/meters/mtr_test_123456789",
}

## Important Note

Since snapshot and thin payloads are different, your event handler code will need to be written to handle both payload styles.
It's important that you understand the differences between these payload styles before you configure your destinations.
