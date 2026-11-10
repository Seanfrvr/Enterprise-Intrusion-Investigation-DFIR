# Command and Control

## Objective

Assess whether a compromised host communicated with external or internal infrastructure in a manner consistent with remote control.

## Telemetry

- Sysmon Event ID 3 network connections, if enabled.
- EDR network events and process-to-connection relationships.
- DNS resolver logs.
- Proxy and secure web gateway logs.
- Firewall and network-flow records.
- Host proxy and WinHTTP configuration.
- Scheduled tasks or services that may initiate recurring connections.

## Analysis method

1. Identify the process responsible for the connection.
2. Record destination address, port, protocol, DNS name and time.
3. Review connection frequency, duration, volume and periodicity.
4. Compare destination and protocol with approved business services.
5. Correlate DNS, proxy, firewall and endpoint records.
6. Determine whether the connection succeeded and whether meaningful data transfer occurred.

## Proxy configuration

A host-level proxy change may affect outbound routing, but configuration alone does not prove a successful connection or command-and-control session. Confirm actual network activity and process context.

## Detection opportunities

Prioritise rare process-to-destination pairs, unexpected outbound connections from server processes, newly configured proxies, unusual periodic beacon-like patterns and connections to destinations inconsistent with the host's role.

## Reporting

Separate observed configuration, attempted connection, successful connection and confirmed command exchange. These are different evidentiary claims.