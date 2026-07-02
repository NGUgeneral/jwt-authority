# JWT Authority Service (`jwt-authority`)

An isolated cryptographic signing utility responsible for issuing, updating, and evaluating stateless cryptographically secure authorization contexts across the `headsntails` platform. (But there is no reason you can't just use it as standlaone service which will work as is without issues).

All the further description explained from the perspective of it being part of [`headsntails`](https://github.com/NGUgeneral/headsntails-platform).

## Security & Access Boundary Structure
To defend system integrity, the service isolates its token actions:
1. **The Public Ingress Path:** External client microservices can reach `/api/v1/auth/refresh` through the public Nginx gateway to acquire updated tokens using a secure asymmetric secret rotation pattern.
2. **The Guarded Path:** Core endpoints like verification checkers (`/api/v1/auth/validate`) are blocked from the internet entirely. The `headsntails-core` hits these validation endpoints using internal container sockets, ensuring signing keys never traverse public networks.

## API Routing Contract (v0.1)

### Public Client Endpoints
* **`POST /api/v1/refresh`** — Validates rotating signature claims and issues freshly signed high-entropy access context payloads.

### Private Microservice Endpoints
* **`POST /api/v1/validate`** — Decodes cryptographic frames and reports explicit access metadata parameters back to requesting internal engines.
* **`GET /api/v1/health`** — Static infrastructure status diagnostic log.

## Configuration Parameters
* `PORT`: System binding execution socket address.
* `JWT_SECRET_KEY`: High-entropy master key variable used for token cryptographic operations. Must remain strict across matching platform configurations.
