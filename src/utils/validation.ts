import { z } from 'zod';

/**
 * Valid domain name: starts with alphanumeric, allows alphanumeric, hyphens, and
 * dots. Rejects protocols, paths, and other URL components to prevent SSRF-style
 * path confusion when the value is interpolated into API URLs.
 *
 * Accepts: example.com, sub.example.com, my-company.co.uk
 * Rejects: http://example.com, example.com/path, ../traversal
 */
export const domainSchema = z
  .string()
  .min(1)
  .max(253)
  .regex(
    /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/,
    'Domain must be a valid hostname without protocol or path (e.g., example.com)'
  );

/**
 * ISO 8601 calendar date: YYYY-MM-DD.
 * Validates structure; calendar correctness is delegated to the upstream API.
 */
export const isodateSchema = z
  .string()
  .regex(
    /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/,
    'Date must be in YYYY-MM-DD format'
  );

/**
 * CVE identifier per MITRE conventions: CVE-YYYY-NNNNN (4–7 digit sequence number).
 * Case-insensitive match; normalised to upper-case by the upstream API.
 */
export const cveIdSchema = z
  .string()
  .regex(
    /^CVE-\d{4}-\d{4,7}$/i,
    'Must be a valid CVE identifier (e.g., CVE-2024-12345)'
  );

/**
 * IP address: dotted-decimal IPv4 or colon-hex IPv6.
 * Does not validate octet ranges beyond structure; upstream API enforces semantics.
 */
export const ipAddressSchema = z
  .string()
  .min(2)
  .max(45)
  .regex(
    /^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$/,
    'Must be a valid IPv4 (e.g., 1.2.3.4) or IPv6 address'
  );

/**
 * Generic opaque identifier as returned by SecurityScorecard (UUID, slug, etc.).
 * Permits alphanumeric characters, hyphens, and underscores only to prevent
 * path-traversal when used in URL segments.
 */
export const opaqueIdSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(
    /^[a-zA-Z0-9-_]+$/,
    'ID must contain only alphanumeric characters, hyphens, and underscores'
  );
