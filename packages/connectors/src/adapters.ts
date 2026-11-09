import type { RequestBody } from "@dip/authorization";
import {
  ConnectorValidationError,
  idOf,
  requireAmount,
  requireString,
  type ConnectorDefinition,
} from "./contract.js";

/** Payments: a transfer to a payee account for the authorized amount. */
export const paymentsCreate: ConnectorDefinition = {
  id: "payments",
  operation: "payment.create",
  build(request: RequestBody) {
    const amount = requireAmount(request);
    const payee = requireString(request.parameters, "payeeAccount");
    return {
      method: "POST",
      url: "https://payments.example.invalid/v1/transfers",
      headers: {},
      body: {
        payee,
        amountMinor: amount.minor,
        currency: amount.currency,
        reference: request.requestId,
      },
    };
  },
  reference: idOf,
};

/** Refunds: reverse part or all of an earlier payment, for the authorized amount. */
export const refundsCreate: ConnectorDefinition = {
  id: "refunds",
  operation: "refund.create",
  build(request: RequestBody) {
    const amount = requireAmount(request);
    const payment = requireString(request.parameters, "paymentExternalRef");
    return {
      method: "POST",
      url: "https://payments.example.invalid/v1/refunds",
      headers: {},
      body: {
        payment,
        amountMinor: amount.minor,
        currency: amount.currency,
        reference: request.requestId,
      },
    };
  },
  reference: idOf,
};

/** Vendor payouts: pay a registered vendor for the authorized amount. */
export const payoutsCreate: ConnectorDefinition = {
  id: "vendor-payouts",
  operation: "payout.create",
  build(request: RequestBody) {
    const amount = requireAmount(request);
    const vendorId = requireString(request.parameters, "vendorId");
    return {
      method: "POST",
      url: "https://payouts.example.invalid/v1/payouts",
      headers: {},
      body: {
        vendorId,
        amountMinor: amount.minor,
        currency: amount.currency,
        reference: request.requestId,
      },
    };
  },
  reference: idOf,
};

/** ERP: post a document such as a purchase order or journal entry. */
export const erpPost: ConnectorDefinition = {
  id: "erp",
  operation: "erp.post",
  build(request: RequestBody) {
    const documentType = requireString(request.parameters, "documentType");
    const documentId = requireString(request.parameters, "documentId");
    if (!/^(PURCHASE_ORDER|JOURNAL_ENTRY|INVOICE)$/.test(documentType)) {
      throw new ConnectorValidationError("INVALID_PARAMETERS", "unsupported documentType");
    }
    return {
      method: "POST",
      url: "https://erp.example.invalid/v1/documents",
      headers: {},
      body: { documentType, documentId, amount: request.amount, reference: request.requestId },
    };
  },
  reference: idOf,
};

/** CRM: update fields on a record. Field values must be strings or integers. */
export const crmUpdate: ConnectorDefinition = {
  id: "crm",
  operation: "crm.update",
  build(request: RequestBody) {
    const objectType = requireString(request.parameters, "objectType");
    const objectId = requireString(request.parameters, "objectId");
    const fields = request.parameters.fields;
    if (typeof fields !== "object" || fields === null || Array.isArray(fields)) {
      throw new ConnectorValidationError("INVALID_PARAMETERS", "fields must be an object");
    }
    for (const v of Object.values(fields)) {
      if (typeof v !== "string" && typeof v !== "number") {
        throw new ConnectorValidationError(
          "INVALID_PARAMETERS",
          "field values must be strings or integers",
        );
      }
    }
    return {
      method: "PATCH",
      url: `https://crm.example.invalid/v1/${encodeURIComponent(objectType)}/${encodeURIComponent(objectId)}`,
      headers: {},
      body: fields,
    };
  },
  reference: idOf,
};

/**
 * Generic HTTP action. The URL must be HTTPS and its host must be on the
 * allowlist fixed at construction. Allowed methods are POST, PUT and PATCH.
 */
export function genericHttpAction(allowedHosts: readonly string[]): ConnectorDefinition {
  const hosts = new Set(allowedHosts.map((h) => h.toLowerCase()));
  return {
    id: "generic-http",
    operation: "http.action",
    build(request: RequestBody) {
      const method = requireString(request.parameters, "method");
      if (method !== "POST" && method !== "PUT" && method !== "PATCH") {
        throw new ConnectorValidationError(
          "INVALID_PARAMETERS",
          "method must be POST, PUT or PATCH",
        );
      }
      const rawUrl = requireString(request.parameters, "url");
      let url: URL;
      try {
        url = new URL(rawUrl);
      } catch {
        throw new ConnectorValidationError("INVALID_PARAMETERS", "url is not valid");
      }
      if (url.protocol !== "https:")
        throw new ConnectorValidationError("URL_NOT_HTTPS", "only https is allowed");
      if (!hosts.has(url.hostname.toLowerCase()))
        throw new ConnectorValidationError("HOST_NOT_ALLOWED", "host is not on the allowlist");
      return { method, url: url.toString(), headers: {}, body: request.parameters.payload ?? null };
    },
    reference: idOf,
  };
}
