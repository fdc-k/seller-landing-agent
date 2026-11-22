// Typed, read-only Seller API operations. No URL or arbitrary path can enter here.
// Identifiers must match the complete string.
const DECIMAL_ID = /^[1-9][0-9]{0,18}(?![\s\S])/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\s\S])/i;
const PAGE = ['limit', 'cursor', 'reverse'];
const SHOW_STATUSES = ['scheduled', 'live', 'stopped', 'ended', 'cancelled'];
const REPORT_STATUSES = ['pending', 'in_progress', 'completed', 'failed', 'cancelled'];

const operations = Object.freeze({
  listShipments: { path: '/shipments', query: PAGE },
  getShipment: { path: '/shipments/:shipment_id', ids: { shipment_id: DECIMAL_ID } },
  listShipmentItems: { path: '/shipments/:shipment_id/items', ids: { shipment_id: DECIMAL_ID }, query: PAGE },
  getShipmentItem: { path: '/shipments/:shipment_id/items/:item_id', ids: { shipment_id: DECIMAL_ID, item_id: DECIMAL_ID } },
  listOrders: { path: '/orders', query: PAGE },
  getOrder: { path: '/orders/:order_id', ids: { order_id: DECIMAL_ID } },
  listOrderItems: { path: '/orders/:order_id/items', ids: { order_id: DECIMAL_ID }, query: PAGE },
  getOrderItem: { path: '/orders/:order_id/items/:item_id', ids: { order_id: DECIMAL_ID, item_id: DECIMAL_ID } },
  listShows: { path: '/shows', query: ['status', ...PAGE], statuses: SHOW_STATUSES },
  getShow: { path: '/shows/:show_id', ids: { show_id: UUID } },
  getShowAnalytics: { path: '/analytics/shows/:show_id', ids: { show_id: UUID } },
  getMe: { path: '/users/me' },
  listReports: { path: '/reports', query: ['status', ...PAGE], statuses: REPORT_STATUSES },
  getReport: { path: '/reports/:report_id', ids: { report_id: UUID } },
});

function invalid(message) {
  throw Object.assign(new Error(message),{code:'INVALID_OPERATION'});
}

export function buildOperation(operation, args = {}) {
  if (typeof operation !== 'string' || !Object.hasOwn(operations, operation)) {
    invalid('Unknown read-only Seller API operation');
  }
  if (!args || typeof args !== 'object' || Array.isArray(args)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(args))) {
    invalid('Operation arguments must be a plain object');
  }
  const spec = operations[operation];
  const allowed = new Set([...Object.keys(spec.ids ?? {}), ...(spec.query ?? [])]);
  for (const key of Reflect.ownKeys(args)) {
    if (typeof key !== 'string' || !allowed.has(key)) invalid('Unknown operation argument');
    const descriptor = Object.getOwnPropertyDescriptor(args, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid('Operation arguments must contain plain values');
  }

  let path = spec.path;
  for (const [key, pattern] of Object.entries(spec.ids ?? {})) {
    if (!Object.hasOwn(args, key) || typeof args[key] !== 'string' || !pattern.test(args[key])) {
      invalid(`Invalid ${key}: a valid ID string is required`);
    }
    path = path.replace(`:${key}`, args[key]);
  }
  const query = new URLSearchParams();
  for (const key of spec.query ?? []) {
    if (!Object.hasOwn(args, key)) continue;
    const value = args[key];
    if (key === 'limit' && (typeof value!=='number' || !Number.isInteger(value) || value < 1 || value > 50)) {
      invalid('Invalid limit: expected an integer from 1 to 50');
    }
    if (key === 'cursor' && (typeof value !== 'string' || Array.from(value).length > 2048)) {
      invalid('Invalid cursor: expected a string of at most 2048 characters');
    }
    if (key === 'reverse' && typeof value !== 'boolean') invalid('Invalid reverse: expected a boolean');
    if (key === 'status' && (typeof value!=='string'||!spec.statuses?.includes(value))) invalid('Invalid status for this operation');
    query.set(key, String(value));
  }
  const encoded = query.toString();
  return { method: 'GET', path: `${path}${encoded ? `?${encoded}` : ''}` };
}
