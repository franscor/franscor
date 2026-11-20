export const Codes = {
  MALFORMED: 'FSP-1000',
  UNSUPPORTED_VERSION: 'FSP-1001',
  TOO_LARGE: 'FSP-1002',
  BAD_SIGNATURE: 'FSP-1100',
  ID_MISMATCH: 'FSP-1101',
  STALE: 'FSP-1102',
  BAD_NONCE: 'FSP-1103',
  NOT_REGISTERED: 'FSP-1104',
  REVOKED: 'FSP-1105',
  OFFLINE: 'FSP-1200',
  DENIED: 'FSP-1201',
  ENCRYPTION_REQUIRED: 'FSP-1203',
  PASSPORT_INVALID: 'FSP-1106',
  PASSPORT_EXPIRED: 'FSP-1107',
  PASSPORT_REVOKED: 'FSP-1108',
  PERMIT_INVALID: 'FSP-1109',
  PERMIT_EXPIRED: 'FSP-1110',
  PERMIT_REVOKED: 'FSP-1111',
  PERMIT_DENIED: 'FSP-1112',
  UNKNOWN_CAPABILITY: 'FSP-1202',
  RATE_LIMITED: 'FSP-1300',
  HANDLER_FAILED: 'FSP-1400',
  TIMEOUT: 'FSP-1401',
  APPROVAL_REJECTED: 'FSP-1402',
} as const;

export class FSPError extends Error {
  override name = 'FSPError';
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
  }
  toBody(): { code: string; message: string } {
    return { code: this.code, message: this.message.replace(/^FSP-\d{4}: /, '') };
  }
}

export type TaskStatus = 'completed' | 'failed' | 'rejected' | 'approval_rejected' | 'timeout' | 'cancelled';

export class TaskError extends FSPError {
  override name = 'TaskError';
  constructor(readonly status: TaskStatus, code: string, message: string, readonly taskId = '') {
    super(code, message);
  }
}
