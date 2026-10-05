/**
 * TypeScript Type Definitions for ShieldCaptcha Enterprise SDK
 */

export interface ShieldCaptchaOptions {
  /** ShieldCaptcha public site key (pub_shield_...) */
  siteKey?: string;
  /** ShieldCaptcha private secret key (sec_shield_...) */
  secretKey?: string;
  /** Base URL of ShieldCaptcha engine (default: https://shield-captcha.vercel.app or local) */
  apiUrl?: string;
  /** Timeout in milliseconds (default: 5000) */
  timeout?: number;
}

export interface VerifyParams {
  /** Single-use pass token from client widget */
  token: string;
  /** Client IP address for risk scoring */
  remoteIp?: string;
}

export interface VerifyResult {
  success: boolean;
  score?: number;
  mode?: string;
  challenge_ts?: string;
  token_id?: string;
  authorized?: boolean;
  error?: string;
  message?: string;
  details?: any;
}

export interface MiddlewareOptions {
  minScore?: number;
  tokenField?: string;
}

export class ShieldCaptcha {
  siteKey: string;
  secretKey: string;
  apiUrl: string;
  timeout: number;

  constructor(options?: ShieldCaptchaOptions);

  verify(params: VerifyParams): Promise<VerifyResult>;

  middleware(options?: MiddlewareOptions): (req: any, res: any, next: (err?: any) => void) => Promise<void>;

  getClientScriptUrl(): string;
}

export function verifyToken(token: string, secretKey?: string, apiUrl?: string): Promise<VerifyResult>;

export const ShieldCaptchaClient: {
  render(target: HTMLElement | string, options?: any): any;
};
