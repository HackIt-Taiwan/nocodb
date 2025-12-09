import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { NestMiddleware } from '@nestjs/common';
import type { AppConfig } from '~/interface/config';
import Noco from '~/Noco';

@Injectable()
export class GlobalMiddleware implements NestMiddleware {
  constructor(protected readonly config: ConfigService<AppConfig>) {}

  use(req: any, res: any, next: () => void) {
    const envPublicUrl = process.env.NC_PUBLIC_URL?.replace(/\/+$/, '');
    const forwardedHostHeader = req.headers['x-forwarded-host'];
    const forwardedProtoHeader = req.headers['x-forwarded-proto'];

    const forwardedHost = Array.isArray(forwardedHostHeader)
      ? forwardedHostHeader[0]
      : forwardedHostHeader;
    const forwardedProto = Array.isArray(forwardedProtoHeader)
      ? forwardedProtoHeader[0]
      : forwardedProtoHeader;

    const host = forwardedHost || req.get('host');
    const protocol = forwardedProto || req.protocol;
    const derivedSiteUrl = (protocol && host ? `${protocol}://${host}` : '')?.replace(/\/+$/, '');

    // Prefer explicit public URL, then config, then proxy headers/host fallback
    req.ncSiteUrl =
      envPublicUrl ||
      Noco.config?.envs?.[Noco.env]?.publicUrl ||
      Noco.config?.publicUrl ||
      derivedSiteUrl ||
      req.protocol + '://' + req.get('host');

    req.ncFullUrl = `${req.ncSiteUrl}${req.originalUrl}`;

    const dashboardPath = this.config.get('dashboardPath', {
      infer: true,
    });

    // used for playwright tests so env is not documented
    req.dashboardUrl =
      process.env.NC_DASHBOARD_URL || req.ncSiteUrl + dashboardPath;
    next();
  }
}
