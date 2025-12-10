import { Injectable } from '@nestjs/common';
import NcToolGui from 'nc-lib-gui';
import { ConfigService } from '@nestjs/config';
import type { NestMiddleware } from '@nestjs/common';
import type { AppConfig } from '~/interface/config';

@Injectable()
export class GuiMiddleware implements NestMiddleware {
  constructor(private configService: ConfigService<AppConfig>) {}

  use(req: any, res: any, next: () => void) {
    const dashboardPath = this.configService.get('dashboardPath', {
      infer: true,
    });

    const pathname: string = req.path || '';
    const isDashboardRoot =
      pathname === dashboardPath ||
      (dashboardPath !== '/' && pathname === `${dashboardPath}/`) ||
      (dashboardPath === '/' && pathname === '/');

    if (isDashboardRoot) {
      const hasRefreshToken =
        !!req.cookies?.refresh_token || !!req.signedCookies?.refresh_token;

      if (!hasRefreshToken) {
        const state = req.query?.state;
        const stateSuffix =
          typeof state === 'string' && state
            ? `?state=${encodeURIComponent(state)}`
            : '';
        return res.redirect(`/auth/passport${stateSuffix}`);
      }
    }

    NcToolGui.expressMiddleware(dashboardPath)(req, res, next);
  }
}
