import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { extractRolesObj, IconType } from 'nocodb-sdk';
import * as ejs from 'ejs';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { PresignedUrl } from 'src/models';
import { User } from '~/models';
import type { AppConfig } from '~/interface/config';

import { UsersService } from '~/services/users/users.service';
import { AppHooksService } from '~/services/app-hooks/app-hooks.service';

import { GlobalGuard } from '~/guards/global/global.guard';
import { NcError } from '~/helpers/catchError';
import { Acl } from '~/middlewares/extract-ids/extract-ids.middleware';
import { MetaApiLimiterGuard } from '~/guards/meta-api-limiter.guard';
import { PublicApiLimiterGuard } from '~/guards/public-api-limiter.guard';
import { NcRequest } from '~/interface/config';
import Noco from '~/Noco';

const PASSPORT_STATE_COOKIE = 'nc_passport_state';
const PASSPORT_PKCE_COOKIE = 'nc_passport_pkce';
const PASSPORT_RETURN_TO_COOKIE = 'nc_passport_return_to';
const PASSPORT_AUTH_COOKIE_MAX_AGE_MS = 10 * 60 * 1000;

@Controller()
export class AuthController {
  constructor(
    protected readonly usersService: UsersService,
    protected readonly appHooksService: AppHooksService,
    protected readonly config: ConfigService<AppConfig>,
  ) {}

  private readonly logger = new Logger(AuthController.name);

  private ensureSsoOnly() {
    NcError.forbidden('Sign in with SSO via Passport');
  }

  private resolveSiteUrl(req: NcRequest) {
    const envUrl = process.env.NC_PUBLIC_URL?.replace(/\/+$/, '');
    const reqUrl = (req as any).ncSiteUrl?.replace(/\/+$/, '');
    return envUrl || reqUrl || '';
  }

  private resolveRedirectUri(req: NcRequest) {
    const override = process.env.PASSPORT_REDIRECT_URI?.trim();
    if (override) {
      return override;
    }

    const siteUrl = this.resolveSiteUrl(req);
    return `${siteUrl}/auth/passport/callback`;
  }

  private formatAxiosError(err: any): string | undefined {
    if (axios.isAxiosError(err)) {
      const status = err.response?.status;
      let body: string | undefined;

      try {
        if (typeof err.response?.data === 'string') {
          body = err.response.data;
        } else if (err.response?.data) {
          body = JSON.stringify(err.response.data);
        }

        if (body?.length > 500) {
          body = `${body.slice(0, 500)}...`;
        }
      } catch {
        // ignore JSON stringify failures
      }

      const parts = [];
      if (status) parts.push(`status ${status}`);
      if (err.code) parts.push(`code ${err.code}`);
      if (body) parts.push(`body ${body}`);
      return parts.join(' | ');
    }

    if (err instanceof Error) {
      return err.message;
    }

    return undefined;
  }

  private getPassportConfig() {
    const baseUrl = process.env.PASSPORT_API_BASE_URL?.replace(/\/+$/, '');
    const oidcIssuer = process.env.PASSPORT_OIDC_ISSUER?.replace(/\/+$/, '');
    let oidcBase: string | undefined;
    if (oidcIssuer) {
      oidcBase = oidcIssuer;
    } else if (baseUrl) {
      if (baseUrl.endsWith('/api/oidc')) {
        oidcBase = baseUrl;
      } else if (baseUrl.endsWith('/api')) {
        oidcBase = `${baseUrl}/oidc`;
      } else {
        oidcBase = `${baseUrl}/api/oidc`;
      }
    }

    const scopesRaw =
      process.env.PASSPORT_OIDC_SCOPES || 'openid,profile,email';
    const scopes = scopesRaw
      .split(/[,\s]+/)
      .map((scope) => scope.trim())
      .filter(Boolean);
    if (!scopes.includes('openid')) {
      scopes.unshift('openid');
    }

    return {
      oidcBase,
      clientId: process.env.PASSPORT_CLIENT_ID,
      clientSecret: process.env.PASSPORT_CLIENT_SECRET,
      scopes,
    };
  }

  private passportCookieOptions() {
    return {
      httpOnly: true,
      sameSite: 'lax' as const,
      maxAge: PASSPORT_AUTH_COOKIE_MAX_AGE_MS,
      domain: process.env.NC_BASE_HOST_NAME || undefined,
    };
  }

  private readCookie(req: NcRequest, name: string) {
    return req.cookies?.[name] || req.signedCookies?.[name];
  }

  private clearPassportCookies(res: Response) {
    const domain = process.env.NC_BASE_HOST_NAME || undefined;
    res.clearCookie(PASSPORT_STATE_COOKIE, { domain });
    res.clearCookie(PASSPORT_PKCE_COOKIE, { domain });
    res.clearCookie(PASSPORT_RETURN_TO_COOKIE, { domain });
  }

  private base64Url(input: Buffer) {
    return input
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  private generateState() {
    return this.base64Url(crypto.randomBytes(16));
  }

  private generatePkcePair() {
    const verifier = this.base64Url(crypto.randomBytes(32));
    const challenge = this.base64Url(
      crypto.createHash('sha256').update(verifier).digest(),
    );
    return { verifier, challenge };
  }

  private sanitizeReturnTo(value: string | undefined) {
    if (!value) return null;
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
      return trimmed;
    }
    return null;
  }

  private redirectPassportError(
    req: NcRequest,
    res: Response,
    error: string,
    description?: string,
  ) {
    const siteUrl = this.resolveSiteUrl(req);
    const dashboardPath = Noco.getConfig().dashboardPath || '/';
    const basePath = `${siteUrl}${dashboardPath}`.replace(/\/+$/, '');
    const baseRedirect = basePath || '/';
    const params = new URLSearchParams();
    params.set('hash-redirect', '/signin');
    const hashParams = new URLSearchParams();
    if (error) {
      hashParams.set('passport_error', error);
    }
    if (description) {
      hashParams.set('passport_error_description', description);
    }
    const returnTo = this.sanitizeReturnTo(
      this.readCookie(req, PASSPORT_RETURN_TO_COOKIE),
    );
    if (returnTo) {
      hashParams.set('continueAfterSignIn', returnTo);
    }
    const hashQuery = hashParams.toString();
    if (hashQuery) {
      params.set('hash-query-params', encodeURIComponent(hashQuery));
    }
    const suffix = params.toString();
    return res.redirect(`${baseRedirect}${suffix ? `?${suffix}` : ''}`);
  }

  @Get('/auth/passport')
  @UseGuards(PublicApiLimiterGuard)
  async passportStart(@Req() req: NcRequest, @Res() res: Response) {
    const { oidcBase, clientId, clientSecret, scopes } =
      this.getPassportConfig();
    if (!oidcBase || !clientId) {
      NcError.forbidden('Passport SSO is not configured');
    }

    const redirectUri = this.resolveRedirectUri(req);
    const state = this.generateState();
    const cookieOptions = this.passportCookieOptions();
    res.cookie(PASSPORT_STATE_COOKIE, state, cookieOptions);

    const returnTo = this.sanitizeReturnTo(
      typeof req.query.state === 'string' ? req.query.state : undefined,
    );
    if (returnTo) {
      res.cookie(PASSPORT_RETURN_TO_COOKIE, returnTo, cookieOptions);
    }

    let codeChallenge: string | undefined;
    if (!clientSecret) {
      const { verifier, challenge } = this.generatePkcePair();
      res.cookie(PASSPORT_PKCE_COOKIE, verifier, cookieOptions);
      codeChallenge = challenge;
    }

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state,
    } as Record<string, string>);

    if (codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }

    return res.redirect(`${oidcBase}/authorize?${params.toString()}`);
  }

  @Get('/auth/passport/callback')
  @UseGuards(PublicApiLimiterGuard)
  async passportCallback(@Req() req: NcRequest, @Res() res: Response) {
    const { oidcBase, clientId, clientSecret } = this.getPassportConfig();
    if (!oidcBase || !clientId) {
      NcError.forbidden('Passport SSO is not configured');
    }

    const stateParam = req.query.state as string | undefined;
    const cookieState = this.readCookie(req, PASSPORT_STATE_COOKIE);
    if (!stateParam || !cookieState || stateParam !== cookieState) {
      this.clearPassportCookies(res);
      return this.redirectPassportError(req, res, 'state_mismatch');
    }

    const error = req.query.error as string | undefined;
    const errorDescription = req.query.error_description as string | undefined;
    if (error) {
      this.logger.warn(
        `Passport OIDC authorization failed: ${error}${
          errorDescription ? ` (${errorDescription})` : ''
        }`,
      );
      this.clearPassportCookies(res);
      return this.redirectPassportError(req, res, error, errorDescription);
    }

    const code = req.query.code as string | undefined;
    if (!code) {
      this.clearPassportCookies(res);
      return this.redirectPassportError(req, res, 'missing_code');
    }

    const redirectUri = this.resolveRedirectUri(req);
    const codeVerifier = this.readCookie(req, PASSPORT_PKCE_COOKIE);
    if (!clientSecret && !codeVerifier) {
      this.clearPassportCookies(res);
      NcError.forbidden('SSO login missing PKCE verifier');
    }

    let tokenData: any;
    try {
      const body = new URLSearchParams();
      body.set('grant_type', 'authorization_code');
      body.set('code', code);
      body.set('client_id', clientId);
      body.set('redirect_uri', redirectUri);
      if (clientSecret) {
        body.set('client_secret', clientSecret);
      }
      if (codeVerifier) {
        body.set('code_verifier', codeVerifier);
      }

      const tokenRes = await axios.post(`${oidcBase}/token`, body.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });
      tokenData = tokenRes.data;
    } catch (err) {
      const detail = this.formatAxiosError(err);
      this.logger.error(
        `Passport OIDC token exchange failed${detail ? `: ${detail}` : ''}`,
      );
      this.clearPassportCookies(res);
      NcError.forbidden(
        detail ? `SSO login failed (${detail})` : 'SSO login failed',
      );
    }

    const accessToken = tokenData?.access_token;
    if (!accessToken) {
      this.clearPassportCookies(res);
      NcError.forbidden('SSO login missing access token');
    }

    let profile: any = {};
    try {
      const userinfoRes = await axios.get(`${oidcBase}/userinfo`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      profile = userinfoRes.data || {};
    } catch (err) {
      const detail = this.formatAxiosError(err);
      this.logger.error(
        `Passport userinfo request failed${detail ? `: ${detail}` : ''}`,
      );
      this.clearPassportCookies(res);
      NcError.forbidden(
        detail ? `SSO login failed (${detail})` : 'SSO login failed',
      );
    }

    const rawEmail = profile.email;
    const email = rawEmail ? String(rawEmail).toLowerCase() : '';
    const displayName =
      profile.nickname ||
      profile.preferred_username ||
      profile.name ||
      email.split('@')[0];
    if (!email || !displayName) {
      this.clearPassportCookies(res);
      NcError.forbidden('SSO login missing required fields');
    }

    let user = await User.getByEmail(email);

    if (!user) {
      const salt = await bcrypt.genSalt(10);
      user = await this.usersService.registerNewUserIfAllowed({
        email,
        salt,
        password: '',
        email_verification_token: null,
        req,
      } as any);
    }

    // attach extra meta (avatar / language) and keep it in sync on every login
    // this is best‑effort only – if the underlying schema is missing optional
    // columns, avoid breaking the whole login flow
    try {
      const currentMeta = (user.meta ?? {}) as any;
      const avatarUrl = profile.picture || currentMeta.icon || user.avatar;
      const locale =
        typeof profile.locale === 'string' ? profile.locale : undefined;

      const updatedMeta = {
        ...currentMeta,
        // always prefer latest avatar from Passport
        icon: avatarUrl,
        iconType: avatarUrl ? IconType.IMAGE : currentMeta.iconType,
        preferred_language: locale ?? currentMeta.preferred_language,
      };

      await this.usersService.profileUpdate({
        id: user.id,
        params: {
          display_name: displayName,
          avatar: avatarUrl,
          meta: updatedMeta,
        },
        req,
      });
    } catch (err) {
      const detail = this.formatAxiosError(err);
      this.logger.error(
        `Passport SSO profile update failed${
          detail ? `: ${detail}` : ''
        }`,
      );
      // continue login even if profile decoration fails
    }

    (req as any).user = {
      ...user,
      provider: 'passport',
    };

    await this.setRefreshToken({ req, res });
    await this.usersService.login(req.user, req);

    const siteUrl = this.resolveSiteUrl(req);
    const dashboardPath = Noco.getConfig().dashboardPath || '/';
    const returnTo = this.sanitizeReturnTo(
      this.readCookie(req, PASSPORT_RETURN_TO_COOKIE),
    );
    this.clearPassportCookies(res);

    const baseRedirect = `${siteUrl}${dashboardPath}`;
    if (returnTo) {
      const separator = baseRedirect.includes('?') ? '&' : '?';
      return res.redirect(
        `${baseRedirect}${separator}continueAfterSignIn=${encodeURIComponent(
          returnTo,
        )}`,
      );
    }
    return res.redirect(baseRedirect);
  }

  @Post([
    '/auth/user/signup',
    '/api/v1/db/auth/user/signup',
    '/api/v1/auth/user/signup',
    '/api/v2/auth/user/signup',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async signup(@Req() req: NcRequest, @Res() res: Response): Promise<any> {
    this.ensureSsoOnly();
    res.json({ msg: 'Please sign in with SSO' });
  }

  @Post([
    '/auth/token/refresh',
    '/api/v1/db/auth/token/refresh',
    '/api/v1/auth/token/refresh',
    '/api/v2/auth/token/refresh',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async refreshToken(
    @Req() req: NcRequest,
    @Res() res: Response,
  ): Promise<any> {
    res.json(
      await this.usersService.refreshToken({
        body: req.body,
        req,
        res,
      }),
    );
  }

  @Post([
    '/auth/user/signin',
    '/api/v1/db/auth/user/signin',
    '/api/v1/auth/user/signin',
    '/api/v2/auth/user/signin',
  ])
  @UseGuards(PublicApiLimiterGuard, AuthGuard('local'))
  @HttpCode(200)
  async signin(@Req() req: NcRequest, @Res() res: Response) {
    this.ensureSsoOnly();
    res.json({ msg: 'Please sign in with SSO' });
  }

  @UseGuards(GlobalGuard)
  @Post(['/api/v1/auth/user/signout', '/api/v2/auth/user/signout'])
  @HttpCode(200)
  async signOut(@Req() req: NcRequest, @Res() res: Response): Promise<any> {
    if (!(req as any).isAuthenticated?.()) {
      NcError.forbidden('Not allowed');
    }
    res.json(
      await this.usersService.signOut({
        req,
        res,
      }),
    );
  }

  @Post(`/auth/google/genTokenByCode`)
  @HttpCode(200)
  @UseGuards(PublicApiLimiterGuard, AuthGuard('google'))
  async googleSignin(@Req() req: NcRequest, @Res() res: Response) {
    await this.setRefreshToken({ req, res });
    res.json(await this.usersService.login(req.user, req));
  }

  @Get('/auth/google')
  @UseGuards(PublicApiLimiterGuard, AuthGuard('google'))
  googleAuthenticate() {
    // google strategy will take care the request
  }

  @Get([
    '/auth/user/me',
    '/api/v1/db/auth/user/me',
    '/api/v1/auth/user/me',
    '/api/v2/auth/user/me',
  ])
  @UseGuards(MetaApiLimiterGuard, GlobalGuard)
  async me(@Req() req: NcRequest) {
    const user = {
      ...req.user,
      roles: extractRolesObj(req.user.roles),
      workspace_roles: extractRolesObj(req.user.workspace_roles),
      base_roles: extractRolesObj(req.user.base_roles),
    };

    await PresignedUrl.signMetaIconImage(user);

    return user;
  }

  @Post([
    '/user/password/change',
    '/api/v1/db/auth/password/change',
    '/api/v1/auth/password/change',
    '/api/v2/auth/password/change',
  ])
  @UseGuards(MetaApiLimiterGuard, GlobalGuard)
  @Acl('passwordChange', {
    scope: 'org',
  })
  @HttpCode(200)
  async passwordChange(@Req() req: NcRequest, @Res() res): Promise<any> {
    this.ensureSsoOnly();
    res.json({ msg: 'Password change is disabled for SSO accounts' });
  }

  @Post([
    '/auth/password/forgot',
    '/api/v1/db/auth/password/forgot',
    '/api/v1/auth/password/forgot',
    '/api/v2/auth/password/forgot',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async passwordForgot(@Req() req: NcRequest): Promise<any> {
    this.ensureSsoOnly();
    return { msg: 'Password reset is disabled for SSO accounts' };
  }

  @Post([
    '/auth/token/validate/:tokenId',
    '/api/v1/db/auth/token/validate/:tokenId',
    '/api/v1/auth/token/validate/:tokenId',
    '/api/v2/auth/token/validate/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async tokenValidate(@Param('tokenId') tokenId: string): Promise<any> {
    this.ensureSsoOnly();
    return { msg: 'Token validation is disabled for SSO accounts' };
  }

  @Post([
    '/auth/password/reset/:tokenId',
    '/api/v1/db/auth/password/reset/:tokenId',
    '/api/v1/auth/password/reset/:tokenId',
    '/api/v2/auth/password/reset/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async passwordReset(
    @Req() req: NcRequest,
    @Param('tokenId') tokenId: string,
    @Body() body: any,
  ): Promise<any> {
    this.ensureSsoOnly();
    return { msg: 'Password reset is disabled for SSO accounts' };
  }

  @Post([
    '/api/v1/db/auth/email/validate/:tokenId',
    '/api/v1/auth/email/validate/:tokenId',
    '/api/v2/auth/email/validate/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async emailVerification(
    @Req() req: NcRequest,
    @Param('tokenId') tokenId: string,
  ): Promise<any> {
    this.ensureSsoOnly();
    return { msg: 'Email verification is disabled for SSO accounts' };
  }

  @Get([
    '/api/v1/db/auth/password/reset/:tokenId',
    '/api/v2/db/auth/password/reset/:tokenId',
    '/auth/password/reset/:tokenId',
  ])
  @UseGuards(PublicApiLimiterGuard)
  async renderPasswordReset(
    @Req() req: NcRequest,
    @Res() res: Response,
    @Param('tokenId') tokenId: string,
  ): Promise<any> {
    this.ensureSsoOnly();
    return res
      .status(403)
      .json({ msg: 'Password reset is disabled for SSO accounts' });
  }

  async setRefreshToken({ res, req }) {
    await this.usersService.setRefreshToken({ res, req });
  }
}
