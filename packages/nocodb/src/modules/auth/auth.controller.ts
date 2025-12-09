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
} from '@nestjs/common';
import { Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { extractRolesObj } from 'nocodb-sdk';
import * as ejs from 'ejs';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import { PresignedUrl } from 'src/models';
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

@Controller()
export class AuthController {
  constructor(
    protected readonly usersService: UsersService,
    protected readonly appHooksService: AppHooksService,
    protected readonly config: ConfigService<AppConfig>,
  ) {}

  private ensureSsoOnly() {
    NcError.forbidden('Sign in with SSO via Passport');
  }

  private getPassportConfig() {
    const baseUrl = process.env.PASSPORT_API_BASE_URL?.replace(/\/+$/, '');
    const apiBase = baseUrl
      ? baseUrl.endsWith('/api')
        ? baseUrl
        : `${baseUrl}/api`
      : undefined;

    return {
      apiBase,
      token: process.env.PASSPORT_API_TOKEN,
      clientId: process.env.PASSPORT_CLIENT_ID ?? '[one]outline',
    };
  }

  @Get('/auth/passport')
  @UseGuards(PublicApiLimiterGuard)
  async passportStart(@Req() req: NcRequest, @Res() res: Response) {
    const { apiBase, token, clientId } = this.getPassportConfig();
    if (!apiBase || !token) {
      NcError.forbidden('Passport SSO is not configured');
    }

    const siteUrl =
      (req as any).ncSiteUrl?.replace(/\/+$/, '') ||
      process.env.NC_PUBLIC_URL?.replace(/\/+$/, '') ||
      '';
    const redirectUri = `${siteUrl}/auth/passport/callback`;
    const dashboardPath = Noco.getConfig().dashboardPath || '/';
    const restartUri = `${siteUrl}${dashboardPath}#/signin`;

    let data: any;
    try {
      const response = await axios.post(
        `${apiBase}/services/consent/request`,
        {
          client_id: clientId,
          redirect_uri: redirectUri,
          fields: ['email', 'nickname', 'avatar_url', 'preferred_language'],
          state: req.query.state,
          restart_uri: restartUri,
        },
        {
          headers: {
            'X-API-Token': token,
          },
        },
      );
      data = response.data;
    } catch (err) {
      NcError.forbidden('Failed to initiate SSO');
    }

    if (!data?.consent_url) {
      NcError.forbidden('SSO initiation failed');
    }

    return res.redirect(data.consent_url);
  }

  @Get('/auth/passport/callback')
  @UseGuards(PublicApiLimiterGuard)
  async passportCallback(@Req() req: NcRequest, @Res() res: Response) {
    const code = req.query.code as string | undefined;
    if (!code) {
      NcError.forbidden('Missing consent code');
    }

    const { apiBase, token, clientId } = this.getPassportConfig();
    if (!apiBase || !token) {
      NcError.forbidden('Passport SSO is not configured');
    }

    let tokenData: any;
    try {
      const tokenRes = await axios.post(
        `${apiBase}/services/consent/token`,
        {
          code,
          client_id: clientId,
        },
        {
          headers: {
            'X-API-Token': token,
          },
        },
      );
      tokenData = tokenRes.data;
    } catch (err) {
      NcError.forbidden('SSO login failed');
    }

    const profile = tokenData?.user;
    if (!profile?.email || !profile?.nickname) {
      NcError.forbidden('SSO login missing required fields');
    }

    const email = String(profile.email).toLowerCase();
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

    // attach extra meta (avatar/language)
    await this.usersService.profileUpdate({
      id: user.id,
      params: {
        display_name: profile.nickname,
        avatar: profile.avatar_url ?? user.avatar,
        meta: {
          ...(user.meta ?? {}),
          preferred_language: profile.preferred_language,
        },
      },
      req,
    });

    (req as any).user = {
      ...user,
      provider: 'passport',
    };

    await this.setRefreshToken({ req, res });
    await this.usersService.login(req.user, req);

    const siteUrl =
      (req as any).ncSiteUrl?.replace(/\/+$/, '') ||
      process.env.NC_PUBLIC_URL?.replace(/\/+$/, '') ||
      '';
    const dashboardPath = Noco.getConfig().dashboardPath || '/';
    return res.redirect(`${siteUrl}${dashboardPath}`);
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
