import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { JwtGuard } from 'src/auth/guard';

@Controller('users')
export class UserController {
  @Get('me')
  @UseGuards(JwtGuard)
  getMe(@Req() req: Request) {
    console.log(req);
    return 'user info';
  }
}
