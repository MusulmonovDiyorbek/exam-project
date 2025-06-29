import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtModule } from '@nestjs/jwt';
import { RolesGuard } from './guard/roles.guard';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './guard/jwt-auth.guard';


@Module({
  imports: [JwtModule.register({
    secret: process.env.JWT_ACCESS_SECRET,
    signOptions: { expiresIn: '1d' }, 
  }),UsersModule],
  controllers: [AuthController,],
  providers: [AuthService, JwtStrategy,],
  exports: [AuthService,JwtModule]
})
export class AuthModule { } 
