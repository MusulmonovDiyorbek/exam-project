import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/user.entity';
import { CourseModule } from './course/course.module';
import { ModelModule } from './model/model.module';
import { EnrollmentModule } from './enrollment/enrollment.module';
import { Course } from './course/entities/course.entity';
import { Model } from './model/entities/model.entity';
import { Enrollment } from './enrollment/entities/enrollment.entity';
import { LessonsModule } from './lessons/lessons.module';
import { AssignmentModule } from './assignment/assignment.module';
import { Assignment } from './assignment/entities/assignment.entity';
import { ResultsModule } from './results/results.module';
import { Result } from './results/entities/result.entity';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/guard/jwt-auth.guard';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      url: process.env.DATABASE_URL,
      autoLoadEntities: true,
      entities: [User, Course, Model, Enrollment, Assignment, Result],
      synchronize: true,
    }),
    AuthModule,
    UsersModule,
    CourseModule,
    ModelModule,
    EnrollmentModule,
    LessonsModule,
    AssignmentModule,
    ResultsModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }
