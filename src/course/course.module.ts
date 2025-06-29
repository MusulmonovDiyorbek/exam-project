import { forwardRef, Module } from '@nestjs/common';
import { CourseService } from './course.service';
import { CourseController } from './course.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Course } from './entities/course.entity';
import { UsersModule } from 'src/users/users.module';
import { User } from 'src/users/entities/user.entity';
import { ModelModule } from 'src/model/model.module';

@Module({
  imports:[
    UsersModule,
    TypeOrmModule.forFeature([Course,User]),
forwardRef(() => ModelModule)], 
  controllers: [CourseController],
  providers: [CourseService],
  exports: [CourseService], 
})
export class CourseModule {}
