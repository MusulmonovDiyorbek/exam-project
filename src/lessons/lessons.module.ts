import { Module } from '@nestjs/common';
import { LessonsService } from './lessons.service';
import { LessonsController } from './lessons.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Lesson } from './entities/lesson.entity';
import { ModelModule } from 'src/model/model.module';

@Module({
  imports: [TypeOrmModule.forFeature([Lesson]), ModelModule],
  controllers: [LessonsController],
  providers: [LessonsService],
})
export class LessonsModule { }
